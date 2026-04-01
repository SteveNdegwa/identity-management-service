import secrets
import bcrypt
from datetime import timedelta
from typing import Optional, Tuple

from django.db import transaction
from django.utils import timezone

from apps.accounts.models import (
    User,
    UserIdentifier,
    IdentifierType,
    SystemUser,
    SystemUserStatus,
    SocialAccount,
    UserMFA,
)
from apps.accounts.identifier_utils import IdentifierNormaliser
from apps.base.models import Country
from apps.sso.models import SSOSession, SSOSessionSystemAccess
from apps.systems.models import System
from apps.audit.models import AuditLog, AuditEventType


class IdentifierConflictError(Exception):
    pass


class ClaimError(Exception):
    pass


class RegistrationError(Exception):
    pass


class AccountService:

    def __init__(self):
        self._normaliser = IdentifierNormaliser()

    @transaction.atomic
    def register_user(
        self,
        system: System,
        password: Optional[str],
        primary_country: Optional[Country] = None,
        email: Optional[str] = None,
        phone_number: Optional[str] = None,
        username: Optional[str] = None,
        ip_address: str = "",
    ) -> User:
        if not system.registration_open:
            raise RegistrationError(
                "This system does not allow self-registration. "
                "Please contact your administrator."
            )

        # Validate required identifiers
        submitted = {
            k: v for k, v in {
                "email": email,
                "phone": phone_number,
                "username": username,
            }.items() if v
        }
        for required_type in system.required_identifier_types:
            if required_type not in submitted:
                raise RegistrationError(
                    f"This system requires your {required_type} to register."
                )

        # Validate password requirement
        if system.passwordless_only:
            password = None
        elif system.allow_password_login and not password:
            raise RegistrationError("A password is required.")

        # Check for conflicts
        self._check_identifier_available(email, IdentifierType.EMAIL)
        self._check_identifier_available(phone_number, IdentifierType.PHONE)
        self._check_identifier_available(username, IdentifierType.USERNAME)

        user = User.objects.create_user(
            email=email,
            phone_number=phone_number,
            username=username,
            password=password,
            primary_country=primary_country,
            added_by_system=system,
        )

        self._audit(
            AuditEventType.USER_CREATED,
            actor_user=user,
            ip=ip_address,
            payload={"system": system.name},
        )

        return user


    @transaction.atomic
    def create_system_user(
        self,
        user: User,
        system: System,
        country: Country,
        first_name: str = "",
        last_name: str = "",
        middle_name: str = "",
        display_name: str = "",
        date_of_birth=None,
        gender: str = "",
        external_ref: str = "",
        metadata: dict = None,
    ) -> SystemUser:
        if not system.available_countries.filter(id=country.id).exists():
            raise RegistrationError(
                f"{system.name} is not available in {country.name}."
            )

        if SystemUser.objects.filter(user=user, system=system).exists():
            raise RegistrationError(
                f"You are already registered in {system.name}."
            )

        system_user = SystemUser.objects.create(
            user=user,
            system=system,
            country=country,
            status=SystemUserStatus.ACTIVE,
            first_name=first_name,
            last_name=last_name,
            middle_name=middle_name,
            display_name=display_name,
            date_of_birth=date_of_birth,
            gender=gender,
            external_ref=external_ref,
            metadata=metadata or {},
        )

        self._audit(
            AuditEventType.SYSTEM_USER_CREATED,
            actor_user=user,
            payload={"system": system.name, "country": country.code},
        )

        return system_user

    @transaction.atomic
    def provision_system_user(
        self,
        system: System,
        country: Country,
        provisioning_email: str = "",
        provisioning_phone: str = "",
        first_name: str = "",
        last_name: str = "",
        external_ref: str = "",
        metadata: dict = None,
        provisioned_by: Optional[SystemUser] = None,
    ) -> SystemUser:
        if not system.available_countries.filter(id=country.id).exists():
            raise RegistrationError(
                f"{system.name} is not available in {country.name}."
            )

        system_user = SystemUser.objects.create(
            user=None,
            system=system,
            country=country,
            status=SystemUserStatus.PENDING,
            provisioning_email=provisioning_email,
            provisioning_phone=provisioning_phone,
            first_name=first_name,
            last_name=last_name,
            external_ref=external_ref,
            metadata=metadata or {},
        )

        self._audit(
            AuditEventType.SYSTEM_USER_CREATED,
            actor_system_user=provisioned_by,
            payload={
                "system": system.name,
                "country": country.code,
                "provisioning_email": provisioning_email,
                "status": "pending",
            },
        )
        return system_user

    @transaction.atomic
    def invite(
        self,
        system_user: SystemUser,
        invited_by: Optional[SystemUser] = None,
        ttl_hours: int = 72,
    ) -> Tuple[str, str]:
        if system_user.status == SystemUserStatus.ACTIVE:
            raise RegistrationError("User is already a member of this system.")

        if system_user.status == SystemUserStatus.SUSPENDED:
            raise RegistrationError("User is suspended in this system.")

        raw_token = secrets.token_urlsafe(48)
        token_hash = bcrypt.hashpw(raw_token.encode(), bcrypt.gensalt()).decode()

        system_user.claim_token_hash = token_hash
        system_user.claim_token_expires_at = timezone.now() + timedelta(hours=ttl_hours)
        system_user.invited_at = timezone.now()
        system_user.status = SystemUserStatus.INVITED

        while True:
            lookup_id = secrets.token_urlsafe(16)
            if not SystemUser.objects.filter(claim_token_lookup_id=lookup_id).exists():
                system_user.claim_token_lookup_id = lookup_id
                system_user.save(update_fields=[
                    "claim_token_hash",
                    "claim_token_lookup_id",
                    "claim_token_expires_at",
                    "invited_at",
                    "status",
                ])
                break

        self._audit(
            AuditEventType.SYSTEM_USER_INVITED,
            actor_system_user=invited_by,
            subject=system_user,
            payload={
                "system": system_user.system.name,
                "provisioning_email": system_user.provisioning_email,
                "expires_hours": ttl_hours,
            },
        )

        return lookup_id, raw_token

    @staticmethod
    def find_system_user_for_claim(lookup_id: str, raw_token: str) -> SystemUser:
        try:
            su = SystemUser.objects.get(
                claim_token_lookup_id=lookup_id,
                status=SystemUserStatus.INVITED,
            )
        except SystemUser.DoesNotExist:
            raise ClaimError("Invalid or expired invite link.")

        if not bcrypt.checkpw(raw_token.encode(), su.claim_token_hash.encode()):
            raise ClaimError("Invalid or expired invite link.")

        if not su.is_claimable:
            raise ClaimError(
                "This invite link has expired. "
                "Please contact your administrator to request a new one."
            )
        return su

    @transaction.atomic
    def claim_new_user(
        self,
        system_user: SystemUser,
        raw_token: str,
        password: Optional[str],
        primary_country: Optional[Country] = None,
        ip_address: str = "",
    ) -> tuple[User, SystemUser]:
        self.find_system_user_for_claim(
            system_user.claim_token_lookup_id, raw_token
        )

        if system_user.provisioning_email:
            try:
                User.objects.get_by_identifier(system_user.provisioning_email)
                raise ClaimError(
                    "An account already exists with this email. "
                    "Please sign in to link your account."
                )
            except User.DoesNotExist:
                pass

        user = User.objects.create_user(
            email=system_user.provisioning_email or None,
            phone_number=system_user.provisioning_phone or None,
            password=password,
            primary_country=primary_country or system_user.country,
            added_by_system=system_user.system,
        )

        self._activate_claim(system_user, user)

        self._audit(
            AuditEventType.SYSTEM_USER_CLAIMED,
            actor_user=user,
            subject=system_user,
            ip=ip_address,
            payload={"system": system_user.system.name, "new_user": True},
        )
        return user, system_user

    @transaction.atomic
    def claim_existing_user(
        self,
        system_user: SystemUser,
        raw_token: str,
        existing_user: User,
        ip_address: str = "",
    ) -> tuple[User, SystemUser]:
        self.find_system_user_for_claim(
            system_user.claim_token_lookup_id, raw_token
        )

        if SystemUser.objects.filter(
            user=existing_user, system=system_user.system
        ).exists():
            raise ClaimError(
                f"You already have an account in {system_user.system.name}."
            )

        self._activate_claim(system_user, existing_user)

        self._audit(
            AuditEventType.SYSTEM_USER_CLAIMED,
            actor_user=existing_user,
            subject=system_user,
            ip=ip_address,
            payload={"system": system_user.system.name, "new_user": False},
        )

        return existing_user, system_user

    @staticmethod
    def _activate_claim(system_user: SystemUser, user: User):
        system_user.user = user
        system_user.status = SystemUserStatus.ACTIVE
        system_user.claimed_at = timezone.now()
        system_user.claim_token_hash = ""
        system_user.claim_token_lookup_id  = ""
        system_user.claim_token_expires_at = None
        system_user.save(update_fields=[
            "user",
            "status",
            "claimed_at",
            "claim_token_hash",
            "claim_token_lookup_id",
            "claim_token_expires_at",
        ])

    @transaction.atomic
    def update_profile(
        self,
        system_user: SystemUser,
        updated_by: Optional[User] = None,
        **fields,
    ) -> SystemUser:
        allowed = {
            "first_name",
            "last_name",
            "middle_name",
            "display_name",
            "date_of_birth",
            "gender",
            "profile_photo_url",
            "metadata",
            "external_ref",
        }
        updated = []
        for key, value in fields.items():
            if key in allowed:
                setattr(system_user, key, value)
                updated.append(key)

        if updated:
            system_user.save(update_fields=updated)
            self._audit(
                AuditEventType.USER_UPDATED,
                actor_user=updated_by or system_user.user,
                subject=system_user,
                payload={"updated_fields": updated},
            )

        return system_user

    @transaction.atomic
    def add_identifier(
        self,
        user: User,
        identifier_type: str,
        value: str,
        system: Optional[System] = None,
        require_verification: bool = True,
        ip_address: str = "",
    ) -> UserIdentifier:
        normalised = self._normaliser.normalise(value, identifier_type)

        # Check for active conflict
        self._check_identifier_available(value, identifier_type, exclude_user=user)

        # Check recycling history
        self._check_recycling_history(normalised, identifier_type)

        identifier = UserIdentifier.all_objects.create(
            user=user,
            identifier_type=identifier_type,
            value=value,
            value_normalised=normalised,
            is_primary=False,
            is_verified=not require_verification,
            verified_at=timezone.now() if not require_verification else None,
            added_by_system=system,
        )

        self._audit(
            AuditEventType.IDENTIFIER_ADDED,
            actor_user=user,
            ip=ip_address,
            identifier_type=identifier_type,
            payload={"type": identifier_type, "requires_verification": require_verification},
        )
        return identifier

    @transaction.atomic
    def verify_identifier(
        self,
        identifier: UserIdentifier,
        ip_address: str = "",
    ) -> UserIdentifier:
        identifier.is_verified = True
        identifier.verified_at = timezone.now()
        identifier.save(update_fields=["is_verified", "verified_at"])

        self._audit(
            AuditEventType.IDENTIFIER_VERIFIED,
            actor_user=identifier.user,
            ip=ip_address,
            identifier_type=identifier.identifier_type,
            payload={"type": identifier.identifier_type},
        )

        return identifier

    @transaction.atomic
    def update_identifier(
        self,
        user: User,
        identifier_type: str,
        new_value: str,
        system: Optional[System] = None,
        ip_address: str = "",
    ) -> UserIdentifier:
        new_identifier = self.add_identifier(
            user=user,
            identifier_type=identifier_type,
            value=new_value,
            system=system,
            require_verification=True,
            ip_address=ip_address,
        )

        return new_identifier

    @transaction.atomic
    def promote_identifier_to_primary(
        self,
        new_identifier: UserIdentifier,
        ip_address: str = "",
    ) -> UserIdentifier:
        if not new_identifier.is_verified:
            raise ValueError(
                "Cannot promote an unverified identifier to primary. "
                "Verify it first via the verification flow."
            )

        user = new_identifier.user

        # Find the current primary identifier of the same type
        old_identifier = UserIdentifier.objects.filter(
            user=user,
            identifier_type=new_identifier.identifier_type,
            is_primary=True,
        ).exclude(id=new_identifier.id).first()

        # Demote old identifier
        if old_identifier:
            old_identifier.disassociate(
                reason="superseded",
                disassociated_by=user,
            )
            # Suspend MFA methods that delivered to the old identifier
            self._suspend_mfa_for_identifier(old_identifier)
            # Flag sessions — the login proof just changed
            self._flag_sessions_for_reauth(
                user,
                reason=f"{new_identifier.identifier_type} changed",
            )

        # Promote new identifier
        new_identifier.is_primary = True
        new_identifier.save(update_fields=["is_primary"])

        # If user had no primary of this type before, also update User-level
        # convenience fields if applicable (kept in sync for Django auth compat)
        self._sync_user_primary_identifier(user, new_identifier)

        self._audit(
            AuditEventType.IDENTIFIER_ADDED,
            actor_user=user,
            ip=ip_address,
            identifier_type=new_identifier.identifier_type,
            payload={
                "action": "promoted_to_primary",
                "type": new_identifier.identifier_type,
                "old_disassociated": str(old_identifier.id) if old_identifier else None,
            },
        )
        return new_identifier

    @transaction.atomic
    def disassociate_identifier(
        self,
        identifier: UserIdentifier,
        reason: str,
        disassociated_by: Optional[User] = None,
        ip_address: str = "",
    ) -> None:
        user = identifier.user

        # Must have at least one other active identifier
        remaining = UserIdentifier.objects.filter(user=user).exclude(id=identifier.id).count()
        if remaining == 0:
            raise ValueError(
                "Cannot remove the only identifier on this account. "
                "Add a new identifier before removing this one."
            )

        was_primary = identifier.is_primary

        identifier.disassociate(reason=reason, disassociated_by=disassociated_by)

        # Suspend MFA that delivered to this identifier
        self._suspend_mfa_for_identifier(identifier)

        # If primary was removed, flag sessions for re-auth
        if was_primary:
            self._flag_sessions_for_reauth(
                user,
                reason=f"Primary {identifier.identifier_type} removed",
            )

        self._audit(
            AuditEventType.IDENTIFIER_DISASSOCIATED,
            actor_user=disassociated_by or user,
            ip=ip_address,
            identifier_type=identifier.identifier_type,
            payload={
                "type": identifier.identifier_type,
                "reason": reason,
                "was_primary": was_primary,
            },
        )

    @transaction.atomic
    def suspend_system_user(
        self,
        system_user: SystemUser,
        reason: str,
        suspended_by: User,
        ip_address: str = "",
    ) -> SystemUser:
        system_user.is_suspended = True
        system_user.suspended_reason = reason
        system_user.suspended_at = timezone.now()
        system_user.suspended_by = suspended_by
        system_user.status = SystemUserStatus.SUSPENDED
        system_user.save(update_fields=[
            "is_suspended",
            "suspended_reason",
            "suspended_at",
            "suspended_by",
            "status",
        ])

        self._revoke_sessions_for_system(system_user)

        self._audit(
            AuditEventType.USER_SUSPENDED,
            actor_user=suspended_by,
            subject=system_user,
            ip=ip_address,
            payload={"system": system_user.system.name, "reason": reason},
        )
        return system_user

    @transaction.atomic
    def restore_system_user(
        self,
        system_user: SystemUser,
        restored_by: User,
        ip_address: str = "",
    ) -> SystemUser:
        system_user.is_suspended = False
        system_user.suspended_reason = ""
        system_user.suspended_at = None
        system_user.suspended_by = None
        system_user.status = SystemUserStatus.ACTIVE
        system_user.save(update_fields=[
            "is_suspended",
            "suspended_reason",
            "suspended_at",
            "suspended_by",
            "status",
        ])

        self._audit(
            AuditEventType.USER_RESTORED,
            actor_user=restored_by,
            subject=system_user,
            ip=ip_address,
            payload={"system": system_user.system.name},
        )
        return system_user

    @transaction.atomic
    def link_social_account(
        self,
        user: User,
        provider: str,
        uid: str,
        access_token: str = "",
        refresh_token: str = "",
        extra_data: dict = None,
    ) -> SocialAccount:
        social, created = SocialAccount.objects.update_or_create(
            provider=provider,
            uid=uid,
            defaults={
                "user": user,
                "extra_data": extra_data or {},
                "access_token": access_token,
                "refresh_token": refresh_token,
            },
        )
        return social

    @transaction.atomic
    def get_or_create_user_from_social(
        self,
        provider: str,
        uid: str,
        email: str,
        access_token: str = "",
        extra_data: dict = None,
    ) -> tuple[User, bool]:
        # Try existing social link
        try:
            social = SocialAccount.objects.select_related("user").get(
                provider=provider, uid=uid
            )
            return social.user, False
        except SocialAccount.DoesNotExist:
            pass

        # Try matching by email
        email = email.strip().lower()
        try:
            user = User.objects.get_by_identifier(email, IdentifierType.EMAIL)
            created = False
        except User.DoesNotExist:
            user = User.objects.create_user(email=email, password=None)
            created = True

        self.link_social_account(
            user, provider, uid, access_token, extra_data=extra_data
        )
        return user, created

    def _check_identifier_available(
        self,
        value: Optional[str],
        identifier_type: str,
        exclude_user: Optional[User] = None,
    ):
        if not value:
            return
        normalised = self._normaliser.normalise(value, identifier_type)
        qs = UserIdentifier.objects.filter(
            identifier_type=identifier_type,
            value_normalised=normalised,
        )
        if exclude_user:
            qs = qs.exclude(user=exclude_user)
        if qs.exists():
            raise IdentifierConflictError(
                f"This {identifier_type} is already registered to another account."
            )

    def _check_recycling_history(self, normalised: str, identifier_type: str):
        historical = UserIdentifier.all_objects.filter(
            identifier_type=identifier_type,
            value_normalised=normalised,
            disassociated_at__isnull=False,
        ).order_by("-disassociated_at").first()

        if not historical:
            return

        gap = timezone.now() - historical.disassociated_at

        self._audit(
            AuditEventType.IDENTIFIER_RECYCLED,
            identifier_type=identifier_type,
            payload={
                "normalised": normalised,
                "previous_user_id": str(historical.user_id),
                "gap_days": gap.days,
                "risk": "high" if gap.days < 30 else "medium" if gap.days < 180 else "low",
            },
        )

    @staticmethod
    def _suspend_mfa_for_identifier(identifier: UserIdentifier):
        if identifier.identifier_type not in (IdentifierType.PHONE, IdentifierType.EMAIL):
            return

        UserMFA.objects.filter(
            user=identifier.user,
            delivery_target=identifier.value,
            is_active=True,
        ).update(is_active=False)

    @staticmethod
    def _flag_sessions_for_reauth(user: User, reason: str = ""):
        SSOSession.objects.filter(
            user=user, is_active=True
        ).update(
            requires_reauth=True,
            reauth_reason=reason,
        )

    @staticmethod
    def _revoke_sessions_for_system(system_user: SystemUser):
        session_ids = SSOSessionSystemAccess.objects.filter(
            system=system_user.system,
            session__user=system_user.user,
            session__is_active=True,
        ).values_list("session_id", flat=True)

        SSOSession.objects.filter(
            id__in=session_ids, is_active=True
        ).update(
            is_active=False,
            revoked_at=timezone.now(),
            revoke_reason="user_suspended",
        )

    def _sync_user_primary_identifier(self, user: User, identifier: UserIdentifier):
        """
        No-op in most cases. Exists as a hook if any part of the Django
        auth stack needs to know the primary email (e.g. email backends).
        """
        pass

    @staticmethod
    def _audit(
        event_type: str,
        actor_user: Optional[User] = None,
        actor_system_user: Optional[SystemUser] = None,
        subject=None,
        ip: str = "",
        identifier_type: str = "",
        payload: dict = None,
        outcome: str = "success",
    ):
        AuditLog.objects.create(
            event_type=event_type,
            actor_user_id=actor_user.id if actor_user else None,
            actor_email=actor_user.get_email() or "" if actor_user else "",
            actor_system_user_id=actor_system_user.id if actor_system_user else None,
            actor_ip=ip or None,
            subject_type=type(subject).__name__ if subject else "",
            subject_id=str(subject.id) if subject else "",
            subject_label=str(subject) if subject else "",
            identifier_type=identifier_type,
            payload=payload or {},
            outcome=outcome,
        )