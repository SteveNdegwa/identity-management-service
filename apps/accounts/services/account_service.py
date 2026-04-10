import secrets
import bcrypt
from datetime import timedelta
from typing import Optional, Tuple, List

from django.core.exceptions import ValidationError
from django.db import transaction
from django.utils import timezone

from apps.accounts.models import (
    User,
    UserIdentifier,
    IdentifierType,
    SystemUser,
    SystemUserStatus,
    SocialAccount,
    Gender,
)
from apps.accounts.identifier_utils import IdentifierNormaliser
from apps.base.models import Country, Realm
from apps.organizations.models import Organization, Branch
from apps.permissions.models import Role
from apps.sso.models import SSOSession, SSOSessionSystemAccess, UserMFA
from apps.systems.models import System
from apps.audit.models import AuditLog, AuditEventType


class AccountService:
    def __init__(self):
        self._normaliser = IdentifierNormaliser()

    @transaction.atomic
    def invite(
            self,
            system_user: SystemUser,
            invited_by: Optional[SystemUser] = None,
            ttl_hours: int = 72,
    ) -> Tuple[str, str]:
        if system_user.status == SystemUserStatus.SUSPENDED:
            raise ValidationError("User is suspended in this system.")
        if system_user.status == SystemUserStatus.ACTIVE:
            raise ValidationError("User is active in this system.")

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
                    "claim_token_hash", "claim_token_lookup_id",
                    "claim_token_expires_at", "invited_at", "status"
                ])
                break

        self._audit(
            AuditEventType.SYSTEM_USER_INVITED,
            actor_system_user=invited_by,
            subject=system_user,
            payload={
                "system": system_user.system.name,
                "provisioning_email": system_user.provisioning_email,
                "provisioning_phone": system_user.provisioning_phone,
                "expires_hours": ttl_hours,
            },
        )

        return lookup_id, raw_token

    @transaction.atomic
    def provision_system_user(
            self,
            provisioned_by: SystemUser,
            system: System,
            country: Country,
            role: Role,
            provisioning_email: str,
            organization: Optional[Organization] = None,
            all_branches: bool = True,
            branch_grants: Optional[List[Branch]] = None,
            provisioning_phone: str = "",
            provisioning_national_id: str = "",
            first_name: str = "",
            last_name: str = "",
            middle_name: str = "",
            display_name: str = "",
            external_ref: str = "",
            metadata: dict = None,
    ) -> SystemUser:
        if not system.available_countries.filter(id=country.id).exists():
            raise ValidationError(f"{system.name} is not available in {country.name}.")

        if not provisioning_email or not provisioning_phone:
            raise ValidationError("Email address or phone number must be provided.")

        system_user = SystemUser.objects.create(
            user=None,
            system=system,
            country=country,
            role=role,
            organization=organization,
            status=SystemUserStatus.PENDING,
            provisioning_email=provisioning_email,
            provisioning_phone=provisioning_phone,
            provisioning_national_id=provisioning_national_id,
            first_name=first_name,
            last_name=last_name,
            middle_name=middle_name,
            display_name=display_name,
            external_ref=external_ref,
            metadata=metadata or {},
            provisioned_by=provisioned_by,
        )

        if branch_grants and not all_branches:
            system_user.branch_access.set(branch_grants)

        lookup_id, raw_token = self.invite(system_user=system_user, invited_by=provisioned_by)
        self._send_claim_notification(
            system_user=system_user,
            lookup_id=lookup_id,
            raw_token=raw_token,
            invited_by=provisioned_by
        )

        self._audit(
            AuditEventType.SYSTEM_USER_CREATED,
            actor_system_user=provisioned_by,
            subject=system_user,
            payload={
                "system": system.name,
                "country": country.code,
                "organization": organization.name if organization else None,
                "role": role.name,
                "provisioning_email": provisioning_email,
                "invite_sent": True,
            },
        )

        return system_user

    @staticmethod
    def find_system_user_for_claim(lookup_id: str, raw_token: str) -> SystemUser:
        try:
            su = SystemUser.objects.select_related("user", "system").get(
                claim_token_lookup_id=lookup_id,
                status=SystemUserStatus.INVITED,
            )
        except SystemUser.DoesNotExist:
            raise ValidationError("Invalid or expired invite link.")

        if not bcrypt.checkpw(raw_token.encode(), su.claim_token_hash.encode()):
            raise ValidationError("Invalid or expired invite link.")
        if not su.is_claimable:
            raise ValidationError("This invite link has expired. Please request a new one.")

        return su

    @transaction.atomic
    def inspect_claim(self, lookup_id: str, raw_token: str) -> dict:
        su = self.find_system_user_for_claim(lookup_id, raw_token)
        system = su.system

        if su.user is not None:
            raise ValidationError("This invitation has already been claimed.")

        payload = {
            "system_user_id": str(su.id),
            "system_name": su.system.name,
            "country_name": su.country.name,
            "organization_name": su.organization.name if su.organization else None,
            "role_name": su.role.name,
            "first_name": su.first_name,
            "last_name": su.last_name,
        }

        existing_user: User | None = self._resolve_existing_user(su, system.realm)
        auth_requirement = self._resolve_claim_auth_requirement(system)
        required_identifier_types = system.required_identifier_types or []

        provided_in_provisioning = []
        if su.provisioning_email:
            provided_in_provisioning.append(IdentifierType.EMAIL)
        if su.provisioning_phone:
            provided_in_provisioning.append(IdentifierType.PHONE)
        if su.provisioning_national_id:
            provided_in_provisioning.append(IdentifierType.NATIONAL_ID)

        additional_required = [t for t in required_identifier_types if t not in provided_in_provisioning]

        if existing_user:
            mask_map = {
                IdentifierType.EMAIL.value: self._mask_email,
                IdentifierType.PHONE.value: self._mask_phone,
                IdentifierType.NATIONAL_ID.value: self._mask_national_id,
                IdentifierType.USERNAME.value: self._mask_username,
            }

            existing_user_details = {
                identifier.identifier_type: mask_map[identifier.identifier_type](identifier.value_normalised)
                for identifier in existing_user.identifiers.all()
            }

            user_has = {ident.identifier_type for ident in existing_user.identifiers.all()}
            missing_for_link = [t for t in required_identifier_types if t not in user_has]

            payload.update({
                "new_user": False,
                "can_link": True,
                "can_create_separate": True,
                "existing_user_details": existing_user_details,
                "provisioning_email": self._mask_email(su.provisioning_email) if su.provisioning_email else None,
                "provisioning_phone": self._mask_phone(su.provisioning_phone) if su.provisioning_phone else None,
                "provisioning_national_id": self._mask_national_id(su.provisioning_national_id)
                if su.provisioning_national_id else None,
                "link_requires_additional_identifiers": missing_for_link,
                "separate_requires": auth_requirement,
                "seperate_required_identifiers": required_identifier_types
            })
        else:
            payload.update({
                "new_user": True,
                "can_link": False,
                "can_create_separate": False,
                "requires": auth_requirement,
                "additional_required_identifiers": additional_required,
            })

        return payload

    @staticmethod
    def _resolve_claim_auth_requirement(system: System) -> dict:
        if system.passwordless_only:
            return {"type": "none"}
        if system.password_type == System.PasswordType.PIN:
            return {"type": "pin"}
        if system.allow_password_login:
            return {"type": "password"}
        return {"type": "none"}

    @transaction.atomic
    def claim_user(
            self,
            claim_token_lookup_id: str,
            claim_token: str,
            claim_action: str = "link",
            password: Optional[str] = None,
            pin: Optional[str] = None,
            email: Optional[str] = None,
            phone: Optional[str] = None,
            national_id: Optional[str] = None,
            username: Optional[str] = None,
    ) -> SystemUser:
        su = self.find_system_user_for_claim(claim_token_lookup_id, claim_token)
        system = su.system

        if su.user is not None:
            raise ValidationError("This invitation has already been claimed.")

        existing_user: User | None =  self._resolve_existing_user(su, system.realm)

        user_identifiers = {
            IdentifierType.EMAIL.value: su.provisioning_email or email,
            IdentifierType.PHONE.value: su.provisioning_phone or phone,
            IdentifierType.NATIONAL_ID.value: su.provisioning_national_id or national_id,
            IdentifierType.USERNAME.value: username
        }

        if claim_action == "link":
            if not existing_user:
                raise ValidationError("Cannot link: no existing user account matches the provisioning details.")
            user = existing_user
            if user.realm != system.realm:
                raise Exception("User realm and System realm conflict.")

            for required_identifier in (system.required_identifier_types or []):
                if not UserIdentifier.objects.filter(
                    user=user,
                    identifier_type=required_identifier,
                ).exists():
                    identifier_value = user_identifiers.get(required_identifier)
                    if not identifier_value:
                        raise ValidationError(f"Cannot link: {required_identifier} is required.")

                    self._check_identifier_available(
                        value=identifier_value,
                        identifier_type=required_identifier,
                        realm=system.realm
                    )
                    self.add_identifier(
                        user=user,
                        identifier_type=IdentifierType.EMAIL,
                        value=identifier_value,
                        system=system,
                        require_verification=False,
                    )

        elif claim_action in ("new", "separate"):
            if claim_action == "new":
                if existing_user:
                    raise ValidationError(
                        "An existing account was found. Use 'link' or 'separate' instead."
                    )

            elif claim_action == "separate":
                user_identifiers = {
                    IdentifierType.EMAIL.value: email,
                    IdentifierType.PHONE.value: phone,
                    IdentifierType.NATIONAL_ID.value: national_id,
                    IdentifierType.USERNAME.value: username
                }

            # Enforce required identifiers
            for required_identifier in system.required_identifier_types or []:
                identifier_value = user_identifiers.get(required_identifier)
                if not identifier_value:
                    raise ValidationError(f"This system requires your {required_identifier} to register.")

                self._check_identifier_available(
                    value=identifier_value,
                    identifier_type=required_identifier,
                    realm=system.realm
                )

            # Credential handling
            if system.passwordless_only:
                password = None
                pin = None
            elif system.password_type == System.PasswordType.PASSWORD:
                if system.allow_password_login and not password:
                    raise ValidationError("A password is required for this system.")
                pin = None
            elif system.password_type == System.PasswordType.PIN:
                if system.allow_password_login and not pin:
                    raise ValidationError("A PIN is required for this system.")
                password = None

            user = User.objects.create_user(
                realm=system.realm,
                email=user_identifiers.get(IdentifierType.EMAIL),
                phone_number=user_identifiers.get(IdentifierType.PHONE),
                username=user_identifiers.get(IdentifierType.USERNAME),
                national_id=user_identifiers.get(IdentifierType.NATIONAL_ID),
                password=password,
                pin=pin,
                primary_country=su.country,
                added_by_system=system,
            )
        else:
            raise ValidationError("Invalid claim_action. Must be one of: 'link', 'new', 'separate'.")

        if not su.user:
            su.user = user

        su.status = SystemUserStatus.ACTIVE
        su.claimed_at = timezone.now()
        su.claim_token_hash = ""
        su.claim_token_lookup_id = ""
        su.claim_token_expires_at = None
        su.save(update_fields=[
            "user", "status", "claimed_at", "claim_token_hash",
            "claim_token_lookup_id", "claim_token_expires_at"
        ])

        return su

    @staticmethod
    def _resolve_existing_user(su: SystemUser, realm: Realm) -> Optional[User]:
        if su.provisioning_email:
            try:
                return User.objects.get_by_identifier(
                    value=su.provisioning_email,
                    identifier_type=IdentifierType.EMAIL,
                    realm=realm
                )
            except User.DoesNotExist:
                pass

        if su.provisioning_national_id:
            try:
                return User.objects.get_by_identifier(
                    value=su.provisioning_national_id,
                    identifier_type=IdentifierType.NATIONAL_ID,
                    realm=realm
                )
            except User.DoesNotExist:
                pass

        if su.provisioning_phone:
            try:
                return User.objects.get_by_identifier(
                    value=su.provisioning_phone,
                    identifier_type=IdentifierType.PHONE,
                    realm=realm
                )
            except User.DoesNotExist:
                pass

        return None

    @transaction.atomic
    def self_registration(
            self,
            system: System,
            role: Role,
            first_name: str,
            last_name: str,
            middle_name: str = "",
            display_name: str = "",
            date_of_birth=None,
            gender: str = Gender.OTHER,
            email: Optional[str] = None,
            phone_number: Optional[str] = None,
            username: Optional[str] = None,
            national_id: Optional[str] = None,
            password: Optional[str] = None,
            pin: Optional[str] = None,
            primary_country: Optional[Country] = None,
            ip_address: str = "",
    ) -> User:
        if not system.registration_open:
            raise ValidationError("This system does not allow self-registration.")

        submitted = {k: v for k, v in {
            IdentifierType.EMAIL.value: email,
            IdentifierType.PHONE.value: phone_number,
            IdentifierType.USERNAME.value: username,
            IdentifierType.NATIONAL_ID.value: national_id,
        }.items() if v and v.strip()}

        for required_type in (system.required_identifier_types or []):
            if required_type not in submitted:
                raise ValidationError(f"This system requires your {required_type} to register.")

        if system.passwordless_only:
            password = None
            pin = None
        elif system.password_type == System.PasswordType.PASSWORD:
            if system.allow_password_login and not password:
                raise ValidationError("A password is required.")
            pin = None
        elif system.password_type == System.PasswordType.PIN:
            if system.allow_password_login and not pin:
                raise ValidationError("A PIN is required for this system.")
            password = None

        # Try to find existing user in the same realm
        existing_user = None
        existing_identifier_type = None
        if email:
            try:
                existing_user = User.objects.get_by_identifier(
                    value=email, identifier_type=IdentifierType.EMAIL, realm=system.realm
                )
                existing_identifier_type = IdentifierType.EMAIL
            except User.DoesNotExist:
                pass
        if not existing_user and national_id:
            try:
                existing_user = User.objects.get_by_identifier(
                    value=national_id, identifier_type=IdentifierType.NATIONAL_ID, realm=system.realm
                )
                existing_identifier_type = IdentifierType.NATIONAL_ID
            except User.DoesNotExist:
                pass
        if not existing_user and phone_number:
            try:
                existing_user = User.objects.get_by_identifier(
                    value=phone_number, identifier_type=IdentifierType.PHONE, realm=system.realm
                )
                existing_identifier_type = IdentifierType.PHONE
            except User.DoesNotExist:
                pass
        if not existing_user and username:
            try:
                existing_user = User.objects.get_by_identifier(
                    value=username, identifier_type=IdentifierType.USERNAME, realm=system.realm
                )
                existing_identifier_type = IdentifierType.USERNAME
            except User.DoesNotExist:
                pass

        if existing_user:
            # Check if user is already registered in THIS system
            if SystemUser.objects.filter(user=existing_user, system=system, status=SystemUserStatus.ACTIVE).exists():
                raise ValidationError(
                    f"This {existing_identifier_type} is already registered in this system."
                )

            # Allow linking
            user = existing_user

            # TODO: PROMPT LINK REQUEST TO USER - USER IS REGISTERED TO ANOTHER SYSTEM IN THE SAME REALM SO
            #  THEY EITHER LINK TO THAT EXISTING ACCOUNT OR CREATE A NEW ACCOUNT
            raise NotImplementedError("Linking logic in self registration is not supported.")

        else:
            # Create new user
            user = User.objects.create_user(
                realm=system.realm,
                email=email,
                phone_number=phone_number,
                username=username,
                national_id=national_id,
                password=password,
                pin=pin,
                primary_country=primary_country,
                added_by_system=system,
            )

        # Create or update SystemUser record
        system_user, created = SystemUser.objects.update_or_create(
            user=user,
            system=system,
            defaults={
                "organization": None,
                "country": primary_country or system.available_countries.first(),
                "role": role,
                "first_name": first_name,
                "last_name": last_name,
                "middle_name": middle_name,
                "display_name": display_name or f"{first_name} {last_name}".strip(),
                "date_of_birth": date_of_birth,
                "gender": gender,
                "status": SystemUserStatus.ACTIVE,
            }
        )

        self._audit(
            AuditEventType.USER_CREATED if created else AuditEventType.USER_LINKED_TO_SYSTEM,
            actor_user=user,
            ip=ip_address,
            payload={
                "system": system.name,
                "via": "self_registration",
                "linked_existing": existing_user is not None
            }
        )

        return user

    @transaction.atomic
    def update_profile(self, system_user: SystemUser, updated_by: Optional[User] = None, **fields) -> SystemUser:
        allowed = {
            "first_name", "last_name", "middle_name", "display_name",
            "date_of_birth", "gender", "profile_photo_url",
            "metadata", "external_ref"
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
        self._check_identifier_available(value, identifier_type, exclude_user=user, realm=user.realm)

        identifier = UserIdentifier.objects.create(
            user=user,
            realm=user.realm,
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
    def verify_identifier(self, identifier: UserIdentifier, ip_address: str = "") -> UserIdentifier:
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
    def promote_identifier_to_primary(self, new_identifier: UserIdentifier, ip_address: str = "") -> UserIdentifier:
        if not new_identifier.is_verified:
            raise ValueError("Cannot promote an unverified identifier to primary.")

        user = new_identifier.user
        old_identifier = UserIdentifier.objects.filter(
            user=user,
            identifier_type=new_identifier.identifier_type,
            is_primary=True,
        ).exclude(id=new_identifier.id).first()
        if old_identifier:
            old_identifier.disassociate(reason="superseded", disassociated_by=user)
            self._suspend_mfa_for_identifier(old_identifier)
            self._flag_sessions_for_reauth(user, f"{new_identifier.identifier_type} changed")

        new_identifier.is_primary = True
        new_identifier.save(update_fields=["is_primary"])
        self._sync_user_primary_identifier(user, new_identifier)

        self._audit(
            AuditEventType.IDENTIFIER_ADDED,
            actor_user=user,
            ip=ip_address,
            identifier_type=new_identifier.identifier_type,
            payload={"action": "promoted_to_primary"},
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
        remaining = UserIdentifier.objects.filter(user=user).exclude(id=identifier.id).count()
        if remaining == 0:
            raise ValueError("Cannot remove the only identifier on this account.")

        was_primary = identifier.is_primary
        identifier.disassociate(reason=reason, disassociated_by=disassociated_by)
        self._suspend_mfa_for_identifier(identifier)
        if was_primary:
            self._flag_sessions_for_reauth(user, f"Primary {identifier.identifier_type} removed")

        self._audit(
            AuditEventType.IDENTIFIER_DISASSOCIATED,
            actor_user=disassociated_by or user,
            ip=ip_address,
            identifier_type=identifier.identifier_type,
            payload={"type": identifier.identifier_type, "reason": reason, "was_primary": was_primary},
        )

    @transaction.atomic
    def suspend_system_user(
            self,
            system_user: SystemUser,
            reason: str,
            suspended_by: User,
            ip_address: str = "",
    ) -> SystemUser:
        system_user.suspended_reason = reason
        system_user.suspended_at = timezone.now()
        system_user.suspended_by = suspended_by
        system_user.status = SystemUserStatus.SUSPENDED
        system_user.save(update_fields=[
            "suspended_reason", "suspended_at", "suspended_by", "status"
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
        system_user.suspended_reason = ""
        system_user.suspended_at = None
        system_user.suspended_by = None
        system_user.status = SystemUserStatus.ACTIVE
        system_user.save(update_fields=[
            "suspended_reason", "suspended_at", "suspended_by", "status"
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
        social, _ = SocialAccount.objects.update_or_create(
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
            system: System,
            provider: str,
            uid: str,
            email: str,
            access_token: str = "",
            extra_data: dict = None,
    ) -> tuple[User, bool]:
        try:
            social = SocialAccount.objects.select_related("user").get(
                provider=provider, uid=uid, user__realm=system.realm
            )
            return social.user, False
        except SocialAccount.DoesNotExist:
            pass
        try:
            user = User.objects.get_by_identifier(email, IdentifierType.EMAIL, system.realm)
            created = False
        except User.DoesNotExist:
            user = User.objects.create_user(realm=system.realm, email=email, password=None)
            created = True
        self.link_social_account(user, provider, uid, access_token, extra_data=extra_data)
        return user, created

    def _check_identifier_available(
            self,
            value: Optional[str],
            identifier_type: str,
            exclude_user: Optional[User] = None,
            realm: Optional[Realm] = None,
    ):
        if not value:
            return
        normalised = self._normaliser.normalise(value, identifier_type)
        qs = UserIdentifier.objects.filter(
            identifier_type=identifier_type,
            value_normalised=normalised,
        )
        if realm:
            qs = qs.filter(realm=realm)
        if exclude_user:
            qs = qs.exclude(user=exclude_user)
        if qs.exists():
            raise ValidationError(f"This {identifier_type} is already registered to another account.")

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
        SSOSession.objects.filter(user=user, is_active=True).update(
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
        SSOSession.objects.filter(id__in=session_ids, is_active=True).update(
            is_active=False,
            revoked_at=timezone.now(),
            revoke_reason="user_suspended",
        )

    @staticmethod
    def _sync_user_primary_identifier(user: User, identifier: UserIdentifier):
        pass

    @staticmethod
    def _mask_username(username: str) -> str:
        if not username:
            return "****"

        if len(username) == 1:
            return username
        elif len(username) == 2:
            return username[0] + "*"

        return username[0] + "*" * (len(username) - 2) + username[-1]

    @staticmethod
    def _mask_national_id(national_id: str) -> str:
        if not national_id:
            return "****"

        # Remove spaces just in case
        clean_id = national_id.replace(" ", "")

        if len(clean_id) <= 4:
            return "*" * len(clean_id)

        visible_tail = 3
        masked_part = "*" * (len(clean_id) - visible_tail)

        return masked_part + clean_id[-visible_tail:]

    @staticmethod
    def _mask_email(email: str) -> str:
        if not email or "@" not in email:
            return "****"
        local, _, domain = email.partition("@")
        if len(local) <= 1:
            masked_local = local
        elif len(local) == 2:
            masked_local = local[0] + "*"
        else:
            masked_local = local[0] + "*" * (len(local) - 2) + local[-1]
        return f"{masked_local}@{domain}"

    @staticmethod
    def _mask_phone(phone: str) -> str:
        if not phone:
            return "****"
        prefix = "+" if phone.startswith("+") else ""
        digits = phone.lstrip("+")
        if len(digits) < 5:
            return phone
        head_len = 3 if prefix == "+" else 2
        tail_len = 2
        mask_len = len(digits) - head_len - tail_len
        if mask_len <= 0:
            return phone
        masked = prefix + digits[:head_len] + "*" * mask_len + digits[-tail_len:]
        return masked

    @staticmethod
    def _send_claim_notification(
            system_user: SystemUser,
            lookup_id: str,
            raw_token: str,
            invited_by: SystemUser,
    ):
        context = {
            "system_name": system_user.system.name,
            "base_country": system_user.country.name if system_user.country else "",
            "organization_name": system_user.organization.name if system_user.organization else None,
            "role_name": system_user.role.name,
            "first_name": system_user.first_name or "User",
            "lookup_id": lookup_id,
            "claim_url": f"https://yourdomain.com/auth/claim/{lookup_id}/{raw_token}",
            "invited_by_name": invited_by.full_name,
        }
        recipient = system_user.provisioning_email or system_user.provisioning_phone
        print(f"[CLAIM NOTIFICATION SENT] To: {recipient}")
        print(f"Context: {context}")

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
            actor_email=actor_user.get_email() if actor_user else "",
            actor_system_user_id=actor_system_user.id if actor_system_user else None,
            actor_ip=ip or None,
            subject_type=type(subject).__name__ if subject else "",
            subject_id=str(subject.id) if subject else "",
            subject_label=str(subject) if subject else "",
            identifier_type=identifier_type,
            payload=payload or {},
            outcome=outcome,
        )