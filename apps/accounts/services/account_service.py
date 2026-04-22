import secrets
import bcrypt
from datetime import timedelta
from typing import Optional, Tuple, List
from django.db import transaction
from django.utils import timezone
from apps.accounts.models import (
    User,
    UserIdentifier,
    SystemUser,
    SystemUserStatus,
    SocialAccount,
    Gender,
)
from apps.accounts.identifier_utils import IdentifierNormaliser
from apps.base.models import Country, Realm
from apps.organizations.models import Organization, Branch
from apps.permissions.models import Role
from apps.sso.models import SSOSession, SSOSessionSystemAccess
from apps.sso.models import UserMFA
from apps.systems.models import System
from apps.audit.models import AuditLog, AuditEventType


class AccountServiceError(Exception):
    pass


class ProvisionSystemUserError(AccountServiceError):
    pass


class SelfRegistrationError(AccountServiceError):
    pass


class RegistrationClosedError(SelfRegistrationError):
    pass


class IdentifierConflictError(SelfRegistrationError):
    pass


class ClaimError(AccountServiceError):
    pass


class InvalidClaimTokenError(ClaimError):
    pass


class ClaimExpiredError(ClaimError):
    pass


class SystemUserStatusError(ClaimError):
    pass


class ManageIdentifierError(AccountServiceError):
    pass


class LinkAccountRequired(AccountServiceError):
    def __init__(self, existing_user: User, matched_on: str):
        self.existing_user = existing_user
        self.matched_on = matched_on
        super().__init__(f"Existing account found matched on {matched_on}")


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
            raise SystemUserStatusError("User is suspended in this system.")
        if system_user.status == SystemUserStatus.ACTIVE:
            raise SystemUserStatusError("User is already active in this system.")

        raw_token = secrets.token_urlsafe(48)
        token_hash = bcrypt.hashpw(raw_token.encode(), bcrypt.gensalt()).decode()

        system_user.claim_token_hash = token_hash
        system_user.claim_token_expires_at = timezone.now() + timedelta(hours=ttl_hours)
        system_user.invited_at = timezone.now()
        system_user.status = SystemUserStatus.INVITED

        # Collision-safe lookup_id
        while True:
            lookup_id = secrets.token_urlsafe(16)
            if not SystemUser.objects.filter(claim_token_lookup_id=lookup_id).exists():
                system_user.claim_token_lookup_id = lookup_id
                system_user.save(update_fields=[
                    "claim_token_hash", "claim_token_lookup_id",
                    "claim_token_expires_at", "invited_at", "status",
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
            provisioning_email: str = "",
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
            raise ProvisionSystemUserError(
                f"{system.name} is not available in {country.name}."
            )

        if not any([provisioning_email, provisioning_phone, provisioning_national_id]):
            raise ProvisionSystemUserError(
                "At least one provisioning identifier (email, phone, or national ID) must be provided."
            )

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
            all_branches=all_branches,
        )

        if branch_grants and not all_branches:
            system_user.branch_access.set(branch_grants)

        lookup_id, raw_token = self.invite(system_user=system_user, invited_by=provisioned_by)

        self._send_claim_notification(
            system_user=system_user,
            lookup_id=lookup_id,
            raw_token=raw_token,
            invited_by=provisioned_by,
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
            raise InvalidClaimTokenError("Invalid or expired invite link.")

        if not bcrypt.checkpw(raw_token.encode(), su.claim_token_hash.encode()):
            raise InvalidClaimTokenError("Invalid or expired invite link.")

        if not su.is_claimable:
            raise ClaimExpiredError("This invite link has expired. Please request a new one.")

        return su

    @transaction.atomic
    def inspect_claim(self, lookup_id: str, raw_token: str) -> dict:
        su = self.find_system_user_for_claim(lookup_id, raw_token)
        system = su.system

        if su.user is not None:
            raise ClaimError("This invitation has already been claimed.")

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
            provided_in_provisioning.append("email")
        if su.provisioning_phone:
            provided_in_provisioning.append("phone")
        if su.provisioning_national_id:
            provided_in_provisioning.append("national_id")

        additional_required = [t for t in required_identifier_types if t not in provided_in_provisioning]

        if existing_user:
            mask_map = {
                "email": self._mask_email,
                "phone": self._mask_phone,
                "national_id": self._mask_national_id,
                "username": self._mask_username,
            }
            existing_user_details = {
                ident.identifier_type: mask_map[ident.identifier_type](ident.value_normalised)
                for ident in existing_user.identifiers.all()
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
                "separate_required_identifiers": required_identifier_types,
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
            raise ClaimError("This invitation has already been claimed.")

        existing_user: User | None = self._resolve_existing_user(su, system.realm)

        provisioned_identifiers = {
            "email": su.provisioning_email or email,
            "phone": su.provisioning_phone or phone,
            "national_id": su.provisioning_national_id or national_id,
            "username": username,
        }

        if claim_action == "link":
            if not existing_user:
                raise ClaimError("Cannot link: no existing user account matches the provisioning details.")
            if existing_user.realm != system.realm:
                raise ClaimError("User realm and system realm do not match.")

            user = existing_user
            for required_type in (system.required_identifier_types or []):
                if not UserIdentifier.objects.filter(user=user, identifier_type=required_type).exists():
                    value = provisioned_identifiers.get(required_type)
                    if not value:
                        raise ClaimError(
                            f"Cannot link: {required_type} is required by this system but was not provided."
                        )
                    self._check_identifier_available(realm=system.realm, value=value, identifier_type=required_type)
                    self.add_identifier(
                        user=user,
                        identifier_type=required_type,
                        value=value,
                        system=system,
                        require_verification=False,
                    )

        elif claim_action in ("new", "separate"):
            if claim_action == "new" and existing_user:
                raise ClaimError("An existing account was found. Use 'link' or 'separate' instead.")

            if claim_action == "separate":
                user_identifiers = {
                    "email": email,
                    "phone": phone,
                    "national_id": national_id,
                    "username": username,
                }
            else:
                user_identifiers = provisioned_identifiers

            for required_type in (system.required_identifier_types or []):
                value = user_identifiers.get(required_type)
                if not value:
                    raise ClaimError(f"This system requires your {required_type} to register.")
                self._check_identifier_available(realm=system.realm, value=value, identifier_type=required_type)

            password, pin = self._resolve_credentials(system, password, pin)
            user = User.objects.create_user(
                realm=system.realm,
                email=user_identifiers.get("email"),
                phone_number=user_identifiers.get("phone"),
                username=user_identifiers.get("username"),
                national_id=user_identifiers.get("national_id"),
                password=password,
                pin=pin,
                primary_country=su.country,
                added_by_system=system,
            )
        else:
            raise ClaimError("Invalid claim_action. Must be one of: 'link', 'new', 'separate'.")

        su.user = user
        su.status = SystemUserStatus.ACTIVE
        su.claimed_at = timezone.now()
        su.claim_token_hash = ""
        su.claim_token_lookup_id = ""
        su.claim_token_expires_at = None
        su.save(update_fields=[
            "user", "status", "claimed_at", "claim_token_hash",
            "claim_token_lookup_id", "claim_token_expires_at",
        ])

        self._audit(
            AuditEventType.SYSTEM_USER_CLAIMED,
            actor_user=user,
            subject=su,
            payload={"action": claim_action, "system": system.name},
        )
        return su

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
        organization: Optional[Organization] = None,
        ip_address: str = "",
    ) -> Tuple[User, SystemUser]:
        if not system.registration_open:
            raise RegistrationClosedError("This system does not allow self-registration.")

        submitted = {k: v for k, v in {
            "email": email,
            "phone": phone_number,
            "username": username,
            "national_id": national_id,
        }.items() if v and v.strip()}

        for required_type in (system.required_identifier_types or []):
            if required_type not in submitted:
                raise SelfRegistrationError(f"This system requires your {required_type} to register.")

        password, pin = self._resolve_credentials(system, password, pin)

        existing_user, existing_identifier_type = self._find_existing_user_for_registration(
            realm=system.realm,
            email=email,
            phone_number=phone_number,
            national_id=national_id,
            username=username,
        )

        if existing_user and existing_identifier_type:
            if SystemUser.objects.filter(
                user=existing_user, system=system, status=SystemUserStatus.ACTIVE
            ).exists():
                raise SelfRegistrationError(
                    f"An account with this {existing_identifier_type} is already registered in this system."
                )
            raise LinkAccountRequired(
                existing_user=existing_user,
                matched_on=existing_identifier_type,
            )

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

        system_user = self._create_system_user_record(
            user=user,
            system=system,
            role=role,
            organization=organization,
            primary_country=primary_country,
            first_name=first_name,
            last_name=last_name,
            middle_name=middle_name,
            display_name=display_name,
            date_of_birth=date_of_birth,
            gender=gender,
        )

        self._audit(
            AuditEventType.USER_CREATED,
            actor_user=user,
            ip=ip_address,
            payload={"system": system.name, "via": "self_registration"},
        )
        return user, system_user

    @transaction.atomic
    def self_registration_link(
        self,
        existing_user: User,
        system: System,
        role: Role,
        first_name: str,
        last_name: str,
        middle_name: str = "",
        display_name: str = "",
        date_of_birth=None,
        gender: str = Gender.OTHER,
        organization: Optional[Organization] = None,
        primary_country: Optional[Country] = None,
        email: Optional[str] = None,
        phone_number: Optional[str] = None,
        username: Optional[str] = None,
        national_id: Optional[str] = None,
        ip_address: str = "",
    ) -> Tuple[User, SystemUser]:
        if existing_user.realm != system.realm:
            raise SelfRegistrationError("User realm and system realm do not match.")
        if SystemUser.objects.filter(user=existing_user, system=system, status=SystemUserStatus.ACTIVE).exists():
            raise SelfRegistrationError("This account is already registered in this system.")

        supplied = {
            "email": email,
            "phone": phone_number,
            "username": username,
            "national_id": national_id,
        }

        for required_type in (system.required_identifier_types or []):
            if not UserIdentifier.objects.filter(user=existing_user, identifier_type=required_type).exists():
                value = supplied.get(required_type)
                if not value:
                    raise SelfRegistrationError(
                        f"Your account does not have a {required_type}. "
                        f"Please provide one to complete registration."
                    )
                self._check_identifier_available(realm=system.realm, value=value, identifier_type=required_type)
                self.add_identifier(
                    user=existing_user,
                    identifier_type=required_type,
                    value=value,
                    system=system,
                    require_verification=False,
                )

        system_user = self._create_system_user_record(
            user=existing_user,
            system=system,
            role=role,
            organization=organization,
            primary_country=primary_country,
            first_name=first_name,
            last_name=last_name,
            middle_name=middle_name,
            display_name=display_name,
            date_of_birth=date_of_birth,
            gender=gender,
        )

        self._audit(
            AuditEventType.USER_LINKED_TO_SYSTEM,
            actor_user=existing_user,
            ip=ip_address,
            payload={"system": system.name, "via": "self_registration_link"},
        )
        return existing_user, system_user

    @transaction.atomic
    def update_profile(
        self,
        system_user: SystemUser,
        updated_by: Optional[User] = None,
        **fields,
    ) -> SystemUser:
        allowed = {
            "first_name", "last_name", "middle_name", "display_name",
            "date_of_birth", "gender", "profile_photo_url",
            "metadata", "external_ref",
        }
        updated = [k for k, v in fields.items() if k in allowed]
        for key in updated:
            setattr(system_user, key, fields[key])

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
        self._check_identifier_available(
            value=value,
            identifier_type=identifier_type,
            exclude_user=user,
            realm=user.realm,
        )

        normalised = self._normaliser.normalise(value, identifier_type)
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
            raise ManageIdentifierError("Cannot promote an unverified identifier to primary.")

        user = new_identifier.user
        old_primary = UserIdentifier.objects.filter(
            user=user,
            identifier_type=new_identifier.identifier_type,
            is_primary=True,
        ).exclude(id=new_identifier.id).first()

        if old_primary:
            old_primary.disassociate(reason="superseded", disassociated_by=user)
            self._suspend_mfa_for_identifier(old_primary)
            self._flag_sessions_for_reauth(user, f"{new_identifier.identifier_type} changed")

        new_identifier.is_primary = True
        new_identifier.save(update_fields=["is_primary"])

        self._audit(
            AuditEventType.IDENTIFIER_PROMOTED,
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
            raise ManageIdentifierError("Cannot remove the only identifier on this account.")

        was_primary = identifier.is_primary
        identifier.disassociate(reason=reason, disassociated_by=disassociated_by)
        self._suspend_mfa_for_identifier(identifier)

        if was_primary:
            self._flag_sessions_for_reauth(
                user, f"Primary {identifier.identifier_type} removed"
            )

        self._audit(
            AuditEventType.IDENTIFIER_DISASSOCIATED,
            actor_user=disassociated_by or user,
            ip=ip_address,
            identifier_type=identifier.identifier_type,
            payload={
                "type": identifier.identifier_type,
                "reason": reason,
                "was_primary": was_primary
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
        if system_user.status == SystemUserStatus.SUSPENDED:
            raise SystemUserStatusError("User is already suspended.")

        system_user.suspended_reason = reason
        system_user.suspended_at = timezone.now()
        system_user.suspended_by = suspended_by
        system_user.status = SystemUserStatus.SUSPENDED
        system_user.save(update_fields=[
            "suspended_reason", "suspended_at",
            "suspended_by", "status"
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
        if system_user.status != SystemUserStatus.SUSPENDED:
            raise SystemUserStatusError("User is not suspended.")

        system_user.suspended_reason = ""
        system_user.suspended_at = None
        system_user.suspended_by = None
        system_user.status = SystemUserStatus.ACTIVE
        system_user.save(update_fields=[
            "suspended_reason", "suspended_at",
            "suspended_by", "status"
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
    ) -> Tuple[User, bool]:
        try:
            social = SocialAccount.objects.select_related("user").get(
                provider=provider, uid=uid, user__realm=system.realm
            )
            return social.user, False
        except SocialAccount.DoesNotExist:
            pass

        try:
            user = User.objects.get_by_identifier(email, "email", system.realm)
            created = False
        except User.DoesNotExist:
            user = User.objects.create_user(realm=system.realm, email=email)
            created = True

        self.link_social_account(user, provider, uid, access_token, extra_data=extra_data)
        return user, created

    @staticmethod
    def _resolve_credentials(
            system: System,
            password: Optional[str],
            pin: Optional[str]
    ) -> Tuple[Optional[str], Optional[str]]:
        if system.passwordless_only:
            return None, None

        if system.password_type == System.PasswordType.PASSWORD:
            if system.allow_password_login and not password:
                raise SelfRegistrationError("A password is required for this system.")
            return password, None

        if system.password_type == System.PasswordType.PIN:
            if system.allow_password_login and not pin:
                raise SelfRegistrationError("A PIN is required for this system.")
            return None, pin

        return password, pin

    @staticmethod
    def _find_existing_user_for_registration(
        realm: Realm,
        email: Optional[str],
        phone_number: Optional[str],
        national_id: Optional[str],
        username: Optional[str],
    ) -> Tuple[Optional[User], Optional[str]]:
        checks = [
            ("email", email),
            ("national_id", national_id),
            ("phone", phone_number),
            ("username", username),
        ]
        for id_type, value in checks:
            if not value:
                continue
            try:
                user = User.objects.get_by_identifier(
                    value=value,
                    identifier_type=id_type,
                    realm=realm
                )
                return user, id_type
            except User.DoesNotExist:
                continue
        return None, None

    @staticmethod
    def _create_system_user_record(
        user: User,
        system: System,
        role: Role,
        organization: Optional[Organization],
        primary_country: Optional[Country],
        first_name: str,
        last_name: str,
        middle_name: str,
        display_name: str,
        date_of_birth,
        gender: str,
    ) -> SystemUser:
        system_user, _ = SystemUser.objects.update_or_create(
            user=user,
            system=system,
            defaults={
                "organization": organization,
                "country": primary_country or system.available_countries.first(),
                "role": role,
                "first_name": first_name,
                "last_name": last_name,
                "middle_name": middle_name,
                "display_name": display_name or f"{first_name} {last_name}".strip(),
                "date_of_birth": date_of_birth,
                "gender": gender,
                "status": SystemUserStatus.ACTIVE,
            },
        )
        return system_user

    @staticmethod
    def _resolve_existing_user(su: SystemUser, realm: Realm) -> Optional[User]:
        for id_type, value in [
            ("email", su.provisioning_email),
            ("national_id", su.provisioning_national_id),
            ("phone", su.provisioning_phone),
        ]:
            if not value:
                continue
            try:
                return User.objects.get_by_identifier(
                    value=value,
                    identifier_type=id_type,
                    realm=realm
                )
            except User.DoesNotExist:
                continue
        return None

    def _check_identifier_available(
            self,
            realm: Realm,
            value: Optional[str],
            identifier_type: str,
            exclude_user: Optional[User] = None,
    ):
        if not value:
            return
        normalised = self._normaliser.normalise(value, identifier_type)
        qs = UserIdentifier.objects.filter(
            realm=realm,
            identifier_type=identifier_type,
            value_normalised=normalised
        )
        if exclude_user:
            qs = qs.exclude(user=exclude_user)
        if qs.exists():
            raise IdentifierConflictError(
                f"This {identifier_type} is already registered to another account."
            )

    @staticmethod
    def _suspend_mfa_for_identifier(identifier: UserIdentifier):
        if identifier.identifier_type not in ("phone", "email"):
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
    def _mask_username(username: str) -> str:
        if not username:
            return "****"
        if len(username) == 1:
            return username
        if len(username) == 2:
            return username[0] + "*"
        return username[0] + "*" * (len(username) - 2) + username[-1]

    @staticmethod
    def _mask_national_id(national_id: str) -> str:
        if not national_id:
            return "****"
        clean = national_id.replace(" ", "")
        if len(clean) <= 4:
            return "*" * len(clean)
        return "*" * (len(clean) - 3) + clean[-3:]

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
        head_len = 3 if prefix else 2
        tail_len = 2
        mask_len = len(digits) - head_len - tail_len
        if mask_len <= 0:
            return phone
        return prefix + digits[:head_len] + "*" * mask_len + digits[-tail_len:]

    @staticmethod
    def _send_claim_notification(system_user: SystemUser, lookup_id: str, raw_token: str, invited_by: SystemUser):
        context = {
            "system_name": system_user.system.name,
            "base_country": system_user.country.name if system_user.country else "",
            "organization_name": system_user.organization.name if system_user.organization else None,
            "role_name": system_user.role.name,
            "first_name": system_user.first_name or "User",
            "lookup_id": lookup_id,
            "claim_url": f"https://yourdomain.com/auth/claim/{lookup_id}/{raw_token}",
            "invited_by_name": invited_by.full_name if invited_by else "",
        }
        recipient = system_user.provisioning_email or system_user.provisioning_phone
        print(f"[CLAIM NOTIFICATION SENT] To: {recipient}\nContext: {context}")

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