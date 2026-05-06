import secrets
from datetime import timedelta
from typing import Optional, Tuple

import bcrypt
from django.db import transaction
from django.db.models import F
from django.utils import timezone

from accounts.identifier_utils import IdentifierNormaliser
from accounts.models import (
    Gender,
    IdentifierType,
    SocialAccount,
    SystemUser,
    SystemUserStatus,
    User,
)
from accounts.services.identifier_verification_service import (
    IdentifierVerificationError,
    IdentifierVerificationService,
)
from accounts.services.referral_service import ReferralService, ReferralServiceError
from audit.models import AuditEventType, AuditLog
from base.models import Country, Realm
from organizations.models import Branch, Organization
from permissions.models import Role
from systems.models import System
from utils.social_providers import normalize_social_provider


class AccountServiceError(Exception):
    pass


class ProvisionSystemUserError(AccountServiceError):
    pass


class SelfRegistrationError(AccountServiceError):
    pass


class RegistrationClosedError(SelfRegistrationError):
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
        self._referral_service = ReferralService()
        self._identifier_verification_service = IdentifierVerificationService()

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
        if not system_user.provisioning_email:
            raise SystemUserStatusError("Provisioning email is required to send an invite.")

        raw_token = secrets.token_urlsafe(48)
        token_hash = bcrypt.hashpw(raw_token.encode(), bcrypt.gensalt()).decode()

        system_user.claim_token_hash = token_hash
        system_user.claim_token_expires_at = timezone.now() + timedelta(hours=ttl_hours)
        system_user.invited_at = timezone.now()
        system_user.status = SystemUserStatus.INVITED
        system_user.save(update_fields=[
            "claim_token_hash",
            "claim_token_expires_at",
            "invited_at",
            "status",
        ])

        self._audit(
            AuditEventType.SYSTEM_USER_INVITED,
            actor_system_user=invited_by,
            subject=system_user,
            payload={
                "system": system_user.system.name,
                "provisioning_email": system_user.provisioning_email
            },
        )

        return system_user.claim_token_lookup_id, raw_token

    @transaction.atomic
    def provision_system_user(
            self,
            provisioned_by: SystemUser,
            system: System,
            country: Optional[Country],
            role: Role,
            provisioning_email: str = "",
            organization: Optional[Organization] = None,
            all_branches: bool = True,
            branch_grants: Optional[list[Branch]] = None,
            external_ref: str = "",
            metadata: Optional[dict] = None,
    ) -> SystemUser:
        if not provisioning_email:
            raise ProvisionSystemUserError("Provisioning email is required.")

        system_user = SystemUser.objects.create(
            user=None,
            system=system,
            country=country,
            role=role,
            organization=organization,
            status=SystemUserStatus.PENDING,
            provisioning_email=provisioning_email.strip().lower(),
            provisioned_by=provisioned_by,
            all_branches=all_branches,
            external_ref=external_ref,
            metadata=metadata or {},
        )
        if branch_grants and not all_branches:
            system_user.branch_access.set(branch_grants)

        self._referral_service.ensure_referral_code(system_user)
        self.invite(system_user=system_user, invited_by=provisioned_by)

        self._audit(
            AuditEventType.SYSTEM_USER_CREATED,
            actor_system_user=provisioned_by,
            subject=system_user,
            payload={"system": system.name},
        )

        return system_user

    def inspect_claim(self, lookup_id: str, token: str) -> dict:
        su = self._get_claimable_system_user(lookup_id, token)

        existing_user = self._find_user_by_email(su.provisioning_email, su.system.realm)

        existing_user_details = {
            "first_name": existing_user.first_name,
            "last_name": existing_user.last_name,
            "phone_number": self._mask_phone(existing_user.phone_number),
            "email": self._mask_email(existing_user.email),
            "system_users": list(
                SystemUser.objects
                .filter(user=existing_user, status=SystemUserStatus.ACTIVE)
                .select_related("system", "organization", "role", "country")
                .annotate(
                    system_name=F("system__name"),
                    organization_name=F("organization__name"),
                    role_name=F("role__name"),
                    country_name=F("country__name"),
                    last_login=F("last_login_at"),
                )
                .values(
                    "system_name",
                    "organization_name",
                    "role_name",
                    "country_name",
                    "last_login",
                )
            )
        } if existing_user else None

        return {
            "lookup_id": su.claim_token_lookup_id,
            "system": su.system.name,
            "organization": su.organization.name if su.organization_id else None,
            "role": su.role.name,
            "country": su.country.code if su.country_id else None,
            "status": su.status,
            "provisioning_email": self._mask_email(su.provisioning_email),
            "existing_account_found": existing_user is not None,
            "existing_user_details": existing_user_details,
            "available_action": "link" if existing_user else "new",
            "password_needed": (
                    su.system.allow_password_login
                    and su.system.password_type == System.PasswordType.PASSWORD
                    and (not existing_user.has_usable_password() if existing_user else True)
            ),
            "pin_needed": (
                    su.system.allow_password_login
                    and su.system.password_type == System.PasswordType.PIN
                    and (not existing_user.pin if existing_user else True)
            )
        }

    @transaction.atomic
    def claim_user(
            self,
            lookup_id: str,
            token: str,
            claim_action: str,
            password: Optional[str] = None,
            pin: Optional[str] = None,
            phone_number: Optional[str] = None,
            first_name: str = "",
            last_name: str = "",
            middle_name: str = "",
            display_name: str = "",
            date_of_birth=None,
            gender: str = Gender.OTHER,
            country: Optional[Country] = None,
            email_verification_id: Optional[str] = None,
            phone_verification_id: Optional[str] = None,
            ip_address: str = "",
    ) -> SystemUser:
        su = self._get_claimable_system_user(lookup_id, token)
        system = su.system
        existing_user = self._find_user_by_email(su.provisioning_email, system.realm)

        if claim_action == "link":
            if not existing_user:
                raise ClaimError("No existing account was found for this invite. Use 'new' instead.")

            user = existing_user
            self._ensure_credentials_if_needed(user, system, password, pin)

        elif claim_action == "new":
            if existing_user:
                raise ClaimError("An existing account was found. Use 'link' instead.")

            self._validate_required_profile(first_name, last_name, date_of_birth, gender)

            if not phone_number:
                raise ClaimError("Phone number is required.")

            if self._find_user_by_phone(phone_number, system.realm):
                raise ClaimError("Phone number already exists.")

            verified = self._validated_contact_verifications(
                email=su.provisioning_email,
                phone_number=phone_number,
                email_verification_id=email_verification_id,
                phone_verification_id=phone_verification_id,
                require_email_verification=False,
            )

            password, pin = self._resolve_credentials(system, password, pin)

            user = User.objects.create_user(
                realm=system.realm,
                email=su.provisioning_email,
                phone_number=phone_number,
                password=password,
                pin=pin,
                primary_country=country or su.country,
                first_name=first_name,
                last_name=last_name,
                middle_name=middle_name,
                display_name=display_name or f"{first_name} {last_name}".strip(),
                date_of_birth=date_of_birth,
                gender=gender,
            )

            self._apply_verified_contacts(user, verified)

        else:
            raise ClaimError("Invalid claim_action. Must be 'link' or  'new'.")

        self._mark_email_verified(user, su.provisioning_email)

        su.user = user
        su.status = SystemUserStatus.ACTIVE
        su.claimed_at = timezone.now()
        su.claim_token_hash = ""
        su.claim_token_expires_at = None
        su.save(update_fields=[
            "user", "status", "claimed_at", "claim_token_hash",
            "claim_token_expires_at"
        ])

        self._audit(
            AuditEventType.SYSTEM_USER_CLAIMED,
            actor_user=user,
            subject=su,
            payload={"action": claim_action, "system": system.name},
            ip=ip_address,
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
            password: Optional[str] = None,
            pin: Optional[str] = None,
            email_verification_id: Optional[str] = None,
            phone_verification_id: Optional[str] = None,
            primary_country: Optional[Country] = None,
            referral_code: Optional[str] = None,
            ip_address: str = "",
    ) -> Tuple[User, SystemUser]:
        if not system.registration_open:
            raise RegistrationClosedError("This system does not allow self-registration.")

        self._validate_required_profile(first_name, last_name, date_of_birth, gender)

        email, phone_number = self._require_email_and_phone(email, phone_number)

        verified = self._validated_contact_verifications(
            email=email,
            phone_number=phone_number,
            email_verification_id=email_verification_id,
            phone_verification_id=phone_verification_id,
        )

        password, pin = self._resolve_credentials(system, password, pin)

        existing_user, matched_on = self._find_existing_user_for_registration(
            realm=system.realm,
            email=email,
            phone_number=phone_number
        )
        if existing_user:
            if SystemUser.objects.filter(user=existing_user, system=system, status=SystemUserStatus.ACTIVE).exists():
                raise SelfRegistrationError(
                    f"An account with this {matched_on} is already registered in this system."
                )
            raise LinkAccountRequired(existing_user=existing_user, matched_on=matched_on)

        user = User.objects.create_user(
            realm=system.realm,
            email=email,
            phone_number=phone_number,
            password=password,
            pin=pin,
            primary_country=primary_country,
            first_name=first_name,
            last_name=last_name,
            middle_name=middle_name,
            display_name=display_name or f"{first_name} {last_name}".strip(),
            date_of_birth=date_of_birth,
            gender=gender,
        )

        self._apply_verified_contacts(user, verified)

        system_user = self._create_system_user_record(
            user=user,
            system=system,
            role=role,
            primary_country=primary_country,
        )
        self._attach_referral_if_present(system_user, referral_code)

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
            primary_country: Optional[Country] = None,
            referral_code: Optional[str] = None,
            ip_address: str = "",
    ) -> Tuple[User, SystemUser]:
        if existing_user.realm_id and existing_user.realm_id != system.realm_id:
            raise SelfRegistrationError("User realm and system realm do not match.")

        if SystemUser.objects.filter(user=existing_user, system=system, status=SystemUserStatus.ACTIVE).exists():
            raise SelfRegistrationError("This account is already registered in this system.")

        system_user = self._create_system_user_record(
            user=existing_user,
            system=system,
            role=role,
            primary_country=primary_country,
        )

        self._attach_referral_if_present(system_user, referral_code)

        self._audit(
            AuditEventType.USER_LINKED_TO_SYSTEM,
            actor_user=existing_user,
            ip=ip_address,
            payload={"system": system.name, "via": "self_registration_link"},
        )

        return existing_user, system_user

    @transaction.atomic
    def self_registration_social(
            self,
            system: System,
            role: Role,
            provider: str,
            uid: str,
            first_name: str,
            last_name: str,
            middle_name: str = "",
            display_name: str = "",
            date_of_birth=None,
            gender: str = Gender.OTHER,
            email: Optional[str] = None,
            phone_number: Optional[str] = None,
            access_token: str = "",
            refresh_token: str = "",
            extra_data: Optional[dict] = None,
            email_verification_id: Optional[str] = None,
            phone_verification_id: Optional[str] = None,
            primary_country: Optional[Country] = None,
            referral_code: Optional[str] = None,
            ip_address: str = "",
    ) -> Tuple[User, SystemUser]:
        if not system.registration_open:
            raise RegistrationClosedError("This system does not allow self-registration.")

        self._validate_required_profile(first_name, last_name, date_of_birth, gender)
        provider = self._validate_social_provider_for_system(system, provider)

        uid = (uid or "").strip()
        if not uid:
            raise SelfRegistrationError("Social account uid is required.")

        email, phone_number = self._require_email_and_phone(email, phone_number)

        verified = self._validated_contact_verifications(
            email=email,
            phone_number=phone_number,
            email_verification_id=email_verification_id,
            phone_verification_id=phone_verification_id,
        )

        social = SocialAccount.objects.select_related("user").filter(
            provider=provider,
            uid=uid,
        ).first()
        if social:
            if SystemUser.objects.filter(
                    user=social.user,
                    system=system,
                    status=SystemUserStatus.ACTIVE
            ).exists():
                raise SelfRegistrationError("This social account is already registered in this system.")

            return self.self_registration_social_link(
                existing_user=social.user,
                system=system,
                role=role,
                provider=provider,
                uid=uid,
                access_token=access_token,
                refresh_token=refresh_token,
                extra_data=extra_data,
                primary_country=primary_country,
                referral_code=referral_code,
                ip_address=ip_address,
            )

        existing_user, matched_on = self._find_existing_user_for_registration(
            realm=system.realm,
            email=email,
            phone_number=phone_number
        )
        if existing_user:
            if SystemUser.objects.filter(
                    user=existing_user,
                    system=system,
                    status=SystemUserStatus.ACTIVE
            ).exists():
                raise SelfRegistrationError(
                    f"An account with this {matched_on} is already registered in this system."
                )
            raise LinkAccountRequired(existing_user=existing_user, matched_on=matched_on)

        user = User.objects.create_user(
            realm=system.realm,
            email=email,
            phone_number=phone_number,
            primary_country=primary_country,
            first_name=first_name,
            last_name=last_name,
            middle_name=middle_name,
            display_name=display_name or f"{first_name} {last_name}".strip(),
            date_of_birth=date_of_birth,
            gender=gender,
        )

        self._apply_verified_contacts(user, verified)

        self.link_social_account(
            user=user,
            provider=provider,
            uid=uid,
            access_token=access_token,
            refresh_token=refresh_token,
            extra_data=extra_data,
        )

        system_user = self._create_system_user_record(
            user=user,
            system=system,
            role=role,
            primary_country=primary_country,
        )

        self._attach_referral_if_present(system_user, referral_code)

        self._audit(
            AuditEventType.USER_CREATED,
            actor_user=user,
            ip=ip_address,
            payload={
                "system": system.name,
                "via": "self_registration_social",
                "provider": provider
            },
        )

        return user, system_user

    @transaction.atomic
    def self_registration_social_link(
            self,
            existing_user: User,
            system: System,
            role: Role,
            provider: str,
            uid: str,
            access_token: str = "",
            refresh_token: str = "",
            extra_data: Optional[dict] = None,
            primary_country: Optional[Country] = None,
            referral_code: Optional[str] = None,
            ip_address: str = "",
    ) -> Tuple[User, SystemUser]:
        provider = self._validate_social_provider_for_system(system, provider)
        uid = (uid or "").strip()
        if not uid:
            raise SelfRegistrationError("Social account uid is required.")

        if existing_user.realm_id and existing_user.realm_id != system.realm_id:
            raise SelfRegistrationError("User realm and system realm do not match.")

        if SystemUser.objects.filter(
                user=existing_user,
                system=system,
                status=SystemUserStatus.ACTIVE
        ).exists():
            raise SelfRegistrationError("This account is already registered in this system.")

        self.link_social_account(
            user=existing_user,
            provider=provider,
            uid=uid,
            access_token=access_token,
            refresh_token=refresh_token,
            extra_data=extra_data,
        )

        system_user = self._create_system_user_record(
            user=existing_user,
            system=system,
            role=role,
            primary_country=primary_country,
        )

        self._attach_referral_if_present(system_user, referral_code)

        self._audit(
            AuditEventType.USER_LINKED_TO_SYSTEM,
            actor_user=existing_user,
            ip=ip_address,
            payload={
                "system": system.name,
                "via": "self_registration_social_link",
                "provider": provider
            },
        )

        return existing_user, system_user

    @transaction.atomic
    def update_profile(self, system_user: SystemUser, **fields) -> SystemUser:
        user = system_user.user
        if not user:
            raise SelfRegistrationError("No user is linked to this system profile.")

        user_fields = {
            "first_name",
            "last_name",
            "middle_name",
            "display_name",
            "date_of_birth",
            "gender",
            "profile_photo_url",
        }
        updated_user = [key for key in fields if key in user_fields]
        for key in updated_user:
            setattr(user, key, fields[key])
        if updated_user:
            user.save(update_fields=updated_user)

        updated_system_user = [key for key in fields if key in {"metadata", "external_ref"}]
        for key in updated_system_user:
            setattr(system_user, key, fields[key])
        if updated_system_user:
            system_user.save(update_fields=updated_system_user)

        self._audit(
            AuditEventType.USER_UPDATED,
            actor_user=user,
            subject=system_user,
            payload={
                "updated_user_fields": updated_user,
                "updated_system_fields": updated_system_user
            },
        )

        return system_user

    @transaction.atomic
    def update_identifier(
            self,
            user: User,
            identifier_type: str,
            new_value: str,
            verification_id: str,
    ) -> None:
        if not identifier_type in IdentifierType.values:
            raise ManageIdentifierError("Invalid identifier type.")

        try:
            verification = self._identifier_verification_service.assert_verified_identifier(
                identifier_type=identifier_type,
                value=new_value,
                verification_id=verification_id,
            )
        except IdentifierVerificationError as exc:
            raise ManageIdentifierError(str(exc))
        if not verification:
            raise ManageIdentifierError(f"A verified {identifier_type} is required.")

        if identifier_type == IdentifierType.EMAIL:
            user.email = new_value
            user.save(update_fields=["email"])

        elif identifier_type == IdentifierType.PHONE:
            user.phone_number = new_value
            user.save(update_fields=["phone"])

        self._apply_verified_contacts(user, {identifier_type: verification})


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
        system_user.status = SystemUserStatus.SUSPENDED
        system_user.save(update_fields=["suspended_reason", "suspended_at", "status"])

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
        system_user.status = SystemUserStatus.ACTIVE
        system_user.save(update_fields=["suspended_reason", "suspended_at", "status"])

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
            extra_data: Optional[dict] = None,
    ) -> SocialAccount:
        provider = self._validate_social_provider(provider)

        uid = (uid or "").strip()
        if not uid:
            raise SelfRegistrationError("Social account uid is required.")

        social, _ = SocialAccount.objects.update_or_create(
            provider=provider,
            uid=uid,
            defaults={
                "user": user,
                "access_token": access_token,
                "refresh_token": refresh_token,
                "extra_data": extra_data or {},
            },
        )

        return social

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

    def _validated_contact_verifications(
            self,
            email: str,
            phone_number: str,
            email_verification_id: Optional[str],
            phone_verification_id: Optional[str],
            require_email_verification: bool = True,
    ) -> dict:
        verified = {}
        for contact_type, value, verification_id in (
            (IdentifierType.EMAIL, email, email_verification_id),
            (IdentifierType.PHONE, phone_number, phone_verification_id),
        ):
            if contact_type == IdentifierType.EMAIL and not require_email_verification:
                continue
            try:
                verification = self._identifier_verification_service.assert_verified_identifier(
                    identifier_type=contact_type,
                    value=value,
                    verification_id=verification_id,
                )
            except IdentifierVerificationError as exc:
                raise SelfRegistrationError(str(exc))

            if not verification:
                raise SelfRegistrationError(f"A verified {contact_type} is required.")

            verified[contact_type] = verification

        return verified

    @staticmethod
    def _mark_email_verified(user: User, email: str) -> None:
        if user.email != (email or "").strip().lower() or user.email_verified:
            return

        now = timezone.now()
        user.email_verified = True
        user.email_verified_at = now
        user.save(update_fields=["email_verified", "email_verified_at"])

    def _apply_verified_contacts(self, user: User, verified: dict) -> None:
        updates = []
        now = timezone.now()

        if IdentifierType.EMAIL in verified:
            user.email_verified = True
            user.email_verified_at = now
            self._identifier_verification_service.consume_registration_verification(
                verified[IdentifierType.EMAIL]
            )
            updates.extend(["email_verified", "email_verified_at"])

        if IdentifierType.PHONE in verified:
            user.phone_verified = True
            user.phone_verified_at = now
            self._identifier_verification_service.consume_registration_verification(
                verified[IdentifierType.PHONE]
            )
            updates.extend(["phone_verified", "phone_verified_at"])

        if updates:
            user.save(update_fields=updates)

    @staticmethod
    def _validate_required_profile(first_name: str, last_name: str, date_of_birth, gender: str) -> None:
        if not first_name:
            raise SelfRegistrationError("First name is required.")
        if not last_name:
            raise SelfRegistrationError("Last name is required.")
        if not date_of_birth:
            raise SelfRegistrationError("Date of birth is required.")
        if not gender:
            raise SelfRegistrationError("Gender is required.")

    @staticmethod
    def _require_email_and_phone(email: Optional[str], phone_number: Optional[str]) -> Tuple[str, str]:
        email = (email or "").strip().lower()
        phone_number = (phone_number or "").strip()
        if not email:
            raise SelfRegistrationError("Email is required.")
        if not phone_number:
            raise SelfRegistrationError("Phone number is required.")
        return email, phone_number

    @staticmethod
    def _find_existing_user_for_registration(
            realm: Realm,
            email: str,
            phone_number: str
    ) -> Tuple[Optional[User], Optional[str]]:
        try:
            return (
                User.objects.get_by_identifier(realm, email, IdentifierType.EMAIL),
                IdentifierType.EMAIL
            )
        except User.DoesNotExist:
            pass
        try:
            return (
                User.objects.get_by_identifier(realm, phone_number, IdentifierType.PHONE),
                IdentifierType.PHONE
            )
        except User.DoesNotExist:
            pass
        return None, None

    @staticmethod
    def _find_user_by_email(email: str, realm: Realm) -> Optional[User]:
        try:
            return User.objects.get_by_identifier(realm, email, IdentifierType.EMAIL)
        except User.DoesNotExist:
            return None

    @staticmethod
    def _find_user_by_phone(phone_number: str, realm: Realm) -> Optional[User]:
        try:
            return User.objects.get_by_identifier(realm, phone_number, IdentifierType.PHONE)
        except User.DoesNotExist:
            return None

    @staticmethod
    def _get_claimable_system_user(lookup_id: str, token: str) -> SystemUser:
        try:
            su = (
                SystemUser.objects
                .select_related("system", "organization", "country", "role")
                .get(claim_token_lookup_id=lookup_id)
            )
        except SystemUser.DoesNotExist:
            raise InvalidClaimTokenError("Invite not found.")
        if not su.claim_token_hash or not su.claim_token_expires_at:
            raise InvalidClaimTokenError("Invite token is invalid.")
        if su.claim_token_expires_at <= timezone.now():
            raise ClaimExpiredError("Invite token has expired.")
        if not bcrypt.checkpw(token.encode(), su.claim_token_hash.encode()):
            raise InvalidClaimTokenError("Invite token is invalid.")
        return su

    @staticmethod
    def _ensure_credentials_if_needed(
            user: User,
            system: System,
            password: Optional[str],
            pin: Optional[str],
    ) -> None:
        updated = []
        if (
                system.password_type == System.PasswordType.PASSWORD
                and system.allow_password_login
                and not user.has_usable_password()
        ):
            if not password:
                raise ClaimError("Password is required to finish linking this invited account.")
            user.set_password(password)
            updated.append("password")

        if (
                system.password_type == System.PasswordType.PIN
                and system.allow_password_login
                and not user.pin
        ):
            if not pin:
                raise ClaimError("PIN is required to finish linking this invited account.")
            user.set_pin(pin)
            updated.append("pin")

        if updated:
            user.save(update_fields=updated)

    def _create_system_user_record(
            self,
            user: User,
            system: System,
            role: Role,
            organization: Optional[Organization] = None,
            primary_country: Optional[Country] = None,
    ) -> SystemUser:
        defaults = {
            "organization": organization,
            "country": primary_country or system.available_countries.first(),
            "role": role,
            "status": SystemUserStatus.ACTIVE,
        }
        system_user, created = SystemUser.objects.get_or_create(
            user=user,
            system=system,
            defaults=defaults,
        )
        if not created:
            for key, value in defaults.items():
                setattr(system_user, key, value)
            system_user.save(update_fields=list(defaults.keys()))

        self._referral_service.ensure_referral_code(system_user)

        return system_user

    def _attach_referral_if_present(self, system_user: SystemUser, referral_code: Optional[str]) -> None:
        if not referral_code:
            return
        try:
            self._referral_service.attach_referral(
                referred=system_user,
                referral_code=referral_code
            )
        except ReferralServiceError as exc:
            raise SelfRegistrationError(str(exc))

    @staticmethod
    def _validate_social_provider(provider: str) -> str:
        try:
            return normalize_social_provider(provider)
        except Exception as exc:
            raise SelfRegistrationError(str(exc))

    def _validate_social_provider_for_system(self, system: System, provider: str) -> str:
        provider = self._validate_social_provider(provider)
        if not system.allow_social_login:
            raise SelfRegistrationError("This system does not allow social login.")
        if system.allowed_social_providers and provider not in system.allowed_social_providers:
            raise SelfRegistrationError(f"This system does not allow {provider} social login.")
        return provider

    @staticmethod
    def _mask_email(email: str) -> str:
        local, _, domain = email.partition("@")
        if not local or not domain:
            return email
        if len(local) <= 2:
            masked_local = local[0] + "*" * max(0, len(local) - 1)
        else:
            masked_local = local[0] + "*" * (len(local) - 2) + local[-1]
        return f"{masked_local}@{domain}"

    @staticmethod
    def _mask_phone(phone: str) -> str:
        if not phone:
            return phone

        digits = "".join(filter(str.isdigit, phone))

        if len(digits) <= 4:
            return "*" * len(digits)

        # Assume country code is first 3 digits if number is long enough (e.g. 254)
        if len(digits) > 9:
            country_code = digits[:3]
            rest = digits[3:]
        else:
            country_code = ""
            rest = digits

        if len(rest) <= 4:
            return country_code + ("*" * len(rest))

        masked = (
                country_code +
                rest[:2] +
                "*" * (len(rest) - 4) +
                rest[-2:]
        )

        return masked

    @staticmethod
    def _audit(
            event_type: str,
            actor_user: Optional[User] = None,
            actor_system_user: Optional[SystemUser] = None,
            subject=None,
            ip: str = "",
            identifier_type: str = "",
            payload: Optional[dict] = None,
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
