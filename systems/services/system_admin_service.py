import secrets
from typing import Optional

import bcrypt
from django.core.exceptions import ValidationError
from django.db import transaction
from django.utils.text import slugify

from accounts.models import SystemUser
from audit.models import AuditEventType, AuditLog
from base.models import Country, Realm
from systems.models import System, SystemClient, SystemSettings
from utils.social_providers import normalize_social_provider_list


class SystemAdminServiceError(Exception):
    pass


class SystemAdminService:
    @staticmethod
    def _normalize_social_providers(providers: Optional[list]) -> Optional[list]:
        if providers is None:
            return None
        try:
            return normalize_social_provider_list(providers)
        except ValidationError as exc:
            raise SystemAdminServiceError(exc.messages[0])

    @staticmethod
    def _validate_referral_settings(*, allows_referrals: bool, registration_open: bool) -> None:
        if allows_referrals and not registration_open:
            raise SystemAdminServiceError(
                "Referrals can only be enabled for systems that allow self-registration."
            )

    @transaction.atomic
    def create_system(
        self,
        *,
        realm: Realm,
        name: str,
        slug: Optional[str] = None,
        countries: Optional[list[Country]] = None,
        performed_by: Optional[SystemUser] = None,
        **kwargs,
    ) -> System:
        clean_name = (name or "").strip()
        if not clean_name:
            raise SystemAdminServiceError("System name is required.")

        self._validate_referral_settings(
            allows_referrals=kwargs.get("allows_referrals", False),
            registration_open=kwargs.get("registration_open", True),
        )
        kwargs["allowed_social_providers"] = self._normalize_social_providers(
            kwargs.get("allowed_social_providers", [])
        )

        final_slug = self._unique_slug(slug or clean_name)
        system = System.objects.create(
            realm=realm,
            name=clean_name,
            slug=final_slug,
            **kwargs,
        )

        if countries:
            system.available_countries.set(countries)

        self._audit(
            AuditEventType.SYSTEM_CREATED,
            actor_system_user=performed_by,
            subject=system,
            payload={
                "name": system.name,
                "slug": system.slug,
                "country_codes": [country.code for country in countries or []],
            },
        )
        return system

    @transaction.atomic
    def update_system(
        self,
        *,
        system: System,
        performed_by: Optional[SystemUser] = None,
        name: Optional[str] = None,
        description: Optional[str] = None,
        logo_url: Optional[str] = None,
        website: Optional[str] = None,
        password_type: Optional[str] = None,
        allow_password_login: Optional[bool] = None,
        allow_passwordless_login: Optional[bool] = None,
        allow_magic_link_login: Optional[bool] = None,
        allow_social_login: Optional[bool] = None,
        passwordless_only: Optional[bool] = None,
        allowed_social_providers: Optional[list] = None,
        registration_open: Optional[bool] = None,
        auto_login_after_registration: Optional[bool] = None,
        requires_approval: Optional[bool] = None,
        allows_referrals: Optional[bool] = None,
        referral_reward_amount = None,
        auto_verify_referrals: Optional[bool] = None,
        mfa_required: Optional[bool] = None,
        mfa_required_enforced: Optional[bool] = None,
        allowed_mfa_methods: Optional[list] = None,
    ) -> System:
        updated = []

        if name is not None:
            clean_name = name.strip()
            if not clean_name:
                raise SystemAdminServiceError("System name cannot be blank.")
            if clean_name != system.name:
                system.slug = self._unique_slug(clean_name, exclude_id=system.id)
                updated.append("slug")
            system.name = clean_name
            updated.append("name")

        if description is not None:
            system.description = description
            updated.append("description")
        if logo_url is not None:
            system.logo_url = logo_url
            updated.append("logo_url")
        if website is not None:
            system.website = website
            updated.append("website")
        if password_type is not None:
            system.password_type = password_type
            updated.append("password_type")
        if allow_password_login is not None:
            system.allow_password_login = allow_password_login
            updated.append("allow_password_login")
        if allow_passwordless_login is not None:
            system.allow_passwordless_login = allow_passwordless_login
            updated.append("allow_passwordless_login")
        if allow_magic_link_login is not None:
            system.allow_magic_link_login = allow_magic_link_login
            updated.append("allow_magic_link_login")
        if allow_social_login is not None:
            system.allow_social_login = allow_social_login
            updated.append("allow_social_login")
        if passwordless_only is not None:
            system.passwordless_only = passwordless_only
            updated.append("passwordless_only")
        if allowed_social_providers is not None:
            system.allowed_social_providers = self._normalize_social_providers(allowed_social_providers)
            updated.append("allowed_social_providers")
        if registration_open is not None:
            system.registration_open = registration_open
            updated.append("registration_open")
        if auto_login_after_registration is not None:
            system.auto_login_after_registration = auto_login_after_registration
            updated.append("auto_login_after_registration")
        if requires_approval is not None:
            system.requires_approval = requires_approval
            updated.append("requires_approval")
        if allows_referrals is not None:
            system.allows_referrals = allows_referrals
            updated.append("allows_referrals")
        if referral_reward_amount is not None:
            system.referral_reward_amount = referral_reward_amount
            updated.append("referral_reward_amount")
        if auto_verify_referrals is not None:
            system.auto_verify_referrals = auto_verify_referrals
            updated.append("auto_verify_referrals")
        if mfa_required is not None:
            system.mfa_required = mfa_required
            updated.append("mfa_required")
        if mfa_required_enforced is not None:
            system.mfa_required_enforced = mfa_required_enforced
            updated.append("mfa_required_enforced")
        if allowed_mfa_methods is not None:
            system.allowed_mfa_methods = allowed_mfa_methods
            updated.append("allowed_mfa_methods")

        if updated:
            self._validate_referral_settings(
                allows_referrals=system.allows_referrals,
                registration_open=system.registration_open,
            )
            system.save(update_fields=updated)
            if system.referrals_enabled:
                from accounts.services.referral_service import ReferralService
                ReferralService().ensure_system_referral_codes(system)
            self._audit(
                AuditEventType.SYSTEM_SETTINGS_CHANGED,
                actor_system_user=performed_by,
                subject=system,
                payload={"action": "updated", "updated_fields": updated},
            )

        return system

    @transaction.atomic
    def deactivate_system(
        self,
        *,
        system: System,
        performed_by: Optional[SystemUser] = None,
    ) -> System:
        if not system.is_active:
            raise SystemAdminServiceError("System is already inactive.")

        system.is_active = False
        system.save(update_fields=["is_active"])

        self._audit(
            AuditEventType.SYSTEM_SETTINGS_CHANGED,
            actor_system_user=performed_by,
            subject=system,
            payload={"action": "deactivated"},
        )
        return system

    @transaction.atomic
    def reactivate_system(
        self,
        *,
        system: System,
        performed_by: Optional[SystemUser] = None,
    ) -> System:
        if system.is_active:
            raise SystemAdminServiceError("System is already active.")

        system.is_active = True
        system.save(update_fields=["is_active"])

        self._audit(
            AuditEventType.SYSTEM_SETTINGS_CHANGED,
            actor_system_user=performed_by,
            subject=system,
            payload={"action": "reactivated"},
        )
        return system

    @transaction.atomic
    def add_country(
        self,
        *,
        system: System,
        country: Country,
        performed_by: Optional[SystemUser] = None,
    ) -> Country:
        if system.available_countries.filter(id=country.id).exists():
            raise SystemAdminServiceError(
                f"{country.name} is already available on {system.name}."
            )

        system.available_countries.add(country)
        self._audit(
            AuditEventType.SYSTEM_SETTINGS_CHANGED,
            actor_system_user=performed_by,
            subject=system,
            payload={"action": "country_added", "country_code": country.code},
        )
        return country

    @transaction.atomic
    def remove_country(
        self,
        *,
        system: System,
        country: Country,
        performed_by: Optional[SystemUser] = None,
    ) -> Country:
        if not system.available_countries.filter(id=country.id).exists():
            raise SystemAdminServiceError(
                f"{country.name} is not configured on {system.name}."
            )

        system.available_countries.remove(country)
        self._audit(
            AuditEventType.SYSTEM_SETTINGS_CHANGED,
            actor_system_user=performed_by,
            subject=system,
            payload={"action": "country_removed", "country_code": country.code},
        )
        return country

    @transaction.atomic
    def create_client(
        self,
        *,
        system: System,
        name: str,
        performed_by: Optional[SystemUser] = None,
        client_type: str = SystemClient.ClientType.CONFIDENTIAL,
        redirect_uris: Optional[list] = None,
        logout_uris: Optional[list] = None,
        allowed_scopes: Optional[list] = None,
        access_token_ttl: int = 0,
        refresh_token_ttl: int = 0,
        id_token_ttl: int = 0,
        override_allow_passwordless_login=None,
        override_allow_magic_link_login=None,
        override_allow_social_login=None,
        override_allowed_social_providers=None,
        is_active: bool = True,
    ) -> tuple[SystemClient, str]:
        clean_name = (name or "").strip()
        if not clean_name:
            raise SystemAdminServiceError("Client name is required.")

        raw_secret = ""
        secret_hash = ""
        if client_type != SystemClient.ClientType.PUBLIC:
            raw_secret = secrets.token_urlsafe(48)
            secret_hash = bcrypt.hashpw(
                raw_secret.encode(),
                bcrypt.gensalt(),
            ).decode()

        client = SystemClient.objects.create(
            system=system,
            name=clean_name,
            client_type=client_type,
            redirect_uris=redirect_uris or [],
            logout_uris=logout_uris or [],
            allowed_scopes=allowed_scopes or [],
            access_token_ttl=access_token_ttl,
            refresh_token_ttl=refresh_token_ttl,
            id_token_ttl=id_token_ttl,
            override_allow_passwordless_login=override_allow_passwordless_login,
            override_allow_magic_link_login=override_allow_magic_link_login,
            override_allow_social_login=override_allow_social_login,
            override_allowed_social_providers=self._normalize_social_providers(override_allowed_social_providers),
            client_secret_hash=secret_hash,
            is_active=is_active,
        )

        self._audit(
            AuditEventType.SYSTEM_SETTINGS_CHANGED,
            actor_system_user=performed_by,
            subject=client,
            payload={
                "action": "client_created",
                "system_id": str(system.id),
                "client_name": client.name,
                "client_type": client.client_type,
            },
        )
        return client, raw_secret

    @transaction.atomic
    def update_client(
        self,
        *,
        client: SystemClient,
        performed_by: Optional[SystemUser] = None,
        name: Optional[str] = None,
        client_type: Optional[str] = None,
        redirect_uris: Optional[list] = None,
        logout_uris: Optional[list] = None,
        allowed_scopes: Optional[list] = None,
        access_token_ttl: Optional[int] = None,
        refresh_token_ttl: Optional[int] = None,
        id_token_ttl: Optional[int] = None,
        override_allow_passwordless_login=None,
        override_allow_magic_link_login=None,
        override_allow_social_login=None,
        override_allowed_social_providers=None,
    ) -> SystemClient:
        updated = []

        if name is not None:
            clean_name = name.strip()
            if not clean_name:
                raise SystemAdminServiceError("Client name cannot be blank.")
            client.name = clean_name
            updated.append("name")
        if client_type is not None:
            client.client_type = client_type
            updated.append("client_type")
        if redirect_uris is not None:
            client.redirect_uris = redirect_uris
            updated.append("redirect_uris")
        if logout_uris is not None:
            client.logout_uris = logout_uris
            updated.append("logout_uris")
        if allowed_scopes is not None:
            client.allowed_scopes = allowed_scopes
            updated.append("allowed_scopes")
        if access_token_ttl is not None:
            client.access_token_ttl = access_token_ttl
            updated.append("access_token_ttl")
        if refresh_token_ttl is not None:
            client.refresh_token_ttl = refresh_token_ttl
            updated.append("refresh_token_ttl")
        if id_token_ttl is not None:
            client.id_token_ttl = id_token_ttl
            updated.append("id_token_ttl")
        if override_allow_passwordless_login is not None:
            client.override_allow_passwordless_login = override_allow_passwordless_login
            updated.append("override_allow_passwordless_login")
        if override_allow_magic_link_login is not None:
            client.override_allow_magic_link_login = override_allow_magic_link_login
            updated.append("override_allow_magic_link_login")
        if override_allow_social_login is not None:
            client.override_allow_social_login = override_allow_social_login
            updated.append("override_allow_social_login")
        if override_allowed_social_providers is not None:
            client.override_allowed_social_providers = self._normalize_social_providers(
                override_allowed_social_providers
            )
            updated.append("override_allowed_social_providers")

        if updated:
            client.save(update_fields=updated)
            self._audit(
                AuditEventType.SYSTEM_SETTINGS_CHANGED,
                actor_system_user=performed_by,
                subject=client,
                payload={"action": "client_updated", "updated_fields": updated},
            )

        return client

    @transaction.atomic
    def deactivate_client(
        self,
        *,
        client: SystemClient,
        performed_by: Optional[SystemUser] = None,
    ) -> SystemClient:
        if not client.is_active:
            raise SystemAdminServiceError("Client is already inactive.")

        client.is_active = False
        client.save(update_fields=["is_active"])
        self._audit(
            AuditEventType.SYSTEM_SETTINGS_CHANGED,
            actor_system_user=performed_by,
            subject=client,
            payload={"action": "client_deactivated"},
        )
        return client

    @transaction.atomic
    def reactivate_client(
        self,
        *,
        client: SystemClient,
        performed_by: Optional[SystemUser] = None,
    ) -> SystemClient:
        if client.is_active:
            raise SystemAdminServiceError("Client is already active.")

        client.is_active = True
        client.save(update_fields=["is_active"])
        self._audit(
            AuditEventType.SYSTEM_SETTINGS_CHANGED,
            actor_system_user=performed_by,
            subject=client,
            payload={"action": "client_reactivated"},
        )
        return client

    @transaction.atomic
    def set_system_setting(
        self,
        *,
        system: System,
        key: str,
        value: str,
        performed_by: Optional[SystemUser] = None,
        value_type: str = SystemSettings.ValueType.STRING,
        description: str = "",
        is_secret: bool = False,
    ) -> SystemSettings:
        clean_key = (key or "").strip()
        if not clean_key:
            raise SystemAdminServiceError("Setting key is required.")

        setting, _ = SystemSettings.objects.update_or_create(
            system=system,
            key=clean_key,
            defaults={
                "value": value,
                "value_type": value_type,
                "description": description,
                "is_secret": is_secret,
            },
        )
        self._audit(
            AuditEventType.SYSTEM_SETTINGS_CHANGED,
            actor_system_user=performed_by,
            subject=setting,
            payload={"system": system.name, "key": clean_key},
        )
        return setting

    @staticmethod
    def _unique_slug(raw_value: str, exclude_id=None) -> str:
        base_slug = slugify(raw_value) or "system"
        candidate = base_slug
        suffix = 2

        while True:
            qs = System.objects.filter(slug=candidate)
            if exclude_id:
                qs = qs.exclude(id=exclude_id)
            if not qs.exists():
                return candidate
            candidate = f"{base_slug}-{suffix}"
            suffix += 1

    @staticmethod
    def _audit(event_type, actor_system_user=None, subject=None, payload=None):
        is_system = isinstance(subject, System)
        subject_system = getattr(subject, "system", None)
        AuditLog.objects.create(
            event_type=event_type,
            actor_user_id=actor_system_user.user_id if actor_system_user and actor_system_user.user_id else None,
            actor_system_user_id=actor_system_user.id if actor_system_user else None,
            subject_type=subject.__class__.__name__ if subject else "",
            subject_id=str(subject.id) if subject else "",
            subject_label=str(subject) if subject else "",
            system_id=str(subject.id) if is_system and subject else getattr(subject, "system_id", None),
            system_name=subject.name if is_system and subject else subject_system.name if subject_system else "",
            payload=payload or {},
        )
