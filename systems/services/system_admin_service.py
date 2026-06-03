import secrets
from urllib.parse import urljoin

import bcrypt
from django.conf import settings
from django.core.exceptions import ValidationError
from django.core.validators import URLValidator
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
    def generate_client_secret() -> str:
        return secrets.token_urlsafe(48)

    @staticmethod
    def hash_client_secret(raw_secret: str) -> str:
        return bcrypt.hashpw(
            raw_secret.encode(),
            bcrypt.gensalt(),
        ).decode()

    @staticmethod
    def _normalize_social_providers(providers: list | None) -> list | None:
        if providers is None:
            return None
        try:
            return normalize_social_provider_list(providers)
        except ValidationError as exc:
            raise SystemAdminServiceError(exc.messages[0]) from exc

    @staticmethod
    def _validate_referral_settings(*, allows_referrals: bool, registration_open: bool) -> None:
        if allows_referrals and not registration_open:
            raise SystemAdminServiceError(
                'Referrals can only be enabled for systems that allow self-registration.'
            )

    @staticmethod
    def _clean_subdomain(subdomain: str | None) -> str | None:
        if subdomain is None:
            return None
        clean_subdomain = subdomain.strip().rstrip('/')
        if not clean_subdomain:
            raise SystemAdminServiceError('Subdomain cannot be blank.')
        try:
            URLValidator(schemes=['http', 'https'])(clean_subdomain)
        except ValidationError as exc:
            raise SystemAdminServiceError('Subdomain must be a valid full URL.') from exc
        return clean_subdomain

    @staticmethod
    def _default_branding_from(parent_system: System) -> dict:
        return {
            'logo_url': parent_system.logo_url,
            'favicon_url': parent_system.favicon_url,
            'primary_color': parent_system.primary_color,
            'secondary_color': parent_system.secondary_color,
            'accent_colors': parent_system.accent_colors,
            'tagline': parent_system.tagline,
        }

    @staticmethod
    def _default_system_config_from(parent_system: System) -> dict:
        return {
            'description': parent_system.description,
            'logo_url': parent_system.logo_url,
            'favicon_url': parent_system.favicon_url,
            'website': parent_system.website,
            'primary_color': parent_system.primary_color,
            'secondary_color': parent_system.secondary_color,
            'accent_colors': parent_system.accent_colors,
            'tagline': parent_system.tagline,
            'password_type': parent_system.password_type,
            'allow_password_login': parent_system.allow_password_login,
            'allow_passwordless_login': parent_system.allow_passwordless_login,
            'allow_magic_link_login': parent_system.allow_magic_link_login,
            'allow_social_login': parent_system.allow_social_login,
            'passwordless_only': parent_system.passwordless_only,
            'allowed_social_providers': parent_system.allowed_social_providers,
            'registration_open': parent_system.registration_open,
            'auto_login_after_registration': parent_system.auto_login_after_registration,
            'requires_approval': parent_system.requires_approval,
            'allows_referrals': parent_system.allows_referrals,
            'referral_reward_amount': parent_system.referral_reward_amount,
            'auto_verify_referrals': parent_system.auto_verify_referrals,
            'mfa_required': parent_system.mfa_required,
            'mfa_required_enforced': parent_system.mfa_required_enforced,
            'allowed_mfa_methods': parent_system.allowed_mfa_methods,
            'refresh_token_timeout_minutes': parent_system.refresh_token_timeout_minutes,
            'mfa_reauth_window_minutes': parent_system.mfa_reauth_window_minutes,
            'default_role': parent_system.default_role,
        }

    @transaction.atomic
    def create_system(
        self,
        *,
        realm: Realm,
        name: str,
        slug: str | None = None,
        countries: list[Country] | None = None,
        performed_by: SystemUser | None = None,
        **kwargs,
    ) -> System:
        clean_name = (name or '').strip()
        if not clean_name:
            raise SystemAdminServiceError('System name is required.')

        self._validate_referral_settings(
            allows_referrals=kwargs.get('allows_referrals', False),
            registration_open=kwargs.get('registration_open', True),
        )
        kwargs['allowed_social_providers'] = self._normalize_social_providers(
            kwargs.get('allowed_social_providers', [])
        )
        kwargs['subdomain'] = self._clean_subdomain(kwargs.get('subdomain'))

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
                'name': system.name,
                'slug': system.slug,
                'country_codes': [country.code for country in countries or []],
            },
        )
        return system

    @transaction.atomic
    def create_reseller(
        self,
        *,
        parent_system: System,
        name: str,
        subdomain: str,
        slug: str | None = None,
        countries: list[Country] | None = None,
        performed_by: SystemUser | None = None,
        client_name: str = 'Default Web App',
        redirect_uris: list | None = None,
        logout_uris: list | None = None,
        allowed_scopes: list | None = None,
        **kwargs,
    ) -> tuple[System, SystemClient, str]:
        if not parent_system.is_active:
            raise SystemAdminServiceError('Parent system must be active.')

        system_config = self._default_system_config_from(parent_system)
        system_config.update({key: value for key, value in kwargs.items() if value is not None})
        system_config['parent_system'] = parent_system
        system_config['subdomain'] = subdomain

        reseller = self.create_system(
            realm=parent_system.realm,
            name=name,
            slug=slug,
            countries=countries or list(parent_system.available_countries.all()),
            performed_by=performed_by,
            **system_config,
        )

        self.sync_reseller_configuration(parent_system=parent_system, reseller=reseller)

        client, raw_secret = self.create_client(
            system=reseller,
            name=client_name,
            performed_by=performed_by,
            redirect_uris=redirect_uris
            if redirect_uris is not None
            else self.build_default_redirect_uris(reseller),
            logout_uris=logout_uris
            if logout_uris is not None
            else self.build_default_logout_uris(reseller),
            allowed_scopes=allowed_scopes or ['openid', 'profile', 'email'],
        )

        self._audit(
            AuditEventType.SYSTEM_RESELLER_CREATED,
            actor_system_user=performed_by,
            subject=reseller,
            payload={
                'action': 'reseller_created',
                'parent_system_id': str(parent_system.id),
                'client_id': str(client.id),
            },
        )
        return reseller, client, raw_secret

    @transaction.atomic
    def sync_reseller_configuration(
        self,
        *,
        parent_system: System,
        reseller: System,
    ) -> None:
        if reseller.parent_system_id != parent_system.id:
            raise SystemAdminServiceError('Reseller is not linked to this parent system.')

        self._sync_settings(parent_system=parent_system, reseller=reseller)
        self._sync_onboarding_catalog(parent_system=parent_system, reseller=reseller)

    @transaction.atomic
    def update_system(
        self,
        *,
        system: System,
        performed_by: SystemUser | None = None,
        name: str | None = None,
        description: str | None = None,
        logo_url: str | None = None,
        favicon_url: str | None = None,
        website: str | None = None,
        subdomain: str | None = None,
        primary_color: str | None = None,
        secondary_color: str | None = None,
        accent_colors: list | None = None,
        tagline: str | None = None,
        password_type: str | None = None,
        allow_password_login: bool | None = None,
        allow_passwordless_login: bool | None = None,
        allow_magic_link_login: bool | None = None,
        allow_social_login: bool | None = None,
        passwordless_only: bool | None = None,
        allowed_social_providers: list | None = None,
        registration_open: bool | None = None,
        auto_login_after_registration: bool | None = None,
        requires_approval: bool | None = None,
        allows_referrals: bool | None = None,
        referral_reward_amount=None,
        auto_verify_referrals: bool | None = None,
        mfa_required: bool | None = None,
        mfa_required_enforced: bool | None = None,
        allowed_mfa_methods: list | None = None,
    ) -> System:
        updated = []

        if name is not None:
            clean_name = name.strip()
            if not clean_name:
                raise SystemAdminServiceError('System name cannot be blank.')
            if clean_name != system.name:
                system.slug = self._unique_slug(clean_name, exclude_id=system.id)
                updated.append('slug')
            system.name = clean_name
            updated.append('name')

        if description is not None:
            system.description = description
            updated.append('description')
        if logo_url is not None:
            system.logo_url = logo_url
            updated.append('logo_url')
        if favicon_url is not None:
            system.favicon_url = favicon_url
            updated.append('favicon_url')
        if website is not None:
            system.website = website
            updated.append('website')
        if subdomain is not None:
            system.subdomain = self._clean_subdomain(subdomain)
            updated.append('subdomain')
        if primary_color is not None:
            system.primary_color = primary_color
            updated.append('primary_color')
        if secondary_color is not None:
            system.secondary_color = secondary_color
            updated.append('secondary_color')
        if accent_colors is not None:
            system.accent_colors = accent_colors
            updated.append('accent_colors')
        if tagline is not None:
            system.tagline = tagline
            updated.append('tagline')
        if password_type is not None:
            system.password_type = password_type
            updated.append('password_type')
        if allow_password_login is not None:
            system.allow_password_login = allow_password_login
            updated.append('allow_password_login')
        if allow_passwordless_login is not None:
            system.allow_passwordless_login = allow_passwordless_login
            updated.append('allow_passwordless_login')
        if allow_magic_link_login is not None:
            system.allow_magic_link_login = allow_magic_link_login
            updated.append('allow_magic_link_login')
        if allow_social_login is not None:
            system.allow_social_login = allow_social_login
            updated.append('allow_social_login')
        if passwordless_only is not None:
            system.passwordless_only = passwordless_only
            updated.append('passwordless_only')
        if allowed_social_providers is not None:
            system.allowed_social_providers = self._normalize_social_providers(
                allowed_social_providers
            )
            updated.append('allowed_social_providers')
        if registration_open is not None:
            system.registration_open = registration_open
            updated.append('registration_open')
        if auto_login_after_registration is not None:
            system.auto_login_after_registration = auto_login_after_registration
            updated.append('auto_login_after_registration')
        if requires_approval is not None:
            system.requires_approval = requires_approval
            updated.append('requires_approval')
        if allows_referrals is not None:
            system.allows_referrals = allows_referrals
            updated.append('allows_referrals')
        if referral_reward_amount is not None:
            system.referral_reward_amount = referral_reward_amount
            updated.append('referral_reward_amount')
        if auto_verify_referrals is not None:
            system.auto_verify_referrals = auto_verify_referrals
            updated.append('auto_verify_referrals')
        if mfa_required is not None:
            system.mfa_required = mfa_required
            updated.append('mfa_required')
        if mfa_required_enforced is not None:
            system.mfa_required_enforced = mfa_required_enforced
            updated.append('mfa_required_enforced')
        if allowed_mfa_methods is not None:
            system.allowed_mfa_methods = allowed_mfa_methods
            updated.append('allowed_mfa_methods')

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
                AuditEventType.SYSTEM_UPDATED,
                actor_system_user=performed_by,
                subject=system,
                payload={'action': 'updated', 'updated_fields': updated},
            )

        return system

    @transaction.atomic
    def deactivate_system(
        self,
        *,
        system: System,
        performed_by: SystemUser | None = None,
    ) -> System:
        if not system.is_active:
            raise SystemAdminServiceError('System is already inactive.')

        system.is_active = False
        system.save(update_fields=['is_active'])

        self._audit(
            AuditEventType.SYSTEM_DEACTIVATED,
            actor_system_user=performed_by,
            subject=system,
            payload={'action': 'deactivated'},
        )
        return system

    @transaction.atomic
    def reactivate_system(
        self,
        *,
        system: System,
        performed_by: SystemUser | None = None,
    ) -> System:
        if system.is_active:
            raise SystemAdminServiceError('System is already active.')

        system.is_active = True
        system.save(update_fields=['is_active'])

        self._audit(
            AuditEventType.SYSTEM_REACTIVATED,
            actor_system_user=performed_by,
            subject=system,
            payload={'action': 'reactivated'},
        )
        return system

    @transaction.atomic
    def add_country(
        self,
        *,
        system: System,
        country: Country,
        performed_by: SystemUser | None = None,
    ) -> Country:
        if system.available_countries.filter(id=country.id).exists():
            raise SystemAdminServiceError(f'{country.name} is already available on {system.name}.')

        system.available_countries.add(country)
        self._audit(
            AuditEventType.SYSTEM_COUNTRY_ADDED,
            actor_system_user=performed_by,
            subject=system,
            payload={'action': 'country_added', 'country_code': country.code},
        )
        return country

    @transaction.atomic
    def remove_country(
        self,
        *,
        system: System,
        country: Country,
        performed_by: SystemUser | None = None,
    ) -> Country:
        if not system.available_countries.filter(id=country.id).exists():
            raise SystemAdminServiceError(f'{country.name} is not configured on {system.name}.')

        system.available_countries.remove(country)
        self._audit(
            AuditEventType.SYSTEM_COUNTRY_REMOVED,
            actor_system_user=performed_by,
            subject=system,
            payload={'action': 'country_removed', 'country_code': country.code},
        )
        return country

    @transaction.atomic
    def create_client(
        self,
        *,
        system: System,
        name: str,
        performed_by: SystemUser | None = None,
        client_type: str = SystemClient.ClientType.CONFIDENTIAL,
        redirect_uris: list | None = None,
        logout_uris: list | None = None,
        allowed_scopes: list | None = None,
        access_token_ttl: int = 0,
        refresh_token_ttl: int = 0,
        id_token_ttl: int = 0,
        override_allow_passwordless_login=None,
        override_allow_magic_link_login=None,
        override_allow_social_login=None,
        override_allowed_social_providers=None,
        is_active: bool = True,
    ) -> tuple[SystemClient, str]:
        clean_name = (name or '').strip()
        if not clean_name:
            raise SystemAdminServiceError('Client name is required.')

        raw_secret = ''
        secret_hash = ''
        if client_type != SystemClient.ClientType.PUBLIC:
            raw_secret = self.generate_client_secret()
            secret_hash = self.hash_client_secret(raw_secret)

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
            override_allowed_social_providers=self._normalize_social_providers(
                override_allowed_social_providers
            ),
            client_secret_hash=secret_hash,
            is_active=is_active,
        )

        self._audit(
            AuditEventType.SYSTEM_CLIENT_CREATED,
            actor_system_user=performed_by,
            subject=client,
            payload={
                'action': 'client_created',
                'system_id': str(system.id),
                'client_name': client.name,
                'client_type': client.client_type,
            },
        )
        return client, raw_secret

    @transaction.atomic
    def regenerate_client_secret(
        self,
        *,
        client: SystemClient,
        performed_by: SystemUser | None = None,
    ) -> tuple[SystemClient, str]:
        if client.client_type == SystemClient.ClientType.PUBLIC:
            raise SystemAdminServiceError('Public clients do not use client secrets.')

        raw_secret = self.generate_client_secret()
        client.client_secret_hash = self.hash_client_secret(raw_secret)
        client.save(update_fields=['client_secret_hash', 'updated_at'])

        self._audit(
            AuditEventType.SYSTEM_CLIENT_SECRET_REGENERATED,
            actor_system_user=performed_by,
            subject=client,
            payload={'action': 'client_secret_regenerated'},
        )
        return client, raw_secret

    @transaction.atomic
    def update_client(
        self,
        *,
        client: SystemClient,
        performed_by: SystemUser | None = None,
        name: str | None = None,
        client_type: str | None = None,
        redirect_uris: list | None = None,
        logout_uris: list | None = None,
        allowed_scopes: list | None = None,
        access_token_ttl: int | None = None,
        refresh_token_ttl: int | None = None,
        id_token_ttl: int | None = None,
        override_allow_passwordless_login=None,
        override_allow_magic_link_login=None,
        override_allow_social_login=None,
        override_allowed_social_providers=None,
    ) -> SystemClient:
        updated = []

        if name is not None:
            clean_name = name.strip()
            if not clean_name:
                raise SystemAdminServiceError('Client name cannot be blank.')
            client.name = clean_name
            updated.append('name')
        if client_type is not None:
            client.client_type = client_type
            updated.append('client_type')
        if redirect_uris is not None:
            client.redirect_uris = redirect_uris
            updated.append('redirect_uris')
        if logout_uris is not None:
            client.logout_uris = logout_uris
            updated.append('logout_uris')
        if allowed_scopes is not None:
            client.allowed_scopes = allowed_scopes
            updated.append('allowed_scopes')
        if access_token_ttl is not None:
            client.access_token_ttl = access_token_ttl
            updated.append('access_token_ttl')
        if refresh_token_ttl is not None:
            client.refresh_token_ttl = refresh_token_ttl
            updated.append('refresh_token_ttl')
        if id_token_ttl is not None:
            client.id_token_ttl = id_token_ttl
            updated.append('id_token_ttl')
        if override_allow_passwordless_login is not None:
            client.override_allow_passwordless_login = override_allow_passwordless_login
            updated.append('override_allow_passwordless_login')
        if override_allow_magic_link_login is not None:
            client.override_allow_magic_link_login = override_allow_magic_link_login
            updated.append('override_allow_magic_link_login')
        if override_allow_social_login is not None:
            client.override_allow_social_login = override_allow_social_login
            updated.append('override_allow_social_login')
        if override_allowed_social_providers is not None:
            client.override_allowed_social_providers = self._normalize_social_providers(
                override_allowed_social_providers
            )
            updated.append('override_allowed_social_providers')

        if updated:
            client.save(update_fields=updated)
            self._audit(
                AuditEventType.SYSTEM_CLIENT_UPDATED,
                actor_system_user=performed_by,
                subject=client,
                payload={'action': 'client_updated', 'updated_fields': updated},
            )

        return client

    @transaction.atomic
    def deactivate_client(
        self,
        *,
        client: SystemClient,
        performed_by: SystemUser | None = None,
    ) -> SystemClient:
        if not client.is_active:
            raise SystemAdminServiceError('Client is already inactive.')

        client.is_active = False
        client.save(update_fields=['is_active'])
        self._audit(
            AuditEventType.SYSTEM_CLIENT_DEACTIVATED,
            actor_system_user=performed_by,
            subject=client,
            payload={'action': 'client_deactivated'},
        )
        return client

    @transaction.atomic
    def reactivate_client(
        self,
        *,
        client: SystemClient,
        performed_by: SystemUser | None = None,
    ) -> SystemClient:
        if client.is_active:
            raise SystemAdminServiceError('Client is already active.')

        client.is_active = True
        client.save(update_fields=['is_active'])
        self._audit(
            AuditEventType.SYSTEM_CLIENT_REACTIVATED,
            actor_system_user=performed_by,
            subject=client,
            payload={'action': 'client_reactivated'},
        )
        return client

    @transaction.atomic
    def set_system_setting(
        self,
        *,
        system: System,
        key: str,
        value: str,
        performed_by: SystemUser | None = None,
        value_type: str = SystemSettings.ValueType.STRING,
        description: str = '',
        is_secret: bool = False,
    ) -> SystemSettings:
        clean_key = (key or '').strip()
        if not clean_key:
            raise SystemAdminServiceError('Setting key is required.')

        setting, _ = SystemSettings.objects.update_or_create(
            system=system,
            key=clean_key,
            defaults={
                'value': value,
                'value_type': value_type,
                'description': description,
                'is_secret': is_secret,
            },
        )
        self._audit(
            AuditEventType.SYSTEM_SETTING_SET,
            actor_system_user=performed_by,
            subject=setting,
            payload={'system': system.name, 'key': clean_key},
        )
        return setting

    @classmethod
    def build_default_redirect_uris(cls, system: System) -> list[str]:
        return [
            cls._build_subdomain_url(system, path)
            for path in getattr(
                settings,
                'IDENTITY_DEFAULT_REDIRECT_PATHS',
                ['/auth/callback'],
            )
        ]

    @classmethod
    def build_default_logout_uris(cls, system: System) -> list[str]:
        return [
            cls._build_subdomain_url(system, path)
            for path in getattr(
                settings,
                'IDENTITY_DEFAULT_LOGOUT_PATHS',
                ['/auth/logout'],
            )
        ]

    @staticmethod
    def _build_subdomain_url(system: System, path: str) -> str:
        if not system.subdomain:
            raise SystemAdminServiceError('System subdomain is required to build OAuth URIs.')
        return urljoin(f'{system.subdomain.rstrip("/")}/', path.lstrip('/'))

    @staticmethod
    def _sync_settings(*, parent_system: System, reseller: System) -> None:
        settings_to_create = []
        existing_keys = set(reseller.settings.values_list('key', flat=True))
        for parent_setting in parent_system.settings.all():
            if parent_setting.key in existing_keys:
                continue
            settings_to_create.append(
                SystemSettings(
                    system=reseller,
                    key=parent_setting.key,
                    value=parent_setting.value,
                    value_type=parent_setting.value_type,
                    description=parent_setting.description,
                    is_secret=parent_setting.is_secret,
                )
            )
        if settings_to_create:
            SystemSettings.objects.bulk_create(settings_to_create)

    @staticmethod
    def _sync_onboarding_catalog(*, parent_system: System, reseller: System) -> None:
        from organizations.models import OnboardingServiceProduct, OnboardingVerificationCheck

        existing_service_codes = set(
            reseller.onboarding_service_products.values_list('code', flat=True)
        )
        services_to_create = []
        for service in parent_system.onboarding_service_products.all():
            if service.code in existing_service_codes:
                continue
            services_to_create.append(
                OnboardingServiceProduct(
                    system=reseller,
                    code=service.code,
                    name=service.name,
                    description=service.description,
                    amount=service.amount,
                    tax_amount=service.tax_amount,
                    currency=service.currency,
                    is_active=service.is_active,
                    sort_order=service.sort_order,
                    metadata=service.metadata,
                )
            )
        if services_to_create:
            OnboardingServiceProduct.objects.bulk_create(services_to_create)

        existing_check_codes = set(
            reseller.onboarding_verification_checks.values_list('code', flat=True)
        )
        checks_to_create = []
        for check in parent_system.onboarding_verification_checks.all():
            if check.code in existing_check_codes:
                continue
            checks_to_create.append(
                OnboardingVerificationCheck(
                    system=reseller,
                    code=check.code,
                    name=check.name,
                    description=check.description,
                    integration_code=check.integration_code,
                    trigger_mode=check.trigger_mode,
                    is_active=check.is_active,
                    required_for_onboarding=check.required_for_onboarding,
                    sort_order=check.sort_order,
                    metadata=check.metadata,
                )
            )
        if checks_to_create:
            OnboardingVerificationCheck.objects.bulk_create(checks_to_create)

    @staticmethod
    def _unique_slug(raw_value: str, exclude_id=None) -> str:
        base_slug = slugify(raw_value) or 'system'
        candidate = base_slug
        suffix = 2

        while True:
            qs = System.objects.filter(slug=candidate)
            if exclude_id:
                qs = qs.exclude(id=exclude_id)
            if not qs.exists():
                return candidate
            candidate = f'{base_slug}-{suffix}'
            suffix += 1

    @staticmethod
    def _audit(event_type, actor_system_user=None, subject=None, payload=None):
        is_system = isinstance(subject, System)
        subject_system = getattr(subject, 'system', None)
        AuditLog.objects.create(
            event_type=event_type,
            actor_user_id=actor_system_user.user_id
            if actor_system_user and actor_system_user.user_id
            else None,
            actor_system_user_id=actor_system_user.id if actor_system_user else None,
            subject_type=subject.__class__.__name__ if subject else '',
            subject_id=str(subject.id) if subject else '',
            subject_label=str(subject) if subject else '',
            system_id=str(subject.id)
            if is_system and subject
            else getattr(subject, 'system_id', None),
            system_name=subject.name
            if is_system and subject
            else subject_system.name
            if subject_system
            else '',
            payload=payload or {},
        )
