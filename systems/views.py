import logging
from typing import Optional

from django.http import JsonResponse
from django.views.decorators.http import require_GET, require_POST, require_http_methods

from base.models import Country, Realm
from systems.models import System, SystemClient, SystemSettings
from systems.services.system_admin_service import (
    SystemAdminService,
    SystemAdminServiceError,
)
from utils.social_providers import SocialProvider
from utils.decorators import user_login_required
from utils.extended_request import ExtendedRequest
from utils.response_provider import ResponseProvider

logger = logging.getLogger(__name__)
system_service = SystemAdminService()


def _get_system(system_id: str) -> Optional[System]:
    try:
        return System.objects.prefetch_related("available_countries").get(id=system_id)
    except System.DoesNotExist:
        return None


def _get_country(data: dict) -> Optional[Country]:
    cid = data.get("country_id") or data.get("country")
    if not cid:
        return None
    try:
        return Country.objects.get(id=cid)
    except Country.DoesNotExist:
        return None


def _get_realm(data: dict) -> Optional[Realm]:
    realm_id = data.get("realm_id") or data.get("realm")
    if not realm_id:
        return None
    try:
        return Realm.objects.get(id=realm_id)
    except Realm.DoesNotExist:
        return None


def _get_client(client_id: str) -> Optional[SystemClient]:
    try:
        return SystemClient.objects.select_related("system").get(id=client_id)
    except SystemClient.DoesNotExist:
        return None


def _get_setting(setting_id: str) -> Optional[SystemSettings]:
    try:
        return SystemSettings.objects.select_related("system").get(id=setting_id)
    except SystemSettings.DoesNotExist:
        return None


def _system_payload(system: System) -> dict:
    return {
        "id": str(system.id),
        "realm_id": str(system.realm_id),
        "name": system.name,
        "slug": system.slug,
        "description": system.description,
        "logo_url": system.logo_url,
        "website": system.website,
        "password_type": system.password_type,
        "allow_password_login": system.allow_password_login,
        "allow_passwordless_login": system.allow_passwordless_login,
        "allow_magic_link_login": system.allow_magic_link_login,
        "allow_social_login": system.allow_social_login,
        "passwordless_only": system.passwordless_only,
        "allowed_social_providers": system.allowed_social_providers,
        "supported_social_providers": list(SocialProvider.values),
        "registration_open": system.registration_open,
        "auto_login_after_registration": system.auto_login_after_registration,
        "requires_approval": system.requires_approval,
        "allows_referrals": system.allows_referrals,
        "referral_reward_amount": str(system.referral_reward_amount),
        "auto_verify_referrals": system.auto_verify_referrals,
        "mfa_required": system.mfa_required,
        "mfa_required_enforced": system.mfa_required_enforced,
        "allowed_mfa_methods": system.allowed_mfa_methods,
        "is_active": system.is_active,
        "available_countries": [
            {
                "id": str(country.id),
                "code": country.code,
                "name": country.name,
            }
            for country in system.available_countries.all().order_by("name")
        ],
        "created_at": system.created_at.isoformat(),
        "updated_at": system.updated_at.isoformat(),
    }


def _client_payload(client: SystemClient) -> dict:
    return {
        "id": str(client.id),
        "system_id": str(client.system_id),
        "name": client.name,
        "client_id": client.client_id,
        "client_type": client.client_type,
        "redirect_uris": client.redirect_uris,
        "logout_uris": client.logout_uris,
        "allowed_scopes": client.allowed_scopes,
        "access_token_ttl": client.access_token_ttl,
        "refresh_token_ttl": client.refresh_token_ttl,
        "id_token_ttl": client.id_token_ttl,
        "override_allow_passwordless_login": client.override_allow_passwordless_login,
        "override_allow_magic_link_login": client.override_allow_magic_link_login,
        "override_allow_social_login": client.override_allow_social_login,
        "override_allowed_social_providers": client.override_allowed_social_providers,
        "supported_social_providers": list(SocialProvider.values),
        "effective_config": client.get_effective_config(),
        "is_active": client.is_active,
        "created_at": client.created_at.isoformat(),
        "updated_at": client.updated_at.isoformat(),
    }


def _setting_payload(setting: SystemSettings) -> dict:
    return {
        "id": str(setting.id),
        "system_id": str(setting.system_id),
        "key": setting.key,
        "value": "" if setting.is_secret else setting.typed_value(),
        "value_type": setting.value_type,
        "description": setting.description,
        "is_secret": setting.is_secret,
        "created_at": setting.created_at.isoformat(),
        "updated_at": setting.updated_at.isoformat(),
    }


@user_login_required(required_permission="system.view")
@require_GET
def system_list_view(request: ExtendedRequest) -> JsonResponse:
    try:
        qs = System.objects.prefetch_related("available_countries").select_related("realm").order_by("name")

        if realm_id := request.GET.get("realm_id"):
            qs = qs.filter(realm_id=realm_id)
        if is_active := request.GET.get("is_active"):
            qs = qs.filter(is_active=is_active.lower() == "true")

        return ResponseProvider.success(
            systems=[_system_payload(system) for system in qs]
        )
    except Exception as e:
        logger.exception("system_list_view: %s", e)
        return ResponseProvider.server_error()


@user_login_required(required_permission="system.view")
@require_GET
def system_detail_view(request: ExtendedRequest, system_id: str) -> JsonResponse:
    try:
        system = _get_system(system_id)
        if not system:
            return ResponseProvider.not_found(
                error="not_found",
                message="System not found.",
            )

        return ResponseProvider.success(**_system_payload(system))
    except Exception as e:
        logger.exception("system_detail_view: %s", e)
        return ResponseProvider.server_error()


@user_login_required(required_permission="system.create")
@require_POST
def system_create_view(request: ExtendedRequest) -> JsonResponse:
    try:
        data = request.data
        realm = _get_realm(data)
        if not realm:
            return ResponseProvider.bad_request(
                error="invalid_realm",
                message="realm_id is required.",
            )

        country_ids = data.get("country_ids") or data.get("countries") or []
        countries = list(Country.objects.filter(id__in=country_ids)) if country_ids else []
        if country_ids and len(countries) != len(country_ids):
            return ResponseProvider.bad_request(
                error="invalid_country",
                message="One or more country_ids are invalid.",
            )

        system = system_service.create_system(
            realm=realm,
            name=data.get("name", ""),
            slug=data.get("slug"),
            countries=countries,
            performed_by=request.system_user,
            description=data.get("description", ""),
            logo_url=data.get("logo_url", ""),
            website=data.get("website", ""),
            password_type=data.get("password_type", System.PasswordType.PASSWORD),
            allow_password_login=data.get("allow_password_login", True),
            allow_passwordless_login=data.get("allow_passwordless_login", False),
            allow_magic_link_login=data.get("allow_magic_link_login", False),
            allow_social_login=data.get("allow_social_login", False),
            passwordless_only=data.get("passwordless_only", False),
            allowed_social_providers=data.get("allowed_social_providers", []),
            registration_open=data.get("registration_open", True),
            auto_login_after_registration=data.get("auto_login_after_registration", False),
            requires_approval=data.get("requires_approval", False),
            allows_referrals=data.get("allows_referrals", False),
            referral_reward_amount=data.get("referral_reward_amount", "0.00"),
            auto_verify_referrals=data.get("auto_verify_referrals", False),
            mfa_required=data.get("mfa_required", False),
            mfa_required_enforced=data.get("mfa_required_enforced", False),
            allowed_mfa_methods=data.get("allowed_mfa_methods", []),
            is_active=data.get("is_active", True),
        )

        return ResponseProvider.created(**_system_payload(system))
    except SystemAdminServiceError as e:
        return ResponseProvider.bad_request(
            error="system_management_error",
            message=str(e),
        )
    except Exception as e:
        logger.exception("system_create_view: %s", e)
        return ResponseProvider.server_error()


@user_login_required(required_permission="system.update")
@require_http_methods(["PATCH"])
def system_update_view(request: ExtendedRequest, system_id: str) -> JsonResponse:
    system = _get_system(system_id)
    if not system:
        return ResponseProvider.not_found(
            error="not_found",
            message="System not found.",
        )

    try:
        data = request.data
        system = system_service.update_system(
            system=system,
            performed_by=request.system_user,
            name=data.get("name"),
            description=data.get("description"),
            logo_url=data.get("logo_url"),
            website=data.get("website"),
            password_type=data.get("password_type"),
            allow_password_login=data.get("allow_password_login"),
            allow_passwordless_login=data.get("allow_passwordless_login"),
            allow_magic_link_login=data.get("allow_magic_link_login"),
            allow_social_login=data.get("allow_social_login"),
            passwordless_only=data.get("passwordless_only"),
            allowed_social_providers=data.get("allowed_social_providers"),
            registration_open=data.get("registration_open"),
            auto_login_after_registration=data.get("auto_login_after_registration"),
            requires_approval=data.get("requires_approval"),
            allows_referrals=data.get("allows_referrals"),
            referral_reward_amount=data.get("referral_reward_amount"),
            auto_verify_referrals=data.get("auto_verify_referrals"),
            mfa_required=data.get("mfa_required"),
            mfa_required_enforced=data.get("mfa_required_enforced"),
            allowed_mfa_methods=data.get("allowed_mfa_methods"),
        )
        return ResponseProvider.success(**_system_payload(system))
    except SystemAdminServiceError as e:
        return ResponseProvider.bad_request(
            error="system_management_error",
            message=str(e),
        )
    except Exception as e:
        logger.exception("system_update_view: %s", e)
        return ResponseProvider.server_error()


@user_login_required(required_permission="system.deactivate")
@require_POST
def system_deactivate_view(request: ExtendedRequest, system_id: str) -> JsonResponse:
    system = _get_system(system_id)
    if not system:
        return ResponseProvider.not_found(
            error="not_found",
            message="System not found.",
        )

    try:
        system = system_service.deactivate_system(
            system=system,
            performed_by=request.system_user,
        )
        return ResponseProvider.success(**_system_payload(system))
    except SystemAdminServiceError as e:
        return ResponseProvider.bad_request(
            error="system_management_error",
            message=str(e),
        )
    except Exception as e:
        logger.exception("system_deactivate_view: %s", e)
        return ResponseProvider.server_error()


@user_login_required(required_permission="system.deactivate")
@require_POST
def system_reactivate_view(request: ExtendedRequest, system_id: str) -> JsonResponse:
    system = _get_system(system_id)
    if not system:
        return ResponseProvider.not_found(
            error="not_found",
            message="System not found.",
        )

    try:
        system = system_service.reactivate_system(
            system=system,
            performed_by=request.system_user,
        )
        return ResponseProvider.success(**_system_payload(system))
    except SystemAdminServiceError as e:
        return ResponseProvider.bad_request(
            error="system_management_error",
            message=str(e),
        )
    except Exception as e:
        logger.exception("system_reactivate_view: %s", e)
        return ResponseProvider.server_error()


@user_login_required(required_permission="system.view")
@require_GET
def system_country_list_view(request: ExtendedRequest, system_id: str) -> JsonResponse:
    try:
        system = _get_system(system_id)
        if not system:
            return ResponseProvider.not_found(
                error="not_found",
                message="System not found.",
            )

        countries = system.available_countries.all().order_by("name")
        return ResponseProvider.success(
            countries=[
                {"id": str(country.id), "code": country.code, "name": country.name}
                for country in countries
            ]
        )
    except Exception as e:
        logger.exception("system_country_list_view: %s", e)
        return ResponseProvider.server_error()


@user_login_required(required_permission="system.manage_countries")
@require_POST
def system_country_add_view(request: ExtendedRequest, system_id: str) -> JsonResponse:
    system = _get_system(system_id)
    if not system:
        return ResponseProvider.not_found(
            error="not_found",
            message="System not found.",
        )

    try:
        country = _get_country(request.data)
        if not country:
            return ResponseProvider.bad_request(
                error="invalid_country",
                message="country_id is required.",
            )

        country = system_service.add_country(
            system=system,
            country=country,
            performed_by=request.system_user,
        )
        return ResponseProvider.success(
            id=str(country.id),
            code=country.code,
            name=country.name,
        )
    except SystemAdminServiceError as e:
        return ResponseProvider.bad_request(
            error="system_management_error",
            message=str(e),
        )
    except Exception as e:
        logger.exception("system_country_add_view: %s", e)
        return ResponseProvider.server_error()


@user_login_required(required_permission="system.manage_countries")
@require_POST
def system_country_remove_view(request: ExtendedRequest, system_id: str) -> JsonResponse:
    system = _get_system(system_id)
    if not system:
        return ResponseProvider.not_found(
            error="not_found",
            message="System not found.",
        )

    try:
        country = _get_country(request.data)
        if not country:
            return ResponseProvider.bad_request(
                error="invalid_country",
                message="country_id is required.",
            )

        country = system_service.remove_country(
            system=system,
            country=country,
            performed_by=request.system_user,
        )
        return ResponseProvider.success(
            id=str(country.id),
            code=country.code,
            name=country.name,
        )
    except SystemAdminServiceError as e:
        return ResponseProvider.bad_request(
            error="system_management_error",
            message=str(e),
        )
    except Exception as e:
        logger.exception("system_country_remove_view: %s", e)
        return ResponseProvider.server_error()


@user_login_required(required_permission="system.view_clients")
@require_GET
def client_list_view(request: ExtendedRequest, system_id: str) -> JsonResponse:
    try:
        system = _get_system(system_id)
        if not system:
            return ResponseProvider.not_found(
                error="not_found",
                message="System not found.",
            )

        qs = system.clients.all().order_by("name")
        if is_active := request.GET.get("is_active"):
            qs = qs.filter(is_active=is_active.lower() == "true")

        return ResponseProvider.success(
            clients=[_client_payload(client) for client in qs]
        )
    except Exception as e:
        logger.exception("client_list_view: %s", e)
        return ResponseProvider.server_error()


@user_login_required(required_permission="system.view_clients")
@require_GET
def client_detail_view(request: ExtendedRequest, client_id: str) -> JsonResponse:
    try:
        client = _get_client(client_id)
        if not client:
            return ResponseProvider.not_found(
                error="not_found",
                message="Client not found.",
            )

        return ResponseProvider.success(**_client_payload(client))
    except Exception as e:
        logger.exception("client_detail_view: %s", e)
        return ResponseProvider.server_error()


@user_login_required(required_permission="system.manage_clients")
@require_POST
def client_create_view(request: ExtendedRequest, system_id: str) -> JsonResponse:
    system = _get_system(system_id)
    if not system:
        return ResponseProvider.not_found(
            error="not_found",
            message="System not found.",
        )

    try:
        data = request.data
        client, raw_secret = system_service.create_client(
            system=system,
            name=data.get("name", ""),
            performed_by=request.system_user,
            client_type=data.get("client_type", SystemClient.ClientType.CONFIDENTIAL),
            redirect_uris=data.get("redirect_uris", []),
            logout_uris=data.get("logout_uris", []),
            allowed_scopes=data.get("allowed_scopes", []),
            access_token_ttl=data.get("access_token_ttl", 0),
            refresh_token_ttl=data.get("refresh_token_ttl", 0),
            id_token_ttl=data.get("id_token_ttl", 0),
            override_allow_passwordless_login=data.get("override_allow_passwordless_login"),
            override_allow_magic_link_login=data.get("override_allow_magic_link_login"),
            override_allow_social_login=data.get("override_allow_social_login"),
            override_allowed_social_providers=data.get("override_allowed_social_providers"),
            is_active=data.get("is_active", True),
        )

        payload = _client_payload(client)
        payload["client_secret"] = raw_secret or None
        return ResponseProvider.created(**payload)
    except SystemAdminServiceError as e:
        return ResponseProvider.bad_request(
            error="system_management_error",
            message=str(e),
        )
    except Exception as e:
        logger.exception("client_create_view: %s", e)
        return ResponseProvider.server_error()


@user_login_required(required_permission="system.manage_clients")
@require_http_methods(["PATCH"])
def client_update_view(request: ExtendedRequest, client_id: str) -> JsonResponse:
    client = _get_client(client_id)
    if not client:
        return ResponseProvider.not_found(
            error="not_found",
            message="Client not found.",
        )

    try:
        data = request.data
        client = system_service.update_client(
            client=client,
            performed_by=request.system_user,
            name=data.get("name"),
            client_type=data.get("client_type"),
            redirect_uris=data.get("redirect_uris"),
            logout_uris=data.get("logout_uris"),
            allowed_scopes=data.get("allowed_scopes"),
            access_token_ttl=data.get("access_token_ttl"),
            refresh_token_ttl=data.get("refresh_token_ttl"),
            id_token_ttl=data.get("id_token_ttl"),
            override_allow_passwordless_login=data.get("override_allow_passwordless_login"),
            override_allow_magic_link_login=data.get("override_allow_magic_link_login"),
            override_allow_social_login=data.get("override_allow_social_login"),
            override_allowed_social_providers=data.get("override_allowed_social_providers"),
        )
        return ResponseProvider.success(**_client_payload(client))
    except SystemAdminServiceError as e:
        return ResponseProvider.bad_request(
            error="system_management_error",
            message=str(e),
        )
    except Exception as e:
        logger.exception("client_update_view: %s", e)
        return ResponseProvider.server_error()


@user_login_required(required_permission="system.manage_clients")
@require_POST
def client_deactivate_view(request: ExtendedRequest, client_id: str) -> JsonResponse:
    client = _get_client(client_id)
    if not client:
        return ResponseProvider.not_found(
            error="not_found",
            message="Client not found.",
        )

    try:
        client = system_service.deactivate_client(
            client=client,
            performed_by=request.system_user,
        )
        return ResponseProvider.success(**_client_payload(client))
    except SystemAdminServiceError as e:
        return ResponseProvider.bad_request(
            error="system_management_error",
            message=str(e),
        )
    except Exception as e:
        logger.exception("client_deactivate_view: %s", e)
        return ResponseProvider.server_error()


@user_login_required(required_permission="system.manage_clients")
@require_POST
def client_reactivate_view(request: ExtendedRequest, client_id: str) -> JsonResponse:
    client = _get_client(client_id)
    if not client:
        return ResponseProvider.not_found(
            error="not_found",
            message="Client not found.",
        )

    try:
        client = system_service.reactivate_client(
            client=client,
            performed_by=request.system_user,
        )
        return ResponseProvider.success(**_client_payload(client))
    except SystemAdminServiceError as e:
        return ResponseProvider.bad_request(
            error="system_management_error",
            message=str(e),
        )
    except Exception as e:
        logger.exception("client_reactivate_view: %s", e)
        return ResponseProvider.server_error()


@user_login_required(required_permission="system.view_settings")
@require_GET
def setting_list_view(request: ExtendedRequest, system_id: str) -> JsonResponse:
    try:
        system = _get_system(system_id)
        if not system:
            return ResponseProvider.not_found(
                error="not_found",
                message="System not found.",
            )

        return ResponseProvider.success(
            settings=[
                _setting_payload(setting)
                for setting in system.settings.all().order_by("key")
            ]
        )
    except Exception as e:
        logger.exception("setting_list_view: %s", e)
        return ResponseProvider.server_error()


@user_login_required(required_permission="system.manage_settings")
@require_POST
def setting_set_view(request: ExtendedRequest, system_id: str) -> JsonResponse:
    system = _get_system(system_id)
    if not system:
        return ResponseProvider.not_found(
            error="not_found",
            message="System not found.",
        )

    try:
        data = request.data
        setting = system_service.set_system_setting(
            system=system,
            key=data.get("key", ""),
            value=data.get("value", ""),
            performed_by=request.system_user,
            value_type=data.get("value_type", SystemSettings.ValueType.STRING),
            description=data.get("description", ""),
            is_secret=data.get("is_secret", False),
        )
        return ResponseProvider.success(**_setting_payload(setting))
    except SystemAdminServiceError as e:
        return ResponseProvider.bad_request(
            error="system_management_error",
            message=str(e),
        )
    except Exception as e:
        logger.exception("setting_set_view: %s", e)
        return ResponseProvider.server_error()


@user_login_required(required_permission="system.view_settings")
@require_GET
def setting_detail_view(request: ExtendedRequest, setting_id: str) -> JsonResponse:
    try:
        setting = _get_setting(setting_id)
        if not setting:
            return ResponseProvider.not_found(
                error="not_found",
                message="Setting not found.",
            )

        return ResponseProvider.success(**_setting_payload(setting))
    except Exception as e:
        logger.exception("setting_detail_view: %s", e)
        return ResponseProvider.server_error()
