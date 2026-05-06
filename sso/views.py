import logging
from typing import Optional

from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST, require_GET

from sso.services.sso_service import (
    SSOService,
    AuthenticationError,
    OAuthError,
    MFARequiredError,
    IdentifierVerificationRequiredError,
    SystemReauthRequiredError,
)
from sso.models import SSOSession
from systems.models import System, SystemClient
from utils.decorators import require_active_session
from utils.extended_request import ExtendedRequest
from utils.response_provider import ResponseProvider

logger = logging.getLogger(__name__)

sso_service = SSOService()


def _get_client(data: dict, key: str = "client_id") -> Optional[SystemClient]:
    client_id = data.get(key, "")
    if not client_id:
        return None
    try:
        return (
            SystemClient.objects
            .select_related("system")
            .get(client_id=client_id, is_active=True)
        )
    except SystemClient.DoesNotExist:
        return None


def _get_system(system_id: str) -> Optional[System]:
    try:
        return System.objects.get(id=system_id, is_active=True)
    except System.DoesNotExist:
        return None


def _mfa_required_payload(exc: MFARequiredError) -> dict:
    return {
        "mfa_required": True,
        "reason": exc.requirement.reason,
        "allowed_methods": exc.requirement.allowed_methods,
        "pending_context_id": exc.pending_context_id or None,
    }


def _post_login_response(session: SSOSession, client: SystemClient) -> JsonResponse:
    try:
        contexts = [vars(ctx) for ctx in sso_service.get_ready_contexts(session, client)]
        return ResponseProvider.success(session_id=str(session.id), contexts=contexts)

    except IdentifierVerificationRequiredError as exc:
        return ResponseProvider.success(
            session_id=str(session.id),
            identifier_verification_required=True,
            required_identifiers=exc.requirements,
        )
    except MFARequiredError as exc:
        return ResponseProvider.success(
            session_id=str(session.id),
            **_mfa_required_payload(exc),
        )

@require_POST
def password_login_view(request: ExtendedRequest) -> JsonResponse:
    try:
        data = request.data
        client = _get_client(data)
        if not client:
            return ResponseProvider.bad_request(
                error="invalid_client", message="Invalid or inactive client."
            )

        session = sso_service.authenticate_password(
            login_value=data["login_value"],
            password=data["password"],
            client=client,
            ip_address=request.client_ip,
            user_agent=request.user_agent,
            device_id=data.get("device_id", ""),
            device_name=data.get("device_name", ""),
            reauth_session_id=data.get("reauth_session_id", ""),
        )
        return _post_login_response(session, client)

    except AuthenticationError as exc:
        return ResponseProvider.unauthorized(error="authentication_error", message=str(exc))
    except Exception as exc:
        logger.exception("password_login_view: %s", exc)
        return ResponseProvider.server_error()


@require_POST
def pin_login_view(request: ExtendedRequest) -> JsonResponse:
    try:
        data = request.data
        client = _get_client(data)
        if not client:
            return ResponseProvider.bad_request(
                error="invalid_client", message="Invalid or inactive client."
            )

        session = sso_service.authenticate_pin(
            login_value=data["login_value"],
            pin=data["pin"],
            client=client,
            ip_address=request.client_ip,
            user_agent=request.user_agent,
            device_id=data.get("device_id", ""),
            device_name=data.get("device_name", ""),
            reauth_session_id=data.get("reauth_session_id", ""),
        )
        return _post_login_response(session, client)

    except AuthenticationError as exc:
        return ResponseProvider.unauthorized(error="authentication_error", message=str(exc))
    except Exception as exc:
        logger.exception("pin_login_view: %s", exc)
        return ResponseProvider.server_error()


@require_POST
def social_login_view(request: ExtendedRequest) -> JsonResponse:
    try:
        data = request.data
        client = _get_client(data)
        if not client:
            return ResponseProvider.bad_request(
                error="invalid_client", message="Invalid or inactive client."
            )

        session = sso_service.authenticate_social(
            client=client,
            provider=data["provider"],
            uid=data.get("uid") or data.get("provider_user_id", ""),
            ip_address=request.client_ip,
            user_agent=request.user_agent,
            device_id=data.get("device_id", ""),
            device_name=data.get("device_name", ""),
            reauth_session_id=data.get("reauth_session_id", ""),
        )
        return _post_login_response(session, client)

    except AuthenticationError as exc:
        return ResponseProvider.unauthorized(error="authentication_error", message=str(exc))
    except Exception as exc:
        logger.exception("social_login_view: %s", exc)
        return ResponseProvider.server_error()


@require_POST
def passwordless_initiate_view(request: ExtendedRequest) -> JsonResponse:
    try:
        data = request.data
        client = _get_client(data)
        if not client:
            return ResponseProvider.bad_request(
                error="invalid_client", message="Invalid or inactive client."
            )

        result = sso_service.initiate_passwordless(
            login_value=data["login_value"],
            client=client,
            ip_address=request.client_ip,
        )
        return ResponseProvider.success(**result)

    except AuthenticationError as exc:
        return ResponseProvider.unauthorized(error="authentication_error", message=str(exc))
    except Exception as exc:
        logger.exception("passwordless_initiate_view: %s", exc)
        return ResponseProvider.server_error()


@require_POST
def passwordless_verify_view(request: ExtendedRequest) -> JsonResponse:
    try:
        data = request.data
        client = _get_client(data)
        if not client:
            return ResponseProvider.bad_request(
                error="invalid_client", message="Invalid or inactive client."
            )

        session = sso_service.verify_passwordless(
            client=client,
            challenge_id=data["challenge_id"],
            code=data["code"],
            ip_address=request.client_ip,
            user_agent=request.user_agent,
            device_id=data.get("device_id", ""),
            device_name=data.get("device_name", ""),
            reauth_session_id=data.get("reauth_session_id", ""),
        )
        return _post_login_response(session, client)

    except AuthenticationError as exc:
        return ResponseProvider.unauthorized(error="authentication_error", message=str(exc))
    except Exception as exc:
        logger.exception("passwordless_verify_view: %s", exc)
        return ResponseProvider.server_error()


@require_POST
def magic_link_initiate_view(request: ExtendedRequest) -> JsonResponse:
    try:
        data = request.data
        client = _get_client(data)
        if not client:
            return ResponseProvider.bad_request(
                error="invalid_client", message="Invalid or inactive client."
            )

        result = sso_service.initiate_magic_link(
            email=data["email"],
            client=client,
            scopes=data.get("scopes", []),
            ip_address=request.client_ip,
        )
        return ResponseProvider.success(**result)

    except AuthenticationError as exc:
        return ResponseProvider.unauthorized(error="authentication_error", message=str(exc))
    except Exception as exc:
        logger.exception("magic_link_initiate_view: %s", exc)
        return ResponseProvider.server_error()


@require_POST
def magic_link_verify_view(request: ExtendedRequest) -> JsonResponse:
    try:
        data = request.data
        client = _get_client(data)
        if not client:
            return ResponseProvider.bad_request(
                error="invalid_client", message="Invalid or inactive client."
            )

        session = sso_service.verify_magic_link(
            client=client,
            raw_token=data["token"],
            ip_address=request.client_ip,
            user_agent=request.user_agent,
            reauth_session_id=data.get("reauth_session_id", ""),
        )
        return _post_login_response(session, client)

    except AuthenticationError as exc:
        return ResponseProvider.unauthorized(error="authentication_error", message=str(exc))
    except Exception as exc:
        logger.exception("magic_link_verify_view: %s", exc)
        return ResponseProvider.server_error()


@require_active_session
@require_POST
def system_mfa_initiate_view(request: ExtendedRequest) -> JsonResponse:
    try:
        data = request.data
        client = _get_client(data)
        if not client:
            return ResponseProvider.bad_request(
                error="invalid_client", message="Invalid or inactive client."
            )

        result = sso_service.initiate_mfa_otp(
            session=request.sso_session,
            method=data["method"],
            client=client,
            ip_address=request.client_ip,
        )
        return ResponseProvider.success(**result)

    except AuthenticationError as exc:
        return ResponseProvider.bad_request(error="mfa_error", message=str(exc))
    except Exception as exc:
        logger.exception("system_mfa_initiate_view: %s", exc)
        return ResponseProvider.server_error()


@require_active_session
@require_POST
def system_mfa_verify_view(request: ExtendedRequest) -> JsonResponse:
    try:
        data = request.data
        client = _get_client(data)
        session = request.sso_session
        if not client:
            return ResponseProvider.bad_request(
                error="invalid_client", message="Invalid or inactive client."
            )

        sso_service.verify_system_mfa_otp(
            session=session,
            client=client,
            challenge_id=data["challenge_id"],
            code=data["code"],
            ip_address=request.client_ip,
        )
        return _post_login_response(session, client)

    except AuthenticationError as exc:
        return ResponseProvider.bad_request(error="mfa_error", message=str(exc))
    except Exception as exc:
        logger.exception("system_mfa_verify_view: %s", exc)
        return ResponseProvider.server_error()


@require_active_session
@require_GET
def list_contexts_view(request: ExtendedRequest) -> JsonResponse:
    try:
        client = _get_client(request.GET)
        if not client:
            return ResponseProvider.bad_request(
                error="invalid_client", message="Invalid or inactive client."
            )

        contexts = [
            vars(ctx)
            for ctx in sso_service.get_ready_contexts(request.sso_session, client)
        ]
        return ResponseProvider.success(contexts=contexts)

    except IdentifierVerificationRequiredError as exc:
        return ResponseProvider.success(
            identifier_verification_required=True,
            required_identifiers=exc.requirements,
        )
    except MFARequiredError as exc:
        return ResponseProvider.success(**_mfa_required_payload(exc))
    except Exception as exc:
        logger.exception("list_contexts_view: %s", exc)
        return ResponseProvider.server_error()


@require_active_session
@require_POST
def context_select_view(request: ExtendedRequest) -> JsonResponse:
    try:
        data   = request.data
        client = _get_client(data)
        if not client:
            return ResponseProvider.bad_request(
                error="invalid_client", message="Invalid or inactive client."
            )

        code = sso_service.select_context(
            session=request.sso_session,
            system_user_id=data["system_user_id"],
            client=client,
            redirect_uri=data["redirect_uri"],
            scopes=data.get("scopes", []),
            state=data.get("state", ""),
            nonce=data.get("nonce", ""),
            code_challenge=data.get("code_challenge", ""),
            code_challenge_method=data.get("code_challenge_method", "S256"),
        )
        return ResponseProvider.success(authorization_code=code)

    except IdentifierVerificationRequiredError as exc:
        return ResponseProvider.success(
            identifier_verification_required=True,
            required_identifiers=exc.requirements,
        )
    except MFARequiredError as exc:
        return ResponseProvider.success(**_mfa_required_payload(exc))
    except OAuthError as exc:
        return ResponseProvider.bad_request(error=exc.error, message=exc.description)
    except Exception as exc:
        logger.exception("context_select_view: %s", exc)
        return ResponseProvider.server_error()


@require_active_session
@require_POST
def context_mfa_initiate_view(request: ExtendedRequest) -> JsonResponse:
    try:
        data = request.data
        client = _get_client(data)
        if not client:
            return ResponseProvider.bad_request(
                error="invalid_client", message="Invalid or inactive client."
            )

        result = sso_service.initiate_mfa_otp(
            session=request.sso_session,
            method=data["method"],
            client=client,
            ip_address=request.client_ip,
        )
        return ResponseProvider.success(**result)

    except AuthenticationError as exc:
        return ResponseProvider.bad_request(error="mfa_error", message=str(exc))
    except Exception as exc:
        logger.exception("context_mfa_initiate_view: %s", exc)
        return ResponseProvider.server_error()


@require_active_session
@require_POST
def context_mfa_verify_view(request: ExtendedRequest) -> JsonResponse:
    try:
        data = request.data
        client = _get_client(data)
        session = request.sso_session
        if not client:
            return ResponseProvider.bad_request(
                error="invalid_client", message="Invalid or inactive client."
            )

        code = sso_service.verify_context_mfa_otp(
            session=session,
            client=client,
            challenge_id=data["challenge_id"],
            code=data["code"],
            pending_context_id=data["pending_context_id"],
            ip_address=request.client_ip,
        )
        return ResponseProvider.success(authorization_code=code)

    except AuthenticationError as exc:
        return ResponseProvider.bad_request(error="mfa_error", message=str(exc))
    except Exception as exc:
        logger.exception("context_mfa_verify_view: %s", exc)
        return ResponseProvider.server_error()


@csrf_exempt
@require_POST
def token_exchange_view(request: ExtendedRequest) -> JsonResponse:
    try:
        data = request.data
        client = _get_client(data)
        if not client:
            return ResponseProvider.bad_request(error="invalid_client", message="Invalid client.")

        tokens = sso_service.exchange_code(
            raw_code=data["code"],
            client=client,
            redirect_uri=data["redirect_uri"],
            code_verifier=data.get("code_verifier", ""),
            client_secret=data.get("client_secret", ""),
        )
        return ResponseProvider.success(
            access_token=tokens.access_token,
            refresh_token=tokens.refresh_token,
            id_token=tokens.id_token,
            token_type=tokens.token_type,
            expires_in=tokens.expires_in,
            scope=tokens.scope,
        )

    except OAuthError as exc:
        return ResponseProvider.unauthorized(error=exc.error, message=exc.description)
    except Exception as exc:
        logger.exception("token_exchange_view: %s", exc)
        return ResponseProvider.server_error()


@csrf_exempt
@require_POST
def token_refresh_view(request: ExtendedRequest) -> JsonResponse:
    try:
        data = request.data
        client = _get_client(data)
        if not client:
            return ResponseProvider.bad_request(error="invalid_client", message="Invalid client.")

        tokens = sso_service.refresh_tokens(
            raw_refresh_token=data["refresh_token"],
            client=client,
        )
        return ResponseProvider.success(
            access_token=tokens.access_token,
            refresh_token=tokens.refresh_token,
            id_token=tokens.id_token,
            token_type=tokens.token_type,
            expires_in=tokens.expires_in,
            scope=tokens.scope,
        )

    except SystemReauthRequiredError as exc:
        return ResponseProvider.unauthorized(
            error="reauth_required",
            message=str(exc),
            session_id=str(exc.session.id),
            system_id=str(exc.system.id),
            system_name=exc.system.name,
        )
    except OAuthError as exc:
        return ResponseProvider.unauthorized(error=exc.error, message=exc.description)
    except Exception as exc:
        logger.exception("token_refresh_view: %s", exc)
        return ResponseProvider.server_error()


@csrf_exempt
@require_POST
def token_revoke_view(request: ExtendedRequest) -> JsonResponse:
    try:
        data = request.data
        client = _get_client(data)
        if client:
            sso_service.revoke_token(
                raw_token=data.get("token", ""),
                client=client,
                ip_address=request.client_ip,
            )
    except Exception as exc:
        logger.exception("token_revoke_view: %s", exc)
    return ResponseProvider.success()


@csrf_exempt
@require_POST
def token_introspect_view(request: ExtendedRequest) -> JsonResponse:
    try:
        result = sso_service.introspect(request.data.get("token", ""))
        return ResponseProvider.success(**result)
    except Exception as exc:
        logger.exception("token_introspect_view: %s", exc)
        return ResponseProvider.success(active=False)


@require_active_session
@require_POST
def logout_view(request: ExtendedRequest) -> JsonResponse:
    try:
        sso_service.logout(
            session=request.sso_session,
            ip_address=request.client_ip,
        )
        return ResponseProvider.success()
    except Exception as exc:
        logger.exception("logout_view: %s", exc)
        return ResponseProvider.server_error()


@require_active_session
@require_POST
def logout_system_view(request: ExtendedRequest) -> JsonResponse:
    try:
        data = request.data
        system = _get_system(data.get("system_id", ""))
        if not system:
            return ResponseProvider.bad_request(
                error="invalid_system", message="System not found."
            )

        sso_service.logout_system(
            session=request.sso_session,
            system=system,
            ip_address=request.client_ip,
        )
        return ResponseProvider.success()
    except Exception as exc:
        logger.exception("logout_system_view: %s", exc)
        return ResponseProvider.server_error()


@require_active_session
@require_POST
def logout_all_view(request: ExtendedRequest) -> JsonResponse:
    try:
        count = sso_service.logout_all(
            user=request.sso_session.user,
            ip_address=request.client_ip,
        )
        return ResponseProvider.success(sessions_revoked=count)
    except Exception as exc:
        logger.exception("logout_all_view: %s", exc)
        return ResponseProvider.server_error()