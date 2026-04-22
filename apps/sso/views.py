import logging
from typing import Optional

from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST, require_GET

from apps.sso.services.sso_service import (
    SSOService,
    AuthenticationError,
    OAuthError,
    MFARequiredError,
    MFAEnrollmentRequiredError,
)
from apps.sso.services.mfa_service import (
    MFAService,
    InvalidMFAOperationError,
    MFARateLimitExceededError
)
from apps.sso.models import SSOSession
from apps.systems.models import System, SystemClient
from utils.decorators import sso_session_required
from utils.extended_request import ExtendedRequest
from utils.response_provider import ResponseProvider

logger = logging.getLogger(__name__)

sso_service = SSOService()
mfa_service = MFAService()


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


def _get_session(session_id: str, user) -> Optional[SSOSession]:
    try:
        return (
            SSOSession.objects
            .select_related("user")
            .get(id=session_id, user=user, is_active=True)
        )
    except SSOSession.DoesNotExist:
        return None


def _contexts_payload(session: SSOSession, system: System) -> list:
    # noinspection PyBroadException
    try:
        return [vars(c) for c in sso_service.get_login_contexts(session, system)]
    except Exception:
        return []


def _post_login_response(session: SSOSession, client: SystemClient) -> JsonResponse:
    system = client.system
    try:
        sso_service.check_system_mfa(session, client)
        contexts = _contexts_payload(session, system)
        return ResponseProvider.success(session_id=str(session.id), contexts=contexts)

    except MFAEnrollmentRequiredError as e:
        return ResponseProvider.success(
            session_id=str(session.id),
            system_mfa_required=True,
            mfa_enrollment_required=True,
            reason=e.requirement.reason,
            allowed_methods=e.requirement.allowed_methods,
        )
    except MFARequiredError as e:
        return ResponseProvider.success(
            session_id=str(session.id),
            system_mfa_required=True,
            mfa_enrollment_required=False,
            reason=e.requirement.reason,
            allowed_methods=e.requirement.allowed_methods,
        )


@require_POST
def password_login_view(request: ExtendedRequest) -> JsonResponse:
    try:
        data = request.data
        client = _get_client(data)
        if not client:
            return ResponseProvider.bad_request(
                error="invalid_client",
                message="Invalid or inactive client."
            )

        session = sso_service.authenticate_password(
            login_value=data["login_value"],
            password=data["password"],
            client=client,
            ip_address=request.client_ip,
            user_agent=request.user_agent,
            device_id=data.get("device_id", ""),
            device_name=data.get("device_name", ""),
        )

        return _post_login_response(session, client)

    except AuthenticationError as e:
        return ResponseProvider.unauthorized(
            error="authentication_error",
            message=str(e)
        )
    except Exception as e:
        logger.exception("password_login_view: %s", e)
        return ResponseProvider.server_error()


@require_POST
def pin_login_view(request: ExtendedRequest) -> JsonResponse:
    try:
        data = request.data
        client = _get_client(data)
        if not client:
            return ResponseProvider.bad_request(
                error="invalid_client",
                message="Invalid or inactive client."
            )

        session = sso_service.authenticate_pin(
            login_value=data["login_value"],
            pin=data["pin"],
            client=client,
            ip_address=request.client_ip,
            user_agent=request.user_agent,
            device_id=data.get("device_id", ""),
            device_name=data.get("device_name", ""),
        )

        return _post_login_response(session, client)

    except AuthenticationError as e:
        return ResponseProvider.unauthorized(
            error="authentication_error",
            message=str(e)
        )
    except Exception as e:
        logger.exception("pin_login_view: %s", e)
        return ResponseProvider.server_error()


@require_POST
def passwordless_initiate_view(request: ExtendedRequest) -> JsonResponse:
    try:
        data = request.data
        client = _get_client(data)
        if not client:
            return ResponseProvider.bad_request(
                error="invalid_client",
                message="Invalid or inactive client."
            )

        result = sso_service.initiate_passwordless(
            login_value=data["login_value"],
            client=client,
            ip_address=request.client_ip,
        )

        return ResponseProvider.success(**result)

    except AuthenticationError as e:
        return ResponseProvider.unauthorized(
            error="authentication_error",
            message=str(e)
        )
    except Exception as e:
        logger.exception("passwordless_initiate_view: %s", e)
        return ResponseProvider.server_error()


@require_POST
def passwordless_verify_view(request: ExtendedRequest) -> JsonResponse:
    try:
        data = request.data
        client = _get_client(data)
        if not client:
            return ResponseProvider.bad_request(
                error="invalid_client",
                message="Invalid or inactive client."
            )

        session = sso_service.verify_passwordless(
            client=client,
            challenge_id=data["challenge_id"],
            code=data["code"],
            ip_address=request.client_ip,
            user_agent=request.user_agent,
            device_id=data.get("device_id", ""),
            device_name=data.get("device_name", ""),
        )

        return _post_login_response(session, client)

    except AuthenticationError as e:
        return ResponseProvider.unauthorized(
            error="authentication_error",
            message=str(e)
        )
    except Exception as e:
        logger.exception("passwordless_verify_view: %s", e)
        return ResponseProvider.server_error()


@require_POST
def magic_link_initiate_view(request: ExtendedRequest) -> JsonResponse:
    try:
        data = request.data
        client = _get_client(data)
        if not client:
            return ResponseProvider.bad_request(
                error="invalid_client",
                message="Invalid or inactive client."
            )

        result = sso_service.initiate_magic_link(
            email=data["email"],
            client=client,
            scopes=data.get("scopes", []),
            ip_address=request.client_ip,
        )
        return ResponseProvider.success(**result)

    except AuthenticationError as e:
        return ResponseProvider.unauthorized(
            error="authentication_error",
            message=str(e)
        )
    except Exception as e:
        logger.exception("magic_link_initiate_view: %s", e)
        return ResponseProvider.server_error()


@require_POST
def magic_link_verify_view(request: ExtendedRequest) -> JsonResponse:
    try:
        data = request.data
        client = _get_client(data)
        if not client:
            return ResponseProvider.bad_request(
                error="invalid_client",
                message="Invalid or inactive client."
            )

        session = sso_service.verify_magic_link(
            client=client,
            raw_token=data["token"],
            ip_address=request.client_ip,
            user_agent=request.user_agent,
        )

        return _post_login_response(session, client)

    except AuthenticationError as e:
        return ResponseProvider.unauthorized(
            error="authentication_error",
            message=str(e)
        )
    except Exception as e:
        logger.exception("magic_link_verify_view: %s", e)
        return ResponseProvider.server_error()


@sso_session_required
@require_POST
def system_mfa_otp_initiate_view(request: ExtendedRequest) -> JsonResponse:
    try:
        data = request.data
        client = _get_client(data)
        if not client:
            return ResponseProvider.bad_request(
                error="invalid_client",
                message="Invalid or inactive client."
            )

        result = mfa_service.initiate_mfa_otp(
            sso_session=request.sso_session,
            method=data["method"],
            client=client,
            ip_address=request.client_ip,
        )
        return ResponseProvider.success(**result)

    except (InvalidMFAOperationError, MFARateLimitExceededError) as e:
        return ResponseProvider.bad_request(
            error="invalid_mfa_operation",
            message=str(e)
        )
    except Exception as e:
        logger.exception("system_mfa_otp_initiate_view: %s", e)
        return ResponseProvider.server_error()


@sso_session_required
@require_POST
def system_mfa_otp_verify_view(request: ExtendedRequest) -> JsonResponse:
    try:
        data = request.data
        client = _get_client(data)
        session = request.sso_session
        if not client:
            return ResponseProvider.bad_request(
                error="invalid_client",
                message="Invalid or inactive client."
            )

        mfa_service.verify_mfa_otp(
            sso_session=session,
            client=client,
            challenge_id=data["challenge_id"],
            code=data["code"],
            ip_address=request.client_ip,
        )

        sso_service.mark_system_mfa_satisfied(session)
        contexts = _contexts_payload(session, client.system)
        return ResponseProvider.success(
            session_id=str(session.id),
            contexts=contexts
        )

    except InvalidMFAOperationError as e:
        return ResponseProvider.bad_request(error="invalid_mfa_operation", message=str(e))
    except Exception as e:
        logger.exception("system_mfa_otp_verify_view: %s", e)
        return ResponseProvider.server_error()


@sso_session_required
@require_POST
def system_mfa_code_verify_view(request: ExtendedRequest) -> JsonResponse:
    try:
        data = request.data
        client = _get_client(data)
        session = request.sso_session
        if not client:
            return ResponseProvider.bad_request(
                error="invalid_client",
                message="Invalid or inactive client."
            )

        verified = mfa_service.verify_mfa_code(
            user=session.user,
            method=data["method"],
            code=data["code"],
            ip_address=request.client_ip,
            sso_session=session,
            system=client.system,
        )
        if not verified:
            return ResponseProvider.unauthorized(
                error="mfa_failed",
                message="Incorrect code."
            )

        sso_service.mark_system_mfa_satisfied(session)
        contexts = _contexts_payload(session, client.system)
        return ResponseProvider.success(
            session_id=str(session.id),
            contexts=contexts
        )

    except InvalidMFAOperationError as e:
        return ResponseProvider.bad_request(error="invalid_mfa_operation", message=str(e))
    except Exception as e:
        logger.exception("system_mfa_code_verify_view: %s", e)
        return ResponseProvider.server_error()


@sso_session_required
@require_GET
def list_contexts_view(request: ExtendedRequest) -> JsonResponse:
    try:
        client = _get_client(request.GET)
        if not client:
            return ResponseProvider.bad_request(
                error="invalid_client",
                message="Invalid or inactive client."
            )

        session = request.sso_session
        contexts = _contexts_payload(session, client.system)
        return ResponseProvider.success(contexts=contexts)

    except Exception as e:
        logger.exception("list_contexts_view: %s", e)
        return ResponseProvider.server_error()


@sso_session_required
@require_POST
def context_select_view(request: ExtendedRequest) -> JsonResponse:
    try:
        data = request.data
        client = _get_client(data)
        session = request.sso_session
        if not client:
            return ResponseProvider.bad_request(
                error="invalid_client",
                message="Invalid or inactive client."
            )

        code = sso_service.select_context(
            session=session,
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

    except MFARequiredError as e:
        return ResponseProvider.success(
            role_mfa_required=True,
            pending_context_id=e.pending_context_id,
            reason=e.requirement.reason,
            allowed_methods=e.requirement.allowed_methods,
        )
    except MFAEnrollmentRequiredError as e:
        return ResponseProvider.success(
            mfa_enrollment_required=True,
            pending_context_id=e.pending_context_id,
            reason=e.requirement.reason,
            allowed_methods=e.requirement.allowed_methods,
        )
    except Exception as e:
        logger.exception("context_select_view: %s", e)
        return ResponseProvider.server_error()


@sso_session_required
@require_POST
def context_mfa_otp_initiate_view(request: ExtendedRequest) -> JsonResponse:
    try:
        data = request.data
        client = _get_client(data)
        if not client:
            return ResponseProvider.bad_request(
                error="invalid_client",
                message="Invalid or inactive client."
            )

        result = mfa_service.initiate_mfa_otp(
            sso_session=request.sso_session,
            method=data["method"],
            client=client,
            ip_address=request.client_ip,
        )
        return ResponseProvider.success(**result)

    except (InvalidMFAOperationError, MFARateLimitExceededError) as e:
        return ResponseProvider.bad_request(
            error="invalid_mfa_operation",
            message=str(e)
        )
    except Exception as e:
        logger.exception("context_mfa_otp_initiate_view: %s", e)
        return ResponseProvider.server_error()


@sso_session_required
@require_POST
def context_mfa_otp_verify_view(request: ExtendedRequest) -> JsonResponse:
    try:
        data = request.data
        client = _get_client(data)
        session = request.sso_session
        if not client:
            return ResponseProvider.bad_request(
                error="invalid_client",
                message="Invalid or inactive client."
            )

        mfa_service.verify_mfa_otp(
            sso_session=session,
            client=client,
            challenge_id=data["challenge_id"],
            code=data["code"],
            ip_address=request.client_ip,
        )

        code = sso_service.satisfy_pending_context_mfa(
            session=session,
            pending_context_id=data["pending_context_id"]
        )
        return ResponseProvider.success(authorization_code=code)

    except InvalidMFAOperationError as e:
        return ResponseProvider.bad_request(
            error="invalid_mfa_operation",
            message=str(e)
        )
    except Exception as e:
        logger.exception("context_mfa_otp_verify_view: %s", e)
        return ResponseProvider.server_error()


@sso_session_required
@require_POST
def context_mfa_code_verify_view(request: ExtendedRequest) -> JsonResponse:
    try:
        data = request.data
        client = _get_client(data)
        session = request.sso_session
        if not client:
            return ResponseProvider.bad_request(
                error="invalid_client",
                message="Invalid or inactive client."
            )

        verified = mfa_service.verify_mfa_code(
            user=session.user,
            method=data["method"],
            code=data["code"],
            ip_address=request.client_ip,
            sso_session=session,
            system=client.system,
        )
        if not verified:
            return ResponseProvider.unauthorized(
                error="mfa_failed",
                message="Incorrect code."
            )

        code = sso_service.satisfy_pending_context_mfa(
            session=session,
            pending_context_id=data["pending_context_id"]
        )
        return ResponseProvider.success(authorization_code=code)

    except InvalidMFAOperationError as e:
        return ResponseProvider.bad_request(
            error="invalid_mfa_operation",
            message=str(e)
        )
    except Exception as e:
        logger.exception("context_mfa_code_verify_view: %s", e)
        return ResponseProvider.server_error()


@sso_session_required
@require_POST
def mfa_enroll_initiate_view(request: ExtendedRequest) -> JsonResponse:
    try:
        data = request.data
        client = _get_client(data) if data.get("client_id") else None

        result = mfa_service.initiate_enrollment(
            user=request.sso_session.user,
            method=data["method"],
            device_name=data.get("device_name", ""),
            delivery_target=data.get("delivery_target"),
            client=client,
            ip_address=request.client_ip,
            pending_enrollment_id=data.get("pending_enrollment_id"),
        )
        return ResponseProvider.success(**result)

    except InvalidMFAOperationError as e:
        return ResponseProvider.bad_request(
            error="invalid_mfa_operation",
            message=str(e)
        )
    except Exception as e:
        logger.exception("mfa_enroll_initiate_view: %s", e)
        return ResponseProvider.server_error()


@sso_session_required
@require_POST
def mfa_enroll_verify_view(request: ExtendedRequest) -> JsonResponse:
    try:
        data = request.data
        result = mfa_service.verify_enrollment(
            user=request.sso_session.user,
            method=data["method"],
            verification_data=data,
            ip_address=request.client_ip,
            pending_enrollment_id=data.get("pending_enrollment_id"),
        )
        return ResponseProvider.success(
            mfa_id=str(result.mfa.id),
            backup_codes=result.backup_codes
        )

    except InvalidMFAOperationError as e:
        return ResponseProvider.bad_request(
            error="invalid_mfa_operation",
            message=str(e)
        )
    except Exception as e:
        logger.exception("mfa_enroll_verify_view: %s", e)
        return ResponseProvider.server_error()


@sso_session_required
@require_GET
def mfa_list_view(request: ExtendedRequest) -> JsonResponse:
    mfas = mfa_service.list_enrolled(request.sso_session.user)
    return ResponseProvider.success(
        mfa_methods=[
            {
                "id": str(m.id),
                "method": m.method,
                "is_primary": m.is_primary,
                "device_name": m.device_name,
                "last_used_at": m.last_used_at
            }
            for m in mfas
        ]
    )


@sso_session_required
@require_POST
def mfa_set_primary_view(request: ExtendedRequest) -> JsonResponse:
    try:
        data = request.data
        mfa = mfa_service.set_primary(
            user=request.sso_session.user,
            mfa_id=data["mfa_id"]
        )
        return ResponseProvider.success(
            mfa_id=str(mfa.id),
            method=mfa.method
        )
    except InvalidMFAOperationError as e:
        return ResponseProvider.bad_request(
            error="invalid_mfa_operation",
            message=str(e)
        )
    except Exception as e:
        logger.exception("mfa_set_primary_view: %s", e)
        return ResponseProvider.server_error()


@sso_session_required
@require_POST
def mfa_remove_view(request: ExtendedRequest) -> JsonResponse:
    try:
        data = request.data
        mfa_service.remove_mfa(
            user=request.sso_session.user,
            mfa_id= data["mfa_id"],
            ip_address=request.client_ip
        )
        return ResponseProvider.success()
    except InvalidMFAOperationError as e:
        return ResponseProvider.bad_request(
            error="invalid_mfa_operation",
            message=str(e)
        )
    except Exception as e:
        logger.exception("mfa_remove_view: %s", e)
        return ResponseProvider.server_error()


@csrf_exempt
@require_POST
def token_exchange_view(request: ExtendedRequest) -> JsonResponse:
    try:
        data = request.data
        client = _get_client(data)
        if not client:
            return ResponseProvider.bad_request(
                error="invalid_client",
                message="Invalid client."
            )

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

    except OAuthError as e:
        return ResponseProvider.unauthorized(
            error=e.error,
            message=e.description
        )
    except Exception as e:
        logger.exception("token_exchange_view: %s", e)
        return ResponseProvider.server_error()


@csrf_exempt
@require_POST
def token_refresh_view(request: ExtendedRequest) -> JsonResponse:
    try:
        data = request.data
        client = _get_client(data)
        if not client:
            return ResponseProvider.bad_request(
                error="invalid_client",
                message="Invalid client."
            )

        tokens = sso_service.refresh_tokens(
            raw_refresh_token=data["refresh_token"],
            client=client
        )

        return ResponseProvider.success(
            access_token=tokens.access_token,
            refresh_token=tokens.refresh_token,
            id_token=tokens.id_token,
            token_type=tokens.token_type,
            expires_in=tokens.expires_in,
            scope=tokens.scope,
        )

    except OAuthError as e:
        return ResponseProvider.unauthorized(
            error=e.error,
            message=e.description
        )
    except Exception as e:
        logger.exception("token_refresh_view: %s", e)
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
    except Exception as e:
        logger.exception("token_revoke_view: %s", e)
    return ResponseProvider.success()


@csrf_exempt
@require_POST
def token_introspect_view(request: ExtendedRequest) -> JsonResponse:
    try:
        data = request.data
        result = sso_service.introspect(data.get("token", ""))
        return ResponseProvider.success(**result)
    except Exception as e:
        logger.exception("token_introspect_view: %s", e)
        return ResponseProvider.success(active=False)


@sso_session_required
@require_POST
def logout_view(request: ExtendedRequest) -> JsonResponse:
    try:
        sso_service.logout(
            session=request.sso_session,
            ip_address=request.client_ip
        )
        return ResponseProvider.success()
    except Exception as e:
        logger.exception("logout_view: %s", e)
        return ResponseProvider.server_error()


@sso_session_required
@require_POST
def logout_all_view(request: ExtendedRequest) -> JsonResponse:
    try:
        count = sso_service.logout_all(
            user=request.sso_session.user,
            ip_address=request.client_ip
        )
        return ResponseProvider.success(sessions_revoked=count)
    except Exception as e:
        logger.exception("logout_all_view: %s", e)
        return ResponseProvider.server_error()