import logging
from datetime import datetime
from typing import Optional

from django.http import JsonResponse
from django.views.decorators.http import require_GET, require_http_methods, require_POST

from accounts.models import IdentifierType, Referral, SystemUser, User
from accounts.services.account_service import (
    AccountService,
    ClaimError,
    ClaimExpiredError,
    InvalidClaimTokenError,
    LinkAccountRequired,
    ManageIdentifierError,
    ProvisionSystemUserError,
    RegistrationClosedError,
    SelfRegistrationError,
    SystemUserStatusError,
)
from accounts.services.identifier_verification_service import (
    IdentifierVerificationError,
    IdentifierVerificationService,
)
from accounts.services.referral_service import ReferralService, ReferralServiceError
from base.models import Country
from organizations.models import Organization
from permissions.models import Role
from sso.models import SSOSession
from sso.services.sso_service import (
    IdentifierVerificationRequiredError,
    MFARequiredError,
    SSOService,
)
from systems.models import System, SystemClient
from utils.decorators import require_active_session, require_user_context
from utils.extended_request import ExtendedRequest
from utils.response_provider import ResponseProvider

logger = logging.getLogger(__name__)
account_service = AccountService()
identifier_verification_service = IdentifierVerificationService()
referral_service = ReferralService()
sso_service = SSOService()


def _get_system(data: dict) -> Optional[System]:
    sid = data.get("system_id") or data.get("system")
    if not sid:
        return None
    try:
        return System.objects.get(id=sid, is_active=True)
    except System.DoesNotExist:
        return None


def _get_role(data: dict, system: System) -> Optional[Role]:
    rid = data.get("role_id") or data.get("role")
    if not rid:
        return None
    try:
        return Role.objects.get(id=rid, system=system, is_active=True)
    except Role.DoesNotExist:
        return None


def _get_country(data: dict) -> Optional[Country]:
    cid = data.get("country_id") or data.get("country")
    if not cid:
        return None
    try:
        return Country.objects.get(id=cid)
    except Country.DoesNotExist:
        return None


def _get_organization(data: dict) -> Optional[Organization]:
    oid = data.get("organization_id") or data.get("organization")
    if not oid:
        return None
    try:
        return Organization.objects.get(id=oid, is_active=True)
    except Organization.DoesNotExist:
        return None


def _get_client(data: dict) -> Optional[SystemClient]:
    client_id = data.get("client_id")
    if not client_id:
        return None
    try:
        return SystemClient.objects.select_related("system").get(client_id=client_id, is_active=True)
    except SystemClient.DoesNotExist:
        return None


def _parse_bool_query(value: Optional[str]) -> Optional[bool]:
    if value is None or value == "":
        return None
    lowered = value.lower()
    if lowered in {"true", "1", "yes"}:
        return True
    if lowered in {"false", "0", "no"}:
        return False
    return None


def _parse_datetime_query(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    return datetime.fromisoformat(value)


def _profile_fields(data: dict) -> dict:
    return {
        "first_name": data.get("first_name", ""),
        "last_name": data.get("last_name", ""),
        "middle_name": data.get("middle_name", ""),
        "display_name": data.get("display_name", ""),
        "date_of_birth": data.get("date_of_birth"),
        "gender": data.get("gender", ""),
    }


def _social_fields(data: dict) -> dict:
    return {
        "provider": data.get("provider"),
        "uid": data.get("uid") or data.get("provider_user_id"),
        "access_token": data.get("access_token", ""),
        "refresh_token": data.get("refresh_token", ""),
        "extra_data": data.get("extra_data") or {},
    }


def _verification_ids(data: dict) -> dict:
    nested = data.get("verification_ids") or {}
    return {
        "email_verification_id": nested.get("email") or data.get("email_verification_id"),
        "phone_verification_id": nested.get("phone") or data.get("phone_verification_id"),
    }


def _system_user_payload(system_user: SystemUser) -> dict:
    user = system_user.user
    return {
        "system_user_id": str(system_user.id),
        "user_id": str(user.id) if user else None,
        "system": system_user.system.name,
        "organization": system_user.organization.name if system_user.organization_id else None,
        "country": system_user.country.code if system_user.country_id else None,
        "role": system_user.role.name,
        "status": system_user.status,
        "email": user.email if user else system_user.provisioning_email,
        "full_name": user.full_name if user else "",
        "referral_code": system_user.referral_code,
    }


def _contact_payload(user: User, contact_type: str) -> dict:
    if contact_type == IdentifierType.EMAIL:
        return {
            "id": IdentifierType.EMAIL,
            "type": IdentifierType.EMAIL,
            "value": user.email,
            "is_primary": True,
            "is_verified": user.email_verified,
            "verified_at": user.email_verified_at.isoformat() if user.email_verified_at else None,
        }
    return {
        "id": IdentifierType.PHONE,
        "type": IdentifierType.PHONE,
        "value": user.phone_number,
        "is_primary": True,
        "is_verified": user.phone_verified,
        "verified_at": user.phone_verified_at.isoformat() if user.phone_verified_at else None,
    }


def _user_payload(user: User) -> dict:
    return {
        "id": str(user.id),
        "email": user.email,
        "email_verified": user.email_verified,
        "phone_number": user.phone_number,
        "phone_verified": user.phone_verified,
        "first_name": user.first_name,
        "last_name": user.last_name,
        "middle_name": user.middle_name,
        "display_name": user.display_name,
        "date_of_birth": user.date_of_birth.isoformat() if user.date_of_birth else None,
        "gender": user.gender,
        "profile_photo_url": user.profile_photo_url,
    }


def _referral_payload(referral: Referral) -> dict:
    return {
        "id": str(referral.id),
        "system_id": str(referral.system_id),
        "referrer_system_user_id": str(referral.referrer_id),
        "referrer_referral_code": referral.referral_code,
        "referred_system_user_id": str(referral.referred_id),
        "is_verified": referral.is_verified,
        "verified_at": referral.verified_at.isoformat() if referral.verified_at else None,
        "is_rewarded": referral.is_rewarded,
        "rewarded_at": referral.rewarded_at.isoformat() if referral.rewarded_at else None,
        "reward_amount": str(referral.system.referral_reward_amount),
        "created_at": referral.created_at.isoformat(),
    }


def _post_registration_response(
    request: ExtendedRequest,
    system: System,
    user: User,
    system_user: SystemUser,
    auth_method: str,
) -> JsonResponse:
    payload = {"user_id": str(user.id), "system_user_id": str(system_user.id)}
    if not system.auto_login_after_registration:
        return ResponseProvider.success(**payload)

    client = _get_client(request.data)
    if not client or client.system_id != system.id:
        payload["auto_login_skipped"] = True
        payload["auto_login_reason"] = "valid_client_id_required"
        return ResponseProvider.success(**payload)

    session = sso_service.create_session_for_user(
        user=user,
        client=client,
        auth_method=auth_method,
        ip_address=request.client_ip,
        user_agent=request.user_agent,
        device_id=request.data.get("device_id", ""),
        device_name=request.data.get("device_name", ""),
    )
    payload["session_id"] = str(session.id)
    try:
        payload["contexts"] = [
            vars(context)
            for context in sso_service.get_ready_contexts(session, client)
        ]
    except IdentifierVerificationRequiredError as exc:
        payload["identifier_verification_required"] = True
        payload["required_identifiers"] = exc.requirements
    except MFARequiredError as exc:
        payload["mfa_required"] = True
        payload["reason"] = exc.requirement.reason
        payload["allowed_methods"] = exc.requirement.allowed_methods
        payload["pending_context_id"] = exc.pending_context_id or None
    return ResponseProvider.success(**payload)


@require_POST
def registration_identifier_initiate_view(request: ExtendedRequest) -> JsonResponse:
    try:
        data = request.data
        system = _get_system(data) if data.get("system_id") or data.get("system") else None

        verification = identifier_verification_service.initiate_registration_verification(
            identifier_type=data.get("identifier_type", ""),
            value=data.get("value", ""),
            method=data.get("method", "otp"),
            ip_address=request.client_ip,
            system=system,
        )

        return ResponseProvider.success(
            verification_id=str(verification.id),
            identifier_type=verification.contact_type,
            method=verification.method,
            masked_destination=identifier_verification_service.masked_value(verification.value),
            expires_in=300,
        )

    except IdentifierVerificationError as e:
        return ResponseProvider.bad_request(
            error="identifier_verification_error",
            message=str(e)
        )
    except Exception as e:
        logger.exception("registration_identifier_initiate_view: %s", e)
        return ResponseProvider.server_error()


@require_POST
def registration_identifier_verify_view(request: ExtendedRequest) -> JsonResponse:
    try:
        verification = identifier_verification_service.verify_registration_verification(
            verification_id=request.data.get("verification_id", ""),
            code=request.data.get("code", ""),
            token=request.data.get("token", ""),
            ip_address=request.client_ip,
        )

        return ResponseProvider.success(
            verification_id=str(verification.id),
            identifier_type=verification.contact_type,
            method=verification.method,
            value=verification.value,
            is_verified=verification.is_verified,
            verified_at=verification.verified_at.isoformat() if verification.verified_at else None,
        )

    except IdentifierVerificationError as e:
        return ResponseProvider.bad_request(
            error="identifier_verification_error",
            message=str(e)
        )
    except Exception as e:
        logger.exception("registration_identifier_verify_view: %s", e)
        return ResponseProvider.server_error()


@require_POST
def register_view(request: ExtendedRequest) -> JsonResponse:
    try:
        data = request.data
        system = _get_system(data)
        if not system:
            return ResponseProvider.bad_request(
                error="invalid_system",
                message="System not found or inactive."
            )

        role = _get_role(data, system)
        if not role:
            return ResponseProvider.bad_request(
                error="invalid_role",
                message="Role not found."
            )

        user, system_user = account_service.self_registration(
            system=system,
            role=role,
            primary_country=_get_country(data),
            ip_address=request.client_ip,
            email=data.get("email"),
            phone_number=data.get("phone_number"),
            password=data.get("password"),
            pin=data.get("pin"),
            referral_code=data.get("referral_code"),
            **_profile_fields(data),
            **_verification_ids(data),
        )

        auth_method = (
            SSOSession.AuthMethod.PIN
            if system.password_type == System.PasswordType.PIN
            else SSOSession.AuthMethod.PASSWORD
        )
        return _post_registration_response(request, system, user, system_user, auth_method)

    except LinkAccountRequired as e:
        return ResponseProvider.conflict(
            link_required=True,
            matched_on=e.matched_on,
            existing_user_id=str(e.existing_user.id),
        )
    except (RegistrationClosedError, SelfRegistrationError) as e:
        return ResponseProvider.bad_request(
            error="registration_error",
            message=str(e)
        )
    except Exception as e:
        logger.exception("register_view: %s", e)
        return ResponseProvider.server_error()


@require_POST
def register_link_view(request: ExtendedRequest) -> JsonResponse:
    try:
        data = request.data
        system = _get_system(data)
        if not system:
            return ResponseProvider.bad_request(
                error="invalid_system",
                message="System not found or inactive."
            )

        role = _get_role(data, system)
        if not role:
            return ResponseProvider.bad_request(
                error="invalid_role",
                message="Role not found."
            )

        try:
            existing_user = User.objects.get(id=data["existing_user_id"])
        except (User.DoesNotExist, KeyError):
            return ResponseProvider.bad_request(
                error="invalid_user",
                message="User not found."
            )

        user, system_user = account_service.self_registration_link(
            existing_user=existing_user,
            system=system,
            role=role,
            primary_country=_get_country(data),
            referral_code=data.get("referral_code"),
            ip_address=request.client_ip,
        )

        auth_method = (
            SSOSession.AuthMethod.PIN
            if system.password_type == System.PasswordType.PIN
            else SSOSession.AuthMethod.PASSWORD
        )
        return _post_registration_response(request, system, user, system_user, auth_method)

    except SelfRegistrationError as e:
        return ResponseProvider.bad_request(
            error="registration_error",
            message=str(e)
        )
    except Exception as e:
        logger.exception("register_link_view: %s", e)
        return ResponseProvider.server_error()


@require_POST
def register_social_view(request: ExtendedRequest) -> JsonResponse:
    try:
        data = request.data
        system = _get_system(data)
        if not system:
            return ResponseProvider.bad_request(error="invalid_system", message="System not found or inactive.")
        role = _get_role(data, system)
        if not role:
            return ResponseProvider.bad_request(error="invalid_role", message="Role not found.")

        user, system_user = account_service.self_registration_social(
            system=system,
            role=role,
            primary_country=_get_country(data),
            referral_code=data.get("referral_code"),
            ip_address=request.client_ip,
            email=data.get("email"),
            phone_number=data.get("phone_number"),
            **_profile_fields(data),
            **_social_fields(data),
            **_verification_ids(data),
        )
        return _post_registration_response(request, system, user, system_user, SSOSession.AuthMethod.SOCIAL)
    except LinkAccountRequired as e:
        return JsonResponse({
            "success": False,
            "link_required": True,
            "matched_on": e.matched_on,
            "existing_user_id": str(e.existing_user.id),
        }, status=409)
    except SelfRegistrationError as e:
        return ResponseProvider.bad_request(error="registration_error", message=str(e))
    except Exception as e:
        logger.exception("register_social_view: %s", e)
        return ResponseProvider.server_error()


@require_POST
def register_social_link_view(request: ExtendedRequest) -> JsonResponse:
    try:
        data = request.data
        system = _get_system(data)
        if not system:
            return ResponseProvider.bad_request(error="invalid_system", message="System not found or inactive.")
        role = _get_role(data, system)
        if not role:
            return ResponseProvider.bad_request(error="invalid_role", message="Role not found.")
        try:
            existing_user = User.objects.get(id=data["existing_user_id"])
        except (User.DoesNotExist, KeyError):
            return ResponseProvider.bad_request(error="invalid_user", message="User not found.")

        user, system_user = account_service.self_registration_social_link(
            existing_user=existing_user,
            system=system,
            role=role,
            primary_country=_get_country(data),
            organization=_get_organization(data),
            referral_code=data.get("referral_code"),
            email=data.get("email"),
            phone_number=data.get("phone_number"),
            ip_address=request.client_ip,
            **_social_fields(data),
        )
        return _post_registration_response(request, system, user, system_user, SSOSession.AuthMethod.SOCIAL)
    except SelfRegistrationError as e:
        return ResponseProvider.bad_request(error="registration_error", message=str(e))
    except Exception as e:
        logger.exception("register_social_link_view: %s", e)
        return ResponseProvider.server_error()


@require_GET
def claim_inspect_view(request: ExtendedRequest) -> JsonResponse:
    try:
        payload = account_service.inspect_claim(
            lookup_id=request.GET.get("lookup_id", ""),
            token=request.GET.get("token", ""),
        )
        return ResponseProvider.success(**payload)
    except (InvalidClaimTokenError, ClaimExpiredError, ClaimError) as e:
        return ResponseProvider.bad_request(error="claim_error", message=str(e))
    except Exception as e:
        logger.exception("claim_inspect_view: %s", e)
        return ResponseProvider.server_error()


@require_POST
def claim_view(request: ExtendedRequest) -> JsonResponse:
    try:
        data = request.data
        su = account_service.claim_user(
            lookup_id=data.get("lookup_id", ""),
            token=data.get("token", ""),
            claim_action=data.get("claim_action", ""),
            password=data.get("password"),
            pin=data.get("pin"),
            phone_number=data.get("phone_number"),
            country=_get_country(data),
            ip_address=request.client_ip,
            **_profile_fields(data),
            **_verification_ids(data),
        )
        return ResponseProvider.success(**_system_user_payload(su))
    except (ClaimError, InvalidClaimTokenError, ClaimExpiredError, RegistrationClosedError) as e:
        return ResponseProvider.bad_request(error="claim_error", message=str(e))
    except Exception as e:
        logger.exception("claim_view: %s", e)
        return ResponseProvider.server_error()


@require_active_session
@require_GET
def me_view(request: ExtendedRequest) -> JsonResponse:
    try:
        user = request.sso_session.user
        memberships = SystemUser.objects.filter(user=user, status="active").select_related("system", "organization", "country", "role")
        return ResponseProvider.success(
            user=_user_payload(user),
            memberships=[_system_user_payload(membership) for membership in memberships],
        )
    except Exception as e:
        logger.exception("me_view: %s", e)
        return ResponseProvider.server_error()


@require_active_session
@require_http_methods(["PATCH"])
def me_update_view(request: ExtendedRequest) -> JsonResponse:
    try:
        system_user = request.system_user or request.sso_session.user.system_users.filter(status="active").first()
        if not system_user:
            return ResponseProvider.bad_request(error="missing_context", message="No active system context found.")
        updated = account_service.update_profile(system_user=system_user, **request.data)
        return ResponseProvider.success(user=_user_payload(updated.user), system_user=_system_user_payload(updated))
    except SelfRegistrationError as e:
        return ResponseProvider.bad_request(error="profile_error", message=str(e))
    except Exception as e:
        logger.exception("me_update_view: %s", e)
        return ResponseProvider.server_error()


@require_user_context
@require_GET
def my_referrals_view(request: ExtendedRequest) -> JsonResponse:
    try:
        referrals = Referral.objects.filter(referrer=request.system_user).select_related("system", "referrer", "referred")
        return ResponseProvider.success(referrals=[_referral_payload(referral) for referral in referrals])
    except Exception as e:
        logger.exception("my_referrals_view: %s", e)
        return ResponseProvider.server_error()


@require_user_context
@require_POST
def attach_my_referral_view(request: ExtendedRequest) -> JsonResponse:
    try:
        referral = referral_service.attach_referral(referred=request.system_user, referral_code=request.data.get("referral_code", ""))
        referral = Referral.objects.select_related("system", "referrer", "referred").get(id=referral.id)
        return ResponseProvider.success(**_referral_payload(referral))
    except ReferralServiceError as e:
        return ResponseProvider.bad_request(error="referral_error", message=str(e))
    except Exception as e:
        logger.exception("attach_my_referral_view: %s", e)
        return ResponseProvider.server_error()


@require_user_context(required_permission="accounts.manage_referrals")
@require_GET
def referral_list_view(request: ExtendedRequest) -> JsonResponse:
    try:
        system_id = request.GET.get("system_id")
        if not system_id:
            return ResponseProvider.bad_request(error="missing_params", message="system_id is required.")
        qs = Referral.objects.filter(system_id=system_id).select_related("system", "referrer", "referred").order_by("-created_at")
        verified = _parse_bool_query(request.GET.get("verified"))
        if verified is not None:
            qs = qs.filter(is_verified=verified)
        rewarded = _parse_bool_query(request.GET.get("rewarded"))
        if rewarded is not None:
            qs = qs.filter(is_rewarded=rewarded)
        return ResponseProvider.success(referrals=[_referral_payload(referral) for referral in qs])
    except Exception as e:
        logger.exception("referral_list_view: %s", e)
        return ResponseProvider.server_error()


@require_active_session
@require_GET
def identifier_list_view(request: ExtendedRequest) -> JsonResponse:
    user = request.sso_session.user
    return ResponseProvider.success(identifiers=[_contact_payload(user, IdentifierType.EMAIL), _contact_payload(user, IdentifierType.PHONE)])


@require_active_session
@require_POST
def identifier_add_view(request: ExtendedRequest) -> JsonResponse:
    return ResponseProvider.bad_request(
        error="contact_error",
        message="Additional identifiers are no longer supported. Users have a single email and phone number."
    )


@require_active_session
@require_POST
def identifier_verify_initiate_view(request: ExtendedRequest, identifier_id: str) -> JsonResponse:
    try:
        if identifier_id not in (IdentifierType.EMAIL, IdentifierType.PHONE):
            return ResponseProvider.bad_request(error="invalid_identifier", message="Identifier must be 'email' or 'phone'.")
        verification = identifier_verification_service.initiate_user_contact_verification(
            user=request.sso_session.user,
            identifier_type=identifier_id,
            method=request.data.get("method", "otp"),
            ip_address=request.client_ip,
        )
        value = request.sso_session.user.email if identifier_id == IdentifierType.EMAIL else request.sso_session.user.phone_number
        return ResponseProvider.success(
            verification_id=str(verification.id),
            identifier_type=identifier_id,
            method=verification.method,
            masked_destination=identifier_verification_service.masked_value(value),
            expires_in=300,
        )
    except IdentifierVerificationError as e:
        return ResponseProvider.bad_request(error="identifier_verification_error", message=str(e))
    except Exception as e:
        logger.exception("identifier_verify_initiate_view: %s", e)
        return ResponseProvider.server_error()


@require_active_session
@require_POST
def identifier_verify_view(request: ExtendedRequest, identifier_id: str) -> JsonResponse:
    try:
        user = identifier_verification_service.verify_user_contact(
            user=request.sso_session.user,
            identifier_type=identifier_id,
            verification_id=request.data.get("verification_id", ""),
            code=request.data.get("code", ""),
            token=request.data.get("token", ""),
            ip_address=request.client_ip,
        )
        return ResponseProvider.success(**_contact_payload(user, identifier_id))
    except IdentifierVerificationError as e:
        return ResponseProvider.bad_request(error="identifier_verification_error", message=str(e))
    except Exception as e:
        logger.exception("identifier_verify_view: %s", e)
        return ResponseProvider.server_error()


@require_active_session
@require_POST
def identifier_promote_view(request: ExtendedRequest, identifier_id: str) -> JsonResponse:
    return ResponseProvider.bad_request(error="contact_error", message="Primary identifier promotion is no longer supported.")


@require_active_session
@require_POST
def identifier_remove_view(request: ExtendedRequest, identifier_id: str) -> JsonResponse:
    return ResponseProvider.bad_request(error="contact_error", message="Removing email/phone is not supported.")


@require_user_context(required_permission="accounts.provision_user")
@require_POST
def provision_system_user_view(request: ExtendedRequest) -> JsonResponse:
    try:
        data = request.data
        system = _get_system(data)
        if not system:
            return ResponseProvider.bad_request(error="invalid_system", message="System not found or inactive.")
        role = _get_role(data, system)
        if not role:
            return ResponseProvider.bad_request(error="invalid_role", message="Role not found.")
        system_user = account_service.provision_system_user(
            provisioned_by=request.system_user,
            system=system,
            country=_get_country(data),
            role=role,
            provisioning_email=data.get("provisioning_email", ""),
            organization=_get_organization(data),
            all_branches=data.get("all_branches", True),
            external_ref=data.get("external_ref", ""),
            metadata=data.get("metadata") or {},
        )
        return ResponseProvider.success(**_system_user_payload(system_user))
    except ProvisionSystemUserError as e:
        return ResponseProvider.bad_request(error="provision_error", message=str(e))
    except Exception as e:
        logger.exception("provision_system_user_view: %s", e)
        return ResponseProvider.server_error()


@require_user_context(required_permission="accounts.suspend_user")
@require_POST
def suspend_system_user_view(request: ExtendedRequest, system_user_id: str) -> JsonResponse:
    try:
        su = SystemUser.objects.get(id=system_user_id)
        su = account_service.suspend_system_user(
            system_user=su,
            reason=request.data.get("reason", ""),
            suspended_by=request.user,
            ip_address=request.client_ip,
        )
        return ResponseProvider.success(**_system_user_payload(su))
    except SystemUser.DoesNotExist:
        return ResponseProvider.not_found(error="not_found", message="System user not found.")
    except SystemUserStatusError as e:
        return ResponseProvider.bad_request(error="status_error", message=str(e))
    except Exception as e:
        logger.exception("suspend_system_user_view: %s", e)
        return ResponseProvider.server_error()


@require_user_context(required_permission="accounts.restore_user")
@require_POST
def restore_system_user_view(request: ExtendedRequest, system_user_id: str) -> JsonResponse:
    try:
        su = SystemUser.objects.get(id=system_user_id)
        su = account_service.restore_system_user(
            system_user=su,
            restored_by=request.user,
            ip_address=request.client_ip,
        )
        return ResponseProvider.success(**_system_user_payload(su))
    except SystemUser.DoesNotExist:
        return ResponseProvider.not_found(error="not_found", message="System user not found.")
    except SystemUserStatusError as e:
        return ResponseProvider.bad_request(error="status_error", message=str(e))
    except Exception as e:
        logger.exception("restore_system_user_view: %s", e)
        return ResponseProvider.server_error()


@require_user_context(required_permission="accounts.manage_referrals")
@require_POST
def verify_referral_view(request: ExtendedRequest, referral_id: str) -> JsonResponse:
    try:
        referral = Referral.objects.select_related("system", "referrer", "referred").get(id=referral_id)
        referral = referral_service.verify_referral(referral)
        return ResponseProvider.success(**_referral_payload(referral))
    except Referral.DoesNotExist:
        return ResponseProvider.not_found(error="not_found", message="Referral not found.")
    except ReferralServiceError as e:
        return ResponseProvider.bad_request(error="referral_error", message=str(e))
    except Exception as e:
        logger.exception("verify_referral_view: %s", e)
        return ResponseProvider.server_error()


@require_user_context(required_permission="accounts.manage_referrals")
@require_POST
def reward_referral_view(request: ExtendedRequest, referral_id: str) -> JsonResponse:
    try:
        referral = Referral.objects.select_related("system", "referrer", "referred").get(id=referral_id)
        referral = referral_service.reward_referral(referral)
        return ResponseProvider.success(**_referral_payload(referral))
    except Referral.DoesNotExist:
        return ResponseProvider.not_found(error="not_found", message="Referral not found.")
    except ReferralServiceError as e:
        return ResponseProvider.bad_request(error="referral_error", message=str(e))
    except Exception as e:
        logger.exception("reward_referral_view: %s", e)
        return ResponseProvider.server_error()


@require_user_context(required_permission="accounts.manage_referrals")
@require_POST
def reward_referrer_referrals_view(request: ExtendedRequest, system_user_id: str) -> JsonResponse:
    try:
        referrer = SystemUser.objects.select_related("system").get(id=system_user_id)
        rewarded = referral_service.reward_referrals(referrer=referrer, referral_ids=request.data.get("referral_ids"))
        rewarded_ids = [str(referral.id) for referral in rewarded]
        total_amount = referrer.system.referral_reward_amount * len(rewarded)
        return ResponseProvider.success(
            rewarded_referral_ids=rewarded_ids,
            rewarded_count=len(rewarded_ids),
            total_amount=str(total_amount),
        )
    except SystemUser.DoesNotExist:
        return ResponseProvider.not_found(error="not_found", message="System user not found.")
    except ReferralServiceError as e:
        return ResponseProvider.bad_request(error="referral_error", message=str(e))
    except Exception as e:
        logger.exception("reward_referrer_referrals_view: %s", e)
        return ResponseProvider.server_error()
