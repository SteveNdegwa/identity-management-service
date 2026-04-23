import logging
from typing import Optional

from django.http import JsonResponse
from django.views.decorators.http import require_POST, require_GET, require_http_methods

from accounts.services.account_service import (
    AccountService,
    LinkAccountRequired,
    RegistrationClosedError,
    IdentifierConflictError,
    SelfRegistrationError,
    ClaimError,
    InvalidClaimTokenError,
    ClaimExpiredError,
    SystemUserStatusError, ManageIdentifierError, ProvisionSystemUserError,
)
from accounts.models import SystemUser, SystemUserStatus, User, UserIdentifier
from permissions.models import Role
from systems.models import System
from base.models import Country
from organizations.models import Organization
from utils.decorators import sso_session_required, user_login_required
from utils.extended_request import ExtendedRequest
from utils.response_provider import ResponseProvider

logger = logging.getLogger(__name__)
account_service = AccountService()


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


def _profile_fields(data: dict) -> dict:
    return {
        "first_name": data.get("first_name", ""),
        "last_name": data.get("last_name", ""),
        "middle_name": data.get("middle_name", ""),
        "display_name": data.get("display_name", ""),
        "date_of_birth": data.get("date_of_birth"),
        "gender": data.get("gender", ""),
    }


def _system_user_payload(su: SystemUser) -> dict:
    return {
        "system_user_id": str(su.id),
        "user_id": str(su.user_id) if su.user_id else None,
        "system": su.system.name,
        "organization": su.organization.name if su.organization_id else None,
        "country": su.country.code,
        "role": su.role.name,
        "status": su.status,
        "first_name": su.first_name,
        "last_name": su.last_name,
        "display_name": su.display_name,
        "profile_photo_url": su.profile_photo_url,
    }


def _identifier_payload(ident: UserIdentifier) -> dict:
    return {
        "id": str(ident.id),
        "type": ident.identifier_type,
        "value": ident.value,
        "is_primary": ident.is_primary,
        "is_verified": ident.is_verified,
        "verified_at": ident.verified_at.isoformat() if ident.verified_at else None,
    }


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

        country = _get_country(data)
        org = _get_organization(data)

        user, system_user = account_service.self_registration(
            system=system,
            role=role,
            primary_country=country,
            organization=org,
            ip_address=request.client_ip,
            **_profile_fields(data),
            email=data.get("email"),
            phone_number=data.get("phone_number"),
            username=data.get("username"),
            national_id=data.get("national_id"),
            password=data.get("password"),
            pin=data.get("pin"),
        )
        return ResponseProvider.success(
            user_id=str(user.id),
            system_user_id=str(system_user.id),
        )
    except LinkAccountRequired as e:
        return JsonResponse({
            "success": False,
            "link_required": True,
            "matched_on": e.matched_on,
            "existing_user_id": str(e.existing_user.id),
        }, status=409)
    except (RegistrationClosedError, IdentifierConflictError, SelfRegistrationError) as e:
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
            existing_user = User.objects.get(
                id=data["existing_user_id"],
                realm=system.realm
            )
        except (User.DoesNotExist, KeyError):
            return ResponseProvider.bad_request(
                error="invalid_user",
                message="User not found."
            )

        country = _get_country(data)
        org = _get_organization(data)

        user, system_user = account_service.self_registration_link(
            existing_user=existing_user,
            system=system,
            role=role,
            primary_country=country,
            organization=org,
            ip_address=request.client_ip,
            **_profile_fields(data),
            email=data.get("email"),
            phone_number=data.get("phone_number"),
            username=data.get("username"),
            national_id=data.get("national_id"),
        )
        return ResponseProvider.success(
            user_id=str(user.id),
            system_user_id=str(system_user.id),
        )
    except (SelfRegistrationError, IdentifierConflictError) as e:
        return ResponseProvider.bad_request(
            error="registration_error",
            message=str(e)
        )
    except Exception as e:
        logger.exception("register_link_view: %s", e)
        return ResponseProvider.server_error()


@require_GET
def claim_inspect_view(request: ExtendedRequest) -> JsonResponse:
    try:
        lookup_id = request.GET.get("lookup_id", "")
        raw_token = request.GET.get("token", "")

        if not lookup_id or not raw_token:
            return ResponseProvider.bad_request(
                error="missing_params",
                message="lookup_id and token are required."
            )

        payload = account_service.inspect_claim(
            lookup_id=lookup_id,
            raw_token=raw_token
        )
        return ResponseProvider.success(**payload)
    except (InvalidClaimTokenError, ClaimExpiredError, ClaimError) as e:
        return ResponseProvider.bad_request(
            error="invalid_claim",
            message=str(e)
        )
    except Exception as e:
        logger.exception("claim_inspect_view: %s", e)
        return ResponseProvider.server_error()


@require_POST
def claim_view(request: ExtendedRequest) -> JsonResponse:
    try:
        data = request.data
        lookup_id = data.get("lookup_id", "")
        raw_token = data.get("token", "")

        if not lookup_id or not raw_token:
            return ResponseProvider.bad_request(
                error="missing_params",
                message="lookup_id and token are required."
            )

        su = account_service.claim_user(
            claim_token_lookup_id=lookup_id,
            claim_token=raw_token,
            claim_action=data.get("claim_action", "link"),
            password=data.get("password"),
            pin=data.get("pin"),
            email=data.get("email"),
            phone=data.get("phone"),
            national_id=data.get("national_id"),
            username=data.get("username"),
        )
        return ResponseProvider.success(
            system_user_id=str(su.id),
            user_id=str(su.user_id),
            status=su.status,
        )
    except (InvalidClaimTokenError, ClaimExpiredError, SystemUserStatusError, ClaimError) as e:
        return ResponseProvider.bad_request(
            error="claim_error",
            message=str(e)
        )
    except Exception as e:
        logger.exception("claim_view: %s", e)
        return ResponseProvider.server_error()


@sso_session_required
@require_GET
def me_view(request: ExtendedRequest) -> JsonResponse:
    try:
        system = _get_system(request.GET)
        if not system:
            return ResponseProvider.bad_request(
                error="invalid_system",
                message="System not found or inactive."
            )

        su = SystemUser.objects.select_related("system", "organization", "country", "role").filter(
            user=request.sso_session.user,
            system=system,
            status=SystemUserStatus.ACTIVE,
        ).first()
        if not su:
            return ResponseProvider.not_found(
                error="not_found",
                message="No active membership found in this system."
            )

        return ResponseProvider.success(**_system_user_payload(su))
    except Exception as e:
        logger.exception("me_view: %s", e)
        return ResponseProvider.server_error()


@sso_session_required
@require_http_methods(["PATCH"])
def me_update_view(request: ExtendedRequest) -> JsonResponse:
    try:
        data = request.data
        system = _get_system(data)
        if not system:
            return ResponseProvider.bad_request(
                error="invalid_system",
                message="system_id is required."
            )

        su = SystemUser.objects.filter(
            user=request.sso_session.user,
            system=system,
            status=SystemUserStatus.ACTIVE,
        ).first()
        if not su:
            return ResponseProvider.not_found(
                error="not_found",
                message="No active membership found in this system."
            )

        updatable = {
            "first_name", "last_name", "middle_name", "display_name",
            "date_of_birth", "gender", "profile_photo_url", "metadata", "external_ref",
        }
        fields = {k: v for k, v in data.items() if k in updatable}
        su = account_service.update_profile(
            system_user=su,
            updated_by=request.sso_session.user,
            **fields,
        )
        return ResponseProvider.success(**_system_user_payload(su))
    except Exception as e:
        logger.exception("me_update_view: %s", e)
        return ResponseProvider.server_error()


@sso_session_required
@require_GET
def identifier_list_view(request: ExtendedRequest) -> JsonResponse:
    try:
        identifiers = request.sso_session.user.identifiers.all()
        return ResponseProvider.success(identifiers=[_identifier_payload(i) for i in identifiers])
    except Exception as e:
        logger.exception("identifier_list_view: %s", e)
        return ResponseProvider.server_error()


@sso_session_required
@require_POST
def identifier_add_view(request: ExtendedRequest) -> JsonResponse:
    try:
        data = request.data
        identifier = account_service.add_identifier(
            user=request.sso_session.user,
            identifier_type=data["identifier_type"],
            value=data["value"],
            require_verification=data.get("require_verification", True),
            ip_address=request.client_ip,
        )
        return ResponseProvider.success(**_identifier_payload(identifier))
    except IdentifierConflictError as e:
        return ResponseProvider.bad_request(
            error="identifier_error",
            message=str(e)
        )
    except Exception as e:
        logger.exception("identifier_add_view: %s", e)
        return ResponseProvider.server_error()


@sso_session_required
@require_POST
def identifier_verify_view(request: ExtendedRequest, identifier_id: str) -> JsonResponse:
    try:
        identifier = UserIdentifier.objects.get(
            id=identifier_id,
            user=request.sso_session.user
        )
        identifier = account_service.verify_identifier(
            identifier=identifier,
            ip_address=request.client_ip
        )
        return ResponseProvider.success(**_identifier_payload(identifier))
    except UserIdentifier.DoesNotExist:
        return ResponseProvider.not_found(
            error="not_found",
            message="Identifier not found."
        )
    except Exception as e:
        logger.exception("identifier_verify_view: %s", e)
        return ResponseProvider.server_error()


@sso_session_required
@require_POST
def identifier_promote_view(request: ExtendedRequest, identifier_id: str) -> JsonResponse:
    try:
        identifier = UserIdentifier.objects.get(
            id=identifier_id,
            user=request.sso_session.user
        )
        identifier = account_service.promote_identifier_to_primary(
            new_identifier=identifier,
            ip_address=request.client_ip
        )
        return ResponseProvider.success(**_identifier_payload(identifier))
    except UserIdentifier.DoesNotExist:
        return ResponseProvider.not_found(
            error="not_found",
            message="Identifier not found."
        )
    except ManageIdentifierError as e:
        return ResponseProvider.bad_request(
            error="manage_identifier_error",
            message=str(e)
        )
    except Exception as e:
        logger.exception("identifier_promote_view: %s", e)
        return ResponseProvider.server_error()


@sso_session_required
@require_http_methods(["DELETE"])
def identifier_remove_view(request: ExtendedRequest, identifier_id: str) -> JsonResponse:
    try:
        identifier = UserIdentifier.objects.get(
            id=identifier_id,
            user=request.sso_session.user
        )
        reason = request.data.get("reason", "user_removed")
        account_service.disassociate_identifier(
            identifier=identifier,
            reason=reason,
            disassociated_by=request.sso_session.user,
            ip_address=request.client_ip,
        )
        return ResponseProvider.success()
    except UserIdentifier.DoesNotExist:
        return ResponseProvider.not_found(
            error="not_found",
            message="Identifier not found."
        )
    except ManageIdentifierError as e:
        return ResponseProvider.bad_request(
            error="manage_identifier_error",
            message=str(e)
        )
    except Exception as e:
        logger.exception("identifier_remove_view: %s", e)
        return ResponseProvider.server_error()


@user_login_required(required_permission="accounts.provision_user")
@require_POST
def provision_system_user_view(request: ExtendedRequest) -> JsonResponse:
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

        country = _get_country(data)
        if not country:
            return ResponseProvider.bad_request(
                error="invalid_country",
                message="Country not found."
            )

        org = _get_organization(data)

        # Current actor (system user)
        actor_su = SystemUser.objects.filter(
            user=request.sso_session.user,
            system=system,
            status=SystemUserStatus.ACTIVE,
        ).first()

        if not actor_su:
            return ResponseProvider.forbidden(
                error="forbidden",
                message="You are not an active member of this system."
            )

        system_user = account_service.provision_system_user(
            provisioned_by=actor_su,
            system=system,
            country=country,
            role=role,
            organization=org,
            all_branches=data.get("all_branches", True),
            provisioning_email=data.get("email", ""),
            provisioning_phone=data.get("phone", ""),
            provisioning_national_id=data.get("national_id", ""),
            first_name=data.get("first_name", ""),
            last_name=data.get("last_name", ""),
            middle_name=data.get("middle_name", ""),
            display_name=data.get("display_name", ""),
            external_ref=data.get("external_ref", ""),
            metadata=data.get("metadata"),
        )

        return ResponseProvider.success(
            **_system_user_payload(system_user),
            message="User provisioned successfully. Invitation sent."
        )

    except ProvisionSystemUserError as e:
        return ResponseProvider.bad_request(
            error="provision_error",
            message=str(e)
        )
    except Exception as e:
        logger.exception("provision_system_user_view: %s", e)
        return ResponseProvider.server_error()


@user_login_required(required_permission="accounts.suspend_user")
@require_POST
def suspend_system_user_view(request: ExtendedRequest, system_user_id: str) -> JsonResponse:
    try:
        su = SystemUser.objects.select_related("system", "user").get(id=system_user_id)
        su = account_service.suspend_system_user(
            system_user=su,
            reason=request.data.get("reason", ""),
            suspended_by=request.sso_session.user,
            ip_address=request.client_ip,
        )
        return ResponseProvider.success(status=su.status)
    except SystemUser.DoesNotExist:
        return ResponseProvider.not_found(
            error="not_found",
            message="System user not found."
        )
    except SystemUserStatusError as e:
        return ResponseProvider.bad_request(
            error="system_user_status_error",
            message=str(e)
        )
    except Exception as e:
        logger.exception("suspend_system_user_view: %s", e)
        return ResponseProvider.server_error()


@user_login_required(required_permission="accounts.restore_user")
@require_POST
def restore_system_user_view(request: ExtendedRequest, system_user_id: str) -> JsonResponse:
    try:
        su = SystemUser.objects.select_related("system", "user").get(id=system_user_id)
        su = account_service.restore_system_user(
            system_user=su,
            restored_by=request.sso_session.user,
            ip_address=request.client_ip,
        )
        return ResponseProvider.success(status=su.status)
    except SystemUser.DoesNotExist:
        return ResponseProvider.not_found(
            error="not_found",
            message="System user not found."
        )
    except SystemUserStatusError as e:
        return ResponseProvider.bad_request(
            error="system_user_status_error",
            message=str(e)
        )
    except Exception as e:
        logger.exception("restore_system_user_view: %s", e)
        return ResponseProvider.server_error()