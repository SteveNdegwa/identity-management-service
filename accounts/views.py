import logging
from datetime import datetime
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
from accounts.services.referral_service import ReferralService, ReferralServiceError
from accounts.models import SystemUser, SystemUserStatus, User, UserIdentifier, Referral
from permissions.models import Role
from systems.models import System
from base.models import Country
from organizations.models import Organization, Branch
from utils.decorators import sso_session_required, user_login_required
from utils.extended_request import ExtendedRequest
from utils.response_provider import ResponseProvider

logger = logging.getLogger(__name__)
account_service = AccountService()
referral_service = ReferralService()


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
        "referral_code": su.referral_code,
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
            referral_code=data.get("referral_code"),
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
            referral_code=data.get("referral_code"),
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


@user_login_required
@require_GET
def me_view(request: ExtendedRequest) -> JsonResponse:
    try:
        referral_service.ensure_referral_code(request.system_user)
        return ResponseProvider.success(**_system_user_payload(request.system_user))
    except Exception as e:
        logger.exception("me_view: %s", e)
        return ResponseProvider.server_error()


@user_login_required
@require_http_methods(["PATCH"])
def me_update_view(request: ExtendedRequest) -> JsonResponse:
    try:
        data = request.data
        updatable = {
            "first_name", "last_name", "middle_name", "display_name",
            "date_of_birth", "gender", "profile_photo_url", "metadata", "external_ref",
        }
        fields = {k: v for k, v in data.items() if k in updatable}
        su = account_service.update_profile(
            system_user=request.system_user,
            updated_by=request.sso_session.user,
            **fields,
        )
        return ResponseProvider.success(**_system_user_payload(su))
    except Exception as e:
        logger.exception("me_update_view: %s", e)
        return ResponseProvider.server_error()


@user_login_required
@require_GET
def my_referrals_view(request: ExtendedRequest) -> JsonResponse:
    try:
        referral_service.ensure_referral_code(request.system_user)
        referrals_made = (
            Referral.objects
            .filter(referrer=request.system_user)
            .select_related("system", "referrer", "referred")
            .order_by("-created_at")
        )
        referral_received = (
            Referral.objects
            .filter(referred=request.system_user)
            .select_related("system", "referrer", "referred")
            .first()
        )

        return ResponseProvider.success(
            referral_code=request.system_user.referral_code,
            referral_amount=str(request.system_user.system.referral_reward_amount),
            auto_verify_referrals=request.system_user.system.auto_verify_referrals,
            referred_by=_referral_payload(referral_received) if referral_received else None,
            referrals=[_referral_payload(referral) for referral in referrals_made],
        )
    except Exception as e:
        logger.exception("my_referrals_view: %s", e)
        return ResponseProvider.server_error()


@user_login_required(required_permission="accounts.manage_referrals")
@require_GET
def referral_list_view(request: ExtendedRequest) -> JsonResponse:
    try:
        system_id = request.GET.get("system_id")
        if not system_id:
            return ResponseProvider.bad_request(
                error="missing_params",
                message="system_id is required.",
            )

        qs = (
            Referral.objects
            .filter(system_id=system_id)
            .select_related("system", "referrer", "referred")
            .order_by("-created_at")
        )

        verified = _parse_bool_query(request.GET.get("verified"))
        if verified is not None:
            qs = qs.filter(is_verified=verified)

        rewarded = _parse_bool_query(request.GET.get("rewarded"))
        if rewarded is not None:
            qs = qs.filter(is_rewarded=rewarded)

        if referrer_system_user_id := request.GET.get("referrer_system_user_id"):
            qs = qs.filter(referrer_id=referrer_system_user_id)

        if referred_system_user_id := request.GET.get("referred_system_user_id"):
            qs = qs.filter(referred_id=referred_system_user_id)

        if referral_code := request.GET.get("referral_code"):
            qs = qs.filter(referral_code__iexact=referral_code.strip())

        created_from = _parse_datetime_query(request.GET.get("created_from"))
        if created_from:
            qs = qs.filter(created_at__gte=created_from)

        created_to = _parse_datetime_query(request.GET.get("created_to"))
        if created_to:
            qs = qs.filter(created_at__lte=created_to)

        verified_from = _parse_datetime_query(request.GET.get("verified_from"))
        if verified_from:
            qs = qs.filter(verified_at__gte=verified_from)

        verified_to = _parse_datetime_query(request.GET.get("verified_to"))
        if verified_to:
            qs = qs.filter(verified_at__lte=verified_to)

        rewarded_from = _parse_datetime_query(request.GET.get("rewarded_from"))
        if rewarded_from:
            qs = qs.filter(rewarded_at__gte=rewarded_from)

        rewarded_to = _parse_datetime_query(request.GET.get("rewarded_to"))
        if rewarded_to:
            qs = qs.filter(rewarded_at__lte=rewarded_to)

        return ResponseProvider.success(
            referrals=[_referral_payload(referral) for referral in qs]
        )
    except ValueError:
        return ResponseProvider.bad_request(
            error="invalid_datetime",
            message="Date filters must be valid ISO datetimes.",
        )
    except Exception as e:
        logger.exception("referral_list_view: %s", e)
        return ResponseProvider.server_error()


@user_login_required
@require_POST
def attach_my_referral_view(request: ExtendedRequest) -> JsonResponse:
    try:
        referral = referral_service.attach_referral(
            referred=request.system_user,
            referral_code=request.data.get("referral_code", ""),
        )
        referral = Referral.objects.select_related("system", "referrer", "referred").get(id=referral.id)
        return ResponseProvider.success(**_referral_payload(referral))
    except ReferralServiceError as e:
        return ResponseProvider.bad_request(
            error="referral_error",
            message=str(e),
        )
    except Exception as e:
        logger.exception("attach_my_referral_view: %s", e)
        return ResponseProvider.server_error()


@user_login_required(required_permission="accounts.manage_referrals")
@require_POST
def verify_referral_view(request: ExtendedRequest, referral_id: str) -> JsonResponse:
    try:
        referral = Referral.objects.select_related("system", "referrer", "referred").get(id=referral_id)
        referral = referral_service.verify_referral(referral)
        return ResponseProvider.success(**_referral_payload(referral))
    except Referral.DoesNotExist:
        return ResponseProvider.not_found(
            error="not_found",
            message="Referral not found.",
        )
    except ReferralServiceError as e:
        return ResponseProvider.bad_request(
            error="referral_error",
            message=str(e),
        )
    except Exception as e:
        logger.exception("verify_referral_view: %s", e)
        return ResponseProvider.server_error()


@user_login_required(required_permission="accounts.manage_referrals")
@require_POST
def reward_referral_view(request: ExtendedRequest, referral_id: str) -> JsonResponse:
    try:
        referral = Referral.objects.select_related("system", "referrer", "referred").get(id=referral_id)
        referral = referral_service.reward_referral(referral)
        return ResponseProvider.success(**_referral_payload(referral))
    except Referral.DoesNotExist:
        return ResponseProvider.not_found(
            error="not_found",
            message="Referral not found.",
        )
    except ReferralServiceError as e:
        return ResponseProvider.bad_request(
            error="referral_error",
            message=str(e),
        )
    except Exception as e:
        logger.exception("reward_referral_view: %s", e)
        return ResponseProvider.server_error()


@user_login_required(required_permission="accounts.manage_referrals")
@require_POST
def reward_referrer_referrals_view(request: ExtendedRequest, system_user_id: str) -> JsonResponse:
    try:
        referrer = SystemUser.objects.select_related("system").get(id=system_user_id)
        rewarded = referral_service.reward_referrals(
            referrer=referrer,
            referral_ids=request.data.get("referral_ids"),
        )
        rewarded_ids = [str(referral.id) for referral in rewarded]
        total_amount = referrer.system.referral_reward_amount * len(rewarded)
        return ResponseProvider.success(
            rewarded_referral_ids=rewarded_ids,
            rewarded_count=len(rewarded_ids),
            total_amount=str(total_amount),
        )
    except SystemUser.DoesNotExist:
        return ResponseProvider.not_found(
            error="not_found",
            message="System user not found.",
        )
    except ReferralServiceError as e:
        return ResponseProvider.bad_request(
            error="referral_error",
            message=str(e),
        )
    except Exception as e:
        logger.exception("reward_referrer_referrals_view: %s", e)
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

        branches = []
        for branch_id in data.get("branch_ids", []):
            try:
                branches.append(Branch.objects.get(id=branch_id, organization=org))
            except Branch.DoesNotExist:
                return ResponseProvider.bad_request(
                    error="invalid_branch",
                    message=f"Branch with id {branch_id} not found.''"
                )

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
            branch_grants=branches,
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
