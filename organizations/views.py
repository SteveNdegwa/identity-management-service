import logging
from typing import Optional

from django.http import JsonResponse
from django.views.decorators.http import require_POST, require_http_methods, require_GET

from base.models import Country
from organizations.models import (
    OrganizationOnboarding,
    OnboardingDocument,
    DocumentRequest,
    DocumentType,
    Organization,
    OrganizationCountry,
    Branch,
    OrganizationSettings,
)
from systems.models import System
from utils.decorators import user_login_required
from utils.extended_request import ExtendedRequest
from utils.response_provider import ResponseProvider

from .services.onboarding_service import OnboardingService, OnboardingError
from .services.organization_service import OrganizationService, OrganizationServiceError

logger = logging.getLogger(__name__)
organization_service = OrganizationService()
onboarding_service = OnboardingService()


def _get_system(data: dict) -> Optional[System]:
    sid = data.get("system_id") or data.get("system")
    if not sid:
        return None
    try:
        return System.objects.get(id=sid, is_active=True)
    except System.DoesNotExist:
        return None


def _get_organization(organization_id: str) -> Optional[Organization]:
    try:
        return Organization.objects.select_related(
            "system", "onboarding"
        ).get(id=organization_id)
    except Organization.DoesNotExist:
        return None


def _get_org_country(org_country_id: str) -> Optional[OrganizationCountry]:
    try:
        return OrganizationCountry.objects.select_related(
            "organization", "country"
        ).get(id=org_country_id)
    except OrganizationCountry.DoesNotExist:
        return None


def _get_branch(branch_id: str) -> Optional[Branch]:
    try:
        return Branch.objects.select_related(
            "organization", "country", "parent"
        ).get(id=branch_id)
    except Branch.DoesNotExist:
        return None


def _get_country(data: dict) -> Optional[Country]:
    cid = data.get("country_id") or data.get("country")
    if not cid:
        return None
    try:
        return Country.objects.get(id=cid)
    except Country.DoesNotExist:
        return None


def _get_onboarding(onboarding_id: str) -> Optional[OrganizationOnboarding]:
    try:
        return OrganizationOnboarding.objects.select_related(
            "system", "country", "contact_system_user", "created_organization"
        ).get(id=onboarding_id)
    except OrganizationOnboarding.DoesNotExist:
        return None


def _get_document(document_id: str) -> Optional[OnboardingDocument]:
    try:
        return OnboardingDocument.objects.select_related(
            "onboarding", "uploaded_by"
        ).get(id=document_id)
    except OnboardingDocument.DoesNotExist:
        return None


def _organization_payload(org: Organization) -> dict:
    return {
        "id": str(org.id),
        "name": org.name,
        "slug": org.slug,
        "description": org.description,
        "logo_url": org.logo_url,
        "website": org.website,
        "is_active": org.is_active,
        "verified": org.verified,
        "verified_at": org.verified_at.isoformat() if org.verified_at else None,
        "system": org.system.name,
        "created_at": org.created_at.isoformat(),
    }


def _org_country_payload(oc: OrganizationCountry) -> dict:
    return {
        "id": str(oc.id),
        "country_code": oc.country.code,
        "country_name": oc.country.name,
        "registration_number": oc.registration_number,
        "tax_id": oc.tax_id,
        "is_active": oc.is_active,
        "activated_at": oc.activated_at.isoformat(),
    }


def _branch_payload(branch: Branch) -> dict:
    return {
        "id": str(branch.id),
        "name": branch.name,
        "code": branch.code,
        "country": branch.country.code,
        "parent_id": str(branch.parent_id) if branch.parent_id else None,
        "is_active": branch.is_active,
        "metadata": branch.metadata,
        "created_at": branch.created_at.isoformat(),
    }


def _setting_payload(s: OrganizationSettings) -> dict:
    return {
        "id": str(s.id),
        "key": s.key,
        "value": "" if s.is_secret else s.value,
        "value_type": s.value_type,
        "description": s.description,
        "is_secret": s.is_secret,
        "updated_by": s.updated_by.full_name if s.updated_by else None,
    }


def _onboarding_payload(onboarding: OrganizationOnboarding) -> dict:
    return {
        "onboarding_id": str(onboarding.id),
        "system_id": str(onboarding.system_id),
        "system_name": onboarding.system.name,
        "country_code": onboarding.country.code,
        "country_name": onboarding.country.name,
        "status": onboarding.status,
        "legal_name": onboarding.legal_name,
        "trading_name": onboarding.trading_name,
        "registration_number": onboarding.registration_number,
        "tax_id": onboarding.tax_id,
        "address": onboarding.address,
        "contact_email": onboarding.contact_email,
        "contact_phone": onboarding.contact_phone,
        "website": onboarding.website,
        "description": onboarding.description,
        "metadata": onboarding.metadata,
        "submitted_at": onboarding.submitted_at.isoformat() if onboarding.submitted_at else None,
        "reviewed_at": onboarding.reviewed_at.isoformat() if onboarding.reviewed_at else None,
        "completed_at": onboarding.completed_at.isoformat() if onboarding.completed_at else None,
        "created_organization_id": str(onboarding.created_organization_id)
        if onboarding.created_organization_id else None,
        "applicant_notes": onboarding.applicant_notes,
        "internal_notes": onboarding.internal_notes,
        "documents": [
            _document_payload(doc)
            for doc in onboarding.documents.all().order_by("-created_at")
        ],
    }


def _document_payload(doc: OnboardingDocument) -> dict:
    return {
        "document_id": str(doc.id),
        "document_type": doc.document_type,
        "label": doc.label,
        "status": doc.status,
        "file_name": doc.file_name,
        "file_size": doc.file_size,
        "mime_type": doc.mime_type,
        "uploaded_by": doc.uploaded_by.full_name if doc.uploaded_by else None,
        "uploaded_at": doc.created_at.isoformat() if hasattr(doc, "created_at") else None,
        "reviewed_at": doc.reviewed_at.isoformat() if doc.reviewed_at else None,
        "review_notes": doc.review_notes,
        "expires_at": doc.expires_at.isoformat() if doc.expires_at else None,
    }


def _document_request_payload(req: DocumentRequest) -> dict:
    return {
        "request_id": str(req.id),
        "document_type": req.document_type,
        "label": req.label,
        "reason": req.reason,
        "requested_by": req.requested_by.full_name if req.requested_by else None,
        "requested_at": req.created_at.isoformat() if hasattr(req, "created_at") else None,
        "deadline": req.deadline.isoformat() if req.deadline else None,
        "fulfilled_at": req.fulfilled_at.isoformat() if req.fulfilled_at else None,
    }


@user_login_required(required_permission="organization.view")
@require_GET
def organization_detail_view(request: ExtendedRequest, organization_id: str) -> JsonResponse:
    try:
        org = _get_organization(organization_id)
        if not org:
            return ResponseProvider.not_found(
                error="not_found",
                message="Organization not found."
            )

        return ResponseProvider.success(**_organization_payload(org))

    except Exception as e:
        logger.exception("organization_detail_view: %s", e)
        return ResponseProvider.server_error()


@user_login_required(required_permission="organization.view")
@require_GET
def organization_list_view(request: ExtendedRequest) -> JsonResponse:
    try:
        system_id = request.GET.get("system_id")
        if not system_id:
            return ResponseProvider.bad_request(
                error="missing_params",
                message="system_id is required."
            )

        qs = (
            Organization.objects
            .filter(system_id=system_id)
            .select_related("system")
            .order_by("name")
        )

        if is_active := request.GET.get("is_active"):
            qs = qs.filter(is_active=is_active.lower() == "true")
        if verified := request.GET.get("verified"):
            qs = qs.filter(verified=verified.lower() == "true")

        return ResponseProvider.success(
            organizations=[_organization_payload(o) for o in qs]
        )

    except Exception as e:
        logger.exception("organization_list_view: %s", e)
        return ResponseProvider.server_error()


@user_login_required(required_permission="organization.update")
@require_http_methods(["PATCH"])
def organization_update_view(request: ExtendedRequest, organization_id: str) -> JsonResponse:
    org = _get_organization(organization_id)
    if not org:
        return ResponseProvider.not_found(
            error="not_found",
            message="Organization not found."
        )
    try:
        data = request.data
        org = organization_service.update_organization(
            organization=org,
            performed_by=request.system_user,
            name=data.get("name"),
            description=data.get("description"),
            logo_url=data.get("logo_url"),
            website=data.get("website"),
        )

        return ResponseProvider.success(**_organization_payload(org))

    except OrganizationServiceError as e:
        return ResponseProvider.bad_request(
            error="organization_management_error",
            message=str(e)
        )
    except Exception as e:
        logger.exception("organization_update_view: %s", e)
        return ResponseProvider.server_error()


@user_login_required(required_permission="organization.deactivate")
@require_POST
def organization_deactivate_view(request: ExtendedRequest, organization_id: str) -> JsonResponse:
    org = _get_organization(organization_id)
    if not org:
        return ResponseProvider.not_found(
            error="not_found",
            message="Organization not found."
        )

    try:
        org = organization_service.deactivate_organization(
            organization=org,
            performed_by=request.system_user
        )

        return ResponseProvider.success(**_organization_payload(org))

    except OrganizationServiceError as e:
        return ResponseProvider.bad_request(
            error="organization_management_error",
            message=str(e)
        )
    except Exception as e:
        logger.exception("organization_deactivate_view: %s", e)
        return ResponseProvider.server_error()


@user_login_required(required_permission="organization.deactivate")
@require_POST
def organization_reactivate_view(request: ExtendedRequest, organization_id: str) -> JsonResponse:
    org = _get_organization(organization_id)
    if not org:
        return ResponseProvider.not_found(
            error="not_found",
            message="Organization not found."
        )

    try:
        org = organization_service.reactivate_organization(
            organization=org,
            performed_by=request.system_user
        )

        return ResponseProvider.success(**_organization_payload(org))

    except OrganizationServiceError as e:
        return ResponseProvider.bad_request(
            error="organization_management_error",
            message=str(e)
        )
    except Exception as e:
        logger.exception("organization_reactivate_view: %s", e)
        return ResponseProvider.server_error()


@user_login_required(required_permission="organization.view")
@require_GET
def org_country_list_view(request: ExtendedRequest, organization_id: str) -> JsonResponse:
    try:
        org = _get_organization(organization_id)
        if not org:
            return ResponseProvider.not_found(
                error="not_found",
                message="Organization not found."
            )

        countries = (
            org.organization_countries
            .select_related("country")
            .order_by("country__name")
        )

        return ResponseProvider.success(
            countries=[_org_country_payload(c) for c in countries]
        )

    except Exception as e:
        logger.exception("org_country_list_view: %s", e)
        return ResponseProvider.server_error()


@user_login_required(required_permission="organization.manage_countries")
@require_POST
def org_country_add_view(request: ExtendedRequest, organization_id: str) -> JsonResponse:
    org = _get_organization(organization_id)
    if not org:
        return ResponseProvider.not_found(
            error="not_found",
            message="Organization not found."
        )

    try:
        data = request.data
        country = _get_country(data)
        if not country:
            return ResponseProvider.bad_request(
                error="invalid_country",
                message="Country not found."
            )

        oc = organization_service.add_country(
            organization=org,
            country=country,
            performed_by=request.system_user,
            registration_number=data.get("registration_number", ""),
            tax_id=data.get("tax_id", ""),
        )

        return ResponseProvider.success(**_org_country_payload(oc))

    except OrganizationServiceError as e:
        return ResponseProvider.bad_request(
            error="organization_management_error",
            message=str(e)
        )
    except Exception as e:
        logger.exception("org_country_add_view: %s", e)
        return ResponseProvider.server_error()


@user_login_required(required_permission="organization.manage_countries")
@require_http_methods(["PATCH"])
def org_country_update_view(request: ExtendedRequest, org_country_id: str) -> JsonResponse:
    oc = _get_org_country(org_country_id)
    if not oc:
        return ResponseProvider.not_found(
            error="not_found",
            message="Organization country not found."
        )

    try:
        data = request.data
        oc = organization_service.update_country(
            org_country=oc,
            performed_by=request.system_user,
            registration_number=data.get("registration_number"),
            tax_id=data.get("tax_id"),
        )

        return ResponseProvider.success(**_org_country_payload(oc))

    except OrganizationServiceError as e:
        return ResponseProvider.bad_request(
            error="organization_management_error",
            message=str(e)
        )
    except Exception as e:
        logger.exception("org_country_update_view: %s", e)
        return ResponseProvider.server_error()


@user_login_required(required_permission="organization.manage_countries")
@require_POST
def org_country_deactivate_view(request: ExtendedRequest, org_country_id: str) -> JsonResponse:
    oc = _get_org_country(org_country_id)
    if not oc:
        return ResponseProvider.not_found(
            error="not_found",
            message="Organization country not found."
        )

    try:
        oc = organization_service.deactivate_country(
            org_country=oc,
            performed_by=request.system_user
        )

        return ResponseProvider.success(**_org_country_payload(oc))

    except OrganizationServiceError as e:
        return ResponseProvider.bad_request(
            error="organization_management_error",
            message=str(e)
        )
    except Exception as e:
        logger.exception("org_country_deactivate_view: %s", e)
        return ResponseProvider.server_error()


@user_login_required(required_permission="organization.view")
@require_GET
def branch_list_view(request: ExtendedRequest, organization_id: str) -> JsonResponse:
    try:
        org = _get_organization(organization_id)
        if not org:
            return ResponseProvider.not_found(
                error="not_found",
                message="Organization not found."
            )

        qs = (
            Branch.objects
            .filter(organization=org)
            .select_related("country", "parent")
            .order_by("country__code", "name")
        )

        if country_id := request.GET.get("country_id"):
            qs = qs.filter(country_id=country_id)
        if is_active := request.GET.get("is_active"):
            qs = qs.filter(is_active=is_active.lower() == "true")
        if parent_id := request.GET.get("parent_id"):
            qs = qs.filter(parent_id=parent_id)
        if request.GET.get("root_only") == "true":
            qs = qs.filter(parent__isnull=True)

        return ResponseProvider.success(
            branches=[_branch_payload(b) for b in qs]
        )

    except Exception as e:
        logger.exception("branch_list_view: %s", e)
        return ResponseProvider.server_error()


@user_login_required(required_permission="organization.view")
@require_GET
def branch_detail_view(request: ExtendedRequest, branch_id: str) -> JsonResponse:
    try:
        branch = _get_branch(branch_id)
        if not branch:
            return ResponseProvider.not_found(
                error="not_found",
                message="Branch not found."
            )

        return ResponseProvider.success(**_branch_payload(branch))

    except Exception as e:
        logger.exception("branch_detail_view: %s", e)
        return ResponseProvider.server_error()


@user_login_required(required_permission="organization.manage_branches")
@require_POST
def branch_create_view(request: ExtendedRequest, organization_id: str) -> JsonResponse:
    org = _get_organization(organization_id)
    if not org:
        return ResponseProvider.not_found(
            error="not_found",
            message="Organization not found."
        )

    try:
        data = request.data
        country = _get_country(data)
        if not country:
            return ResponseProvider.bad_request(
                error="invalid_country",
                message="country_id is required."
            )

        parent = None
        if parent_id := data.get("parent_id"):
            parent = _get_branch(parent_id)
            if not parent:
                return ResponseProvider.bad_request(
                    error="invalid_parent",
                    message="Parent branch not found."
                )

        branch = organization_service.create_branch(
            organization=org,
            country=country,
            performed_by=request.system_user,
            name=data.get("name", ""),
            code=data.get("code", ""),
            parent=parent,
            metadata=data.get("metadata"),
        )

        return ResponseProvider.success(**_branch_payload(branch))

    except OrganizationServiceError as e:
        return ResponseProvider.bad_request(
            error="organization_management_error",
            message=str(e)
        )
    except Exception as e:
        logger.exception("branch_create_view: %s", e)
        return ResponseProvider.server_error()


@user_login_required(required_permission="organization.manage_branches")
@require_http_methods(["PATCH"])
def branch_update_view(request: ExtendedRequest, branch_id: str) -> JsonResponse:
    branch = _get_branch(branch_id)
    if not branch:
        return ResponseProvider.not_found(
            error="not_found",
            message="Branch not found."
        )

    try:
        data = request.data

        parent = None
        if "parent_id" in data:
            raw_parent_id = data["parent_id"]
            if raw_parent_id:
                parent = _get_branch(raw_parent_id)
                if not parent:
                    return ResponseProvider.bad_request(
                        error="invalid_parent",
                        message="Parent branch not found."
                    )

        branch = organization_service.update_branch(
            branch=branch,
            performed_by=request.system_user,
            name=data.get("name"),
            code=data.get("code"),
            parent=parent,
            metadata=data.get("metadata"),
        )

        return ResponseProvider.success(**_branch_payload(branch))

    except OrganizationServiceError as e:
        return ResponseProvider.bad_request(
            error="organization_management_error",
            message=str(e)
        )
    except Exception as e:
        logger.exception("branch_update_view: %s", e)
        return ResponseProvider.server_error()


@user_login_required(required_permission="organization.manage_branches")
@require_POST
def branch_deactivate_view(request: ExtendedRequest, branch_id: str) -> JsonResponse:
    branch = _get_branch(branch_id)
    if not branch:
        return ResponseProvider.not_found(
            error="not_found",
            message="Branch not found."
        )

    try:
        branch = organization_service.deactivate_branch(
            branch=branch,
            performed_by=request.system_user
        )

        return ResponseProvider.success(**_branch_payload(branch))

    except OrganizationServiceError as e:
        return ResponseProvider.bad_request(
            error="organization_management_error",
            message=str(e)
        )
    except Exception as e:
        logger.exception("branch_deactivate_view: %s", e)
        return ResponseProvider.server_error()


@user_login_required(required_permission="organization.manage_branches")
@require_POST
def branch_reactivate_view(request: ExtendedRequest, branch_id: str) -> JsonResponse:
    branch = _get_branch(branch_id)
    if not branch:
        return ResponseProvider.not_found(
            error="not_found",
            message="Branch not found."
        )

    try:
        branch = organization_service.reactivate_branch(
            branch=branch,
            performed_by=request.system_user
        )

        return ResponseProvider.success(**_branch_payload(branch))

    except OrganizationServiceError as e:
        return ResponseProvider.bad_request(
            error="organization_error",
            message=str(e)
        )
    except Exception as e:
        logger.exception("branch_reactivate_view: %s", e)
        return ResponseProvider.server_error()


@user_login_required(required_permission="organization.view_settings")
@require_GET
def settings_list_view(request: ExtendedRequest, organization_id: str) -> JsonResponse:
    try:
        org = _get_organization(organization_id)
        if not org:
            return ResponseProvider.not_found(
                error="not_found",
                message="Organization not found."
            )

        settings = org.settings.select_related("updated_by").order_by("key")

        return ResponseProvider.success(
            settings=[_setting_payload(s) for s in settings]
        )

    except Exception as e:
        logger.exception("settings_list_view: %s", e)
        return ResponseProvider.server_error()


@user_login_required(required_permission="organization.manage_settings")
@require_POST
def settings_set_view(request: ExtendedRequest, organization_id: str) -> JsonResponse:
    org = _get_organization(organization_id)
    if not org:
        return ResponseProvider.not_found(
            error="not_found",
            message="Organization not found."
        )

    try:
        data = request.data
        setting = organization_service.set_setting(
            organization=org,
            performed_by=request.system_user,
            key=data.get("key", ""),
            value=data.get("value", ""),
            value_type=data.get("value_type", OrganizationSettings.ValueType.STRING),
            description=data.get("description", ""),
            is_secret=bool(data.get("is_secret", False)),
        )

        return ResponseProvider.success(**_setting_payload(setting))

    except OrganizationServiceError as e:
        return ResponseProvider.bad_request(
            error="organization_service_error",
            message=str(e)
        )
    except Exception as e:
        logger.exception("settings_set_view: %s", e)
        return ResponseProvider.server_error()


@user_login_required(required_permission="organization.manage_settings")
@require_http_methods(["DELETE"])
def settings_delete_view(request: ExtendedRequest, organization_id: str, key: str) -> JsonResponse:
    org = _get_organization(organization_id)
    if not org:
        return ResponseProvider.not_found(
            error="not_found",
            message="Organization not found."
        )

    try:
        organization_service.delete_setting(
            organization=org,
            performed_by=request.system_user,
            key=key
        )

        return ResponseProvider.success()

    except OrganizationServiceError as e:
        return ResponseProvider.bad_request(
            error="organization_service_error",
            message=str(e)
        )
    except Exception as e:
        logger.exception("settings_delete_view: %s", e)
        return ResponseProvider.server_error()


@user_login_required(required_permission="onboarding.create")
@require_POST
def onboarding_create_view(request: ExtendedRequest) -> JsonResponse:
    try:
        data = request.data
        files = request.FILES

        system = _get_system(data)
        if not system:
            return ResponseProvider.bad_request(
                error="invalid_system",
                message="System not found or inactive."
            )

        country = _get_country(data)
        if not country:
            return ResponseProvider.bad_request(
                error="invalid_country",
                message="Country not found."
            )

        onboarding = onboarding_service.create_application(
            system=system,
            country=country,
            contact_system_user=request.system_user,
            legal_name=data.get("legal_name", ""),
            trading_name=data.get("trading_name", ""),
            registration_number=data.get("registration_number", ""),
            tax_id=data.get("tax_id", ""),
            address=data.get("address", ""),
            contact_email=data.get("contact_email", ""),
            contact_phone=data.get("contact_phone", ""),
            website=data.get("website", ""),
            description=data.get("description", ""),
            metadata=data.get("metadata"),
            documents=files,
        )

        return ResponseProvider.success(**_onboarding_payload(onboarding))

    except OnboardingError as e:
        return ResponseProvider.bad_request(
            error="onboarding_error",
            message=str(e)
        )
    except Exception as e:
        logger.exception("onboarding_create_view: %s", e)
        return ResponseProvider.server_error()


@user_login_required(required_permission="onboarding.update")
@require_http_methods(["PATCH"])
def onboarding_update_view(request: ExtendedRequest, onboarding_id: str) -> JsonResponse:
    try:
        data = request.data
        onboarding = _get_onboarding(onboarding_id)
        if not onboarding:
            return ResponseProvider.not_found(
                error="not_found",
                message="Onboarding application not found."
            )

        updated = onboarding_service.update_application(
            onboarding=onboarding,
            performed_by=request.system_user,
            **data,
        )

        return ResponseProvider.success(**_onboarding_payload(updated))

    except OnboardingError as e:
        return ResponseProvider.bad_request(
            error="onboarding_error",
            message=str(e)
        )
    except Exception as e:
        logger.exception("onboarding_update_view: %s", e)
        return ResponseProvider.server_error()


@user_login_required(required_permission="onboarding.submit")
@require_POST
def onboarding_submit_view(request: ExtendedRequest, onboarding_id: str) -> JsonResponse:
    try:
        onboarding = _get_onboarding(onboarding_id)
        if not onboarding:
            return ResponseProvider.not_found(
                error="not_found",
                message="Onboarding application not found."
            )

        updated = onboarding_service.submit(
            onboarding=onboarding,
            performed_by=request.system_user
        )

        return ResponseProvider.success(**_onboarding_payload(updated))

    except OnboardingError as e:
        return ResponseProvider.bad_request(
            error="onboarding_error",
            message=str(e)
        )
    except Exception as e:
        logger.exception("onboarding_submit_view: %s", e)
        return ResponseProvider.server_error()


@user_login_required(required_permission="onboarding.update")
@require_POST
def onboarding_upload_document_view(request: ExtendedRequest, onboarding_id: str) -> JsonResponse:
    try:
        data = request.data
        files = request.FILES

        onboarding = _get_onboarding(onboarding_id)
        if not onboarding:
            return ResponseProvider.not_found(
                error="not_found",
                message="Onboarding application not found."
            )

        document_type = data.get("document_type")
        if not document_type or document_type not in DocumentType.values:
            return ResponseProvider.bad_request(
                error="invalid_document_type",
                message="Valid document_type is required."
            )

        file = files.get("file")
        if not file:
            return ResponseProvider.bad_request(
                error="missing_file",
                message="File is required."
            )

        doc = onboarding_service.upload_document(
            onboarding=onboarding,
            uploaded_by=request.system_user,
            document_type=document_type,
            file=file,
            label=data.get("label", ""),
            expires_at=data.get("expires_at"),
            fulfils_request_id=data.get("fulfils_request_id"),
        )

        return ResponseProvider.success(**_document_payload(doc))

    except OnboardingError as e:
        return ResponseProvider.bad_request(
            error="onboarding_error",
            message=str(e)
        )
    except Exception as e:
        logger.exception("onboarding_upload_document_view: %s", e)
        return ResponseProvider.server_error()


@user_login_required(required_permission="onboarding.start_review")
@require_POST
def onboarding_start_review_view(request: ExtendedRequest, onboarding_id: str) -> JsonResponse:
    try:
        onboarding = _get_onboarding(onboarding_id)
        if not onboarding:
            return ResponseProvider.not_found(
                error="not_found",
                message="Onboarding application not found."
            )

        updated = onboarding_service.start_review(
            onboarding=onboarding,
            performed_by=request.system_user
        )

        return ResponseProvider.success(**_onboarding_payload(updated))

    except OnboardingError as e:
        return ResponseProvider.bad_request(
            error="onboarding_error",
            message=str(e)
        )
    except Exception as e:
        logger.exception("onboarding_start_review_view: %s", e)
        return ResponseProvider.server_error()


@user_login_required(required_permission="onboarding.request_documents")
@require_POST
def onboarding_request_documents_view(request: ExtendedRequest, onboarding_id: str) -> JsonResponse:
    try:
        data = request.data
        onboarding = _get_onboarding(onboarding_id)
        if not onboarding:
            return ResponseProvider.not_found(
                error="not_found",
                message="Onboarding application not found."
            )

        req = onboarding_service.request_documents(
            onboarding=onboarding,
            performed_by=request.system_user,
            document_type=data.get("document_type"),
            reason=data.get("reason", ""),
            label=data.get("label", ""),
            deadline=data.get("deadline"),
            applicant_notes=data.get("applicant_notes", ""),
        )

        return ResponseProvider.success(
            **_onboarding_payload(onboarding), request=_document_request_payload(req)
        )

    except OnboardingError as e:
        return ResponseProvider.bad_request(
            error="onboarding_error",
            message=str(e)
        )
    except Exception as e:
        logger.exception("onboarding_request_documents_view: %s", e)
        return ResponseProvider.server_error()


@user_login_required(required_permission="onboarding.review_document")
@require_POST
def onboarding_review_document_view(request: ExtendedRequest, document_id: str) -> JsonResponse:
    try:
        data = request.data
        document = _get_document(document_id)
        if not document:
            return ResponseProvider.not_found(
                error="not_found",
                message="Document not found."
            )

        updated_doc = onboarding_service.review_document(
            document=document,
            reviewed_by=request.system_user,
            approved=data.get("approved", False),
            notes=data.get("notes", ""),
        )

        return ResponseProvider.success(**_document_payload(updated_doc))

    except OnboardingError as e:
        return ResponseProvider.bad_request(
            error="onboarding_error",
            message=str(e)
        )
    except Exception as e:
        logger.exception("onboarding_review_document_view: %s", e)
        return ResponseProvider.server_error()


@user_login_required(required_permission="onboarding.approve")
@require_POST
def onboarding_approve_view(request: ExtendedRequest, onboarding_id: str) -> JsonResponse:
    try:
        onboarding = _get_onboarding(onboarding_id)
        if not onboarding:
            return ResponseProvider.not_found(
                error="not_found",
                message="Onboarding application not found."
            )

        updated = onboarding_service.approve(
            onboarding=onboarding,
            performed_by=request.system_user,
            internal_notes=request.data.get("internal_notes", ""),
        )

        return ResponseProvider.success(**_onboarding_payload(updated))

    except OnboardingError as e:
        return ResponseProvider.bad_request(
            error="onboarding_error",
            message=str(e)
        )
    except Exception as e:
        logger.exception("onboarding_approve_view: %s", e)
        return ResponseProvider.server_error()


@user_login_required(required_permission="onboarding.reject")
@require_POST
def onboarding_reject_view(request: ExtendedRequest, onboarding_id: str) -> JsonResponse:
    try:
        data = request.data
        onboarding = _get_onboarding(onboarding_id)
        if not onboarding:
            return ResponseProvider.not_found(
                error="not_found",
                message="Onboarding application not found."
            )

        updated = onboarding_service.reject(
            onboarding=onboarding,
            performed_by=request.system_user,
            reason=data.get("reason", ""),
            applicant_notes=data.get("applicant_notes", ""),
            internal_notes=data.get("internal_notes", ""),
        )

        return ResponseProvider.success(**_onboarding_payload(updated))

    except OnboardingError as e:
        return ResponseProvider.bad_request(
            error="onboarding_error",
            message=str(e)
        )
    except Exception as e:
        logger.exception("onboarding_reject_view: %s", e)
        return ResponseProvider.server_error()


@user_login_required(required_permission="onboarding.complete")
@require_POST
def onboarding_complete_view(request: ExtendedRequest, onboarding_id: str) -> JsonResponse:
    try:
        onboarding = _get_onboarding(onboarding_id)
        if not onboarding:
            return ResponseProvider.not_found(
                error="not_found",
                message="Onboarding application not found."
            )

        org = onboarding_service.complete_onboarding(
            onboarding=onboarding,
            performed_by=request.system_user
        )

        return ResponseProvider.success(
            onboarding=_onboarding_payload(onboarding),
            organization={
                "id": str(org.id),
                "name": org.name,
                "slug": org.slug,
            },
        )

    except OnboardingError as e:
        return ResponseProvider.bad_request(
            error="onboarding_error",
            message=str(e)
        )
    except Exception as e:
        logger.exception("onboarding_complete_view: %s", e)
        return ResponseProvider.server_error()


@user_login_required(required_permission="onboarding.add_note")
@require_POST
def onboarding_add_note_view(request: ExtendedRequest, onboarding_id: str) -> JsonResponse:
    try:
        data = request.data
        onboarding = _get_onboarding(onboarding_id)
        if not onboarding:
            return ResponseProvider.not_found(
                error="not_found",
                message="Onboarding application not found."
            )

        activity = onboarding_service.add_note(
            onboarding=onboarding,
            performed_by=request.system_user,
            note=data.get("note", ""),
            internal=data.get("internal", False),
        )

        return ResponseProvider.success(
            note={
                "activity_id": str(activity.id),
                "type": activity.activity_type,
                "description": activity.description,
                "internal": data.get("internal", False),
            }
        )

    except OnboardingError as e:
        return ResponseProvider.bad_request(
            error="onboarding_error",
            message=str(e)
        )
    except Exception as e:
        logger.exception("onboarding_add_note_view: %s", e)
        return ResponseProvider.server_error()


@user_login_required(required_permission="onboarding.view")
@require_GET
def onboarding_detail_view(request: ExtendedRequest, onboarding_id: str) -> JsonResponse:
    try:
        onboarding = _get_onboarding(onboarding_id)
        if not onboarding:
            return ResponseProvider.not_found(
                error="not_found",
                message="Onboarding application not found."
            )

        return ResponseProvider.success(**_onboarding_payload(onboarding))

    except Exception as e:
        logger.exception("onboarding_detail_view: %s", e)
        return ResponseProvider.server_error()