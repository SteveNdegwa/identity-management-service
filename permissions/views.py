import logging
from datetime import datetime
from typing import Optional

from django.http import JsonResponse
from django.views.decorators.http import require_GET, require_POST, require_http_methods

from accounts.models import SystemUser
from base.models import Country
from organizations.models import Organization
from permissions.models import (
    PermissionCategory,
    Permission,
    Role,
    UserPermissionOverride,
)
from permissions.services.permission_service import (
    PermissionService,
    PermissionServiceError,
    UNSET,
)
from systems.models import System
from utils.decorators import user_login_required
from utils.extended_request import ExtendedRequest
from utils.response_provider import ResponseProvider

logger = logging.getLogger(__name__)
permission_service = PermissionService()


def _get_system(system_id: str) -> Optional[System]:
    try:
        return System.objects.get(id=system_id)
    except System.DoesNotExist:
        return None


def _get_country(data: dict) -> Optional[Country]:
    country_id = data.get("country_id") or data.get("country")
    if not country_id:
        return None
    try:
        return Country.objects.get(id=country_id)
    except Country.DoesNotExist:
        return None


def _get_organization(data: dict) -> Optional[Organization]:
    organization_id = data.get("organization_id") or data.get("organization")
    if not organization_id:
        return None
    try:
        return Organization.objects.get(id=organization_id)
    except Organization.DoesNotExist:
        return None


def _get_category(category_id: str) -> Optional[PermissionCategory]:
    try:
        return PermissionCategory.objects.select_related("system").get(id=category_id)
    except PermissionCategory.DoesNotExist:
        return None


def _get_permission(permission_id: str) -> Optional[Permission]:
    try:
        return Permission.objects.select_related("system", "category").get(id=permission_id)
    except Permission.DoesNotExist:
        return None


def _get_role(role_id: str) -> Optional[Role]:
    try:
        return Role.objects.select_related(
            "system",
            "country",
            "parent_role",
            "created_by_org",
        ).prefetch_related("role_permissions__permission").get(id=role_id)
    except Role.DoesNotExist:
        return None


def _get_system_user(system_user_id: str) -> Optional[SystemUser]:
    try:
        return SystemUser.objects.select_related(
            "system",
            "organization",
            "country",
            "role",
            "user",
        ).get(id=system_user_id)
    except SystemUser.DoesNotExist:
        return None


def _get_override(override_id: str) -> Optional[UserPermissionOverride]:
    try:
        return UserPermissionOverride.objects.select_related(
            "system_user",
            "permission",
            "granted_by",
            "system_user__organization",
            "system_user__country",
            "system_user__role",
            "system_user__system",
        ).get(id=override_id)
    except UserPermissionOverride.DoesNotExist:
        return None


def _parse_datetime(value):
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        raise PermissionServiceError("expires_at must be a valid ISO datetime.")


def _category_payload(category: PermissionCategory) -> dict:
    return {
        "id": str(category.id),
        "system_id": str(category.system_id),
        "name": category.name,
        "slug": category.slug,
        "description": category.description,
        "created_at": category.created_at.isoformat(),
        "updated_at": category.updated_at.isoformat(),
    }


def _permission_payload(permission: Permission) -> dict:
    return {
        "id": str(permission.id),
        "system_id": str(permission.system_id),
        "category_id": str(permission.category_id) if permission.category_id else None,
        "codename": permission.codename,
        "name": permission.name,
        "description": permission.description,
        "is_read_only": permission.is_read_only,
        "is_sensitive": permission.is_sensitive,
        "is_active": permission.is_active,
        "created_at": permission.created_at.isoformat(),
        "updated_at": permission.updated_at.isoformat(),
    }


def _role_payload(role: Role) -> dict:
    active_permissions = [
        {
            "id": str(rp.permission.id),
            "codename": rp.permission.codename,
            "name": rp.permission.name,
        }
        for rp in role.role_permissions.all()
        if rp.is_active
    ]
    active_permissions.sort(key=lambda item: item["codename"])

    return {
        "id": str(role.id),
        "system_id": str(role.system_id),
        "country_id": str(role.country_id) if role.country_id else None,
        "country_code": role.country.code if role.country_id else None,
        "name": role.name,
        "slug": role.slug,
        "description": role.description,
        "parent_role_id": str(role.parent_role_id) if role.parent_role_id else None,
        "mfa_required": role.mfa_required,
        "mfa_allowed_methods": role.mfa_allowed_methods,
        "mfa_reauth_window_minutes": role.mfa_reauth_window_minutes,
        "is_system_defined": role.is_system_defined,
        "created_by_org_id": str(role.created_by_org_id) if role.created_by_org_id else None,
        "is_active": role.is_active,
        "permissions": active_permissions,
        "created_at": role.created_at.isoformat(),
        "updated_at": role.updated_at.isoformat(),
    }


def _override_payload(override: UserPermissionOverride) -> dict:
    system_user = override.system_user
    return {
        "id": str(override.id),
        "system_user_id": str(system_user.id),
        "permission_id": str(override.permission_id),
        "permission_codename": override.permission.codename,
        "effect": override.effect,
        "reason": override.reason,
        "expires_at": override.expires_at.isoformat() if override.expires_at else None,
        "is_active": override.is_active,
        "is_expired": override.is_expired,
        "granted_by_id": str(override.granted_by_id) if override.granted_by_id else None,
        "system_id": str(system_user.system_id),
        "organization_id": str(system_user.organization_id),
        "country_code": system_user.country.code,
        "role_id": str(system_user.role_id),
        "created_at": override.created_at.isoformat(),
        "updated_at": override.updated_at.isoformat(),
    }


@user_login_required(required_permission="permission.view")
@require_GET
def category_list_view(request: ExtendedRequest, system_id: str) -> JsonResponse:
    try:
        system = _get_system(system_id)
        if not system:
            return ResponseProvider.not_found(error="not_found", message="System not found.")

        categories = system.permission_categories.all().order_by("name")
        return ResponseProvider.success(
            categories=[_category_payload(category) for category in categories]
        )
    except Exception as e:
        logger.exception("category_list_view: %s", e)
        return ResponseProvider.server_error()


@user_login_required(required_permission="permission.manage")
@require_POST
def category_create_view(request: ExtendedRequest, system_id: str) -> JsonResponse:
    system = _get_system(system_id)
    if not system:
        return ResponseProvider.not_found(error="not_found", message="System not found.")

    try:
        category = permission_service.create_category(
            system=system,
            name=request.data.get("name", ""),
            slug=request.data.get("slug"),
            description=request.data.get("description", ""),
            performed_by=request.system_user,
        )
        return ResponseProvider.created(**_category_payload(category))
    except PermissionServiceError as e:
        return ResponseProvider.bad_request(error="permission_management_error", message=str(e))
    except Exception as e:
        logger.exception("category_create_view: %s", e)
        return ResponseProvider.server_error()


@user_login_required(required_permission="permission.view")
@require_GET
def category_detail_view(request: ExtendedRequest, category_id: str) -> JsonResponse:
    try:
        category = _get_category(category_id)
        if not category:
            return ResponseProvider.not_found(error="not_found", message="Category not found.")
        return ResponseProvider.success(**_category_payload(category))
    except Exception as e:
        logger.exception("category_detail_view: %s", e)
        return ResponseProvider.server_error()


@user_login_required(required_permission="permission.manage")
@require_http_methods(["PATCH"])
def category_update_view(request: ExtendedRequest, category_id: str) -> JsonResponse:
    category = _get_category(category_id)
    if not category:
        return ResponseProvider.not_found(error="not_found", message="Category not found.")

    try:
        category = permission_service.update_category(
            category=category,
            performed_by=request.system_user,
            name=request.data.get("name"),
            description=request.data.get("description"),
        )
        return ResponseProvider.success(**_category_payload(category))
    except PermissionServiceError as e:
        return ResponseProvider.bad_request(error="permission_management_error", message=str(e))
    except Exception as e:
        logger.exception("category_update_view: %s", e)
        return ResponseProvider.server_error()


@user_login_required(required_permission="permission.view")
@require_GET
def permission_list_view(request: ExtendedRequest, system_id: str) -> JsonResponse:
    try:
        system = _get_system(system_id)
        if not system:
            return ResponseProvider.not_found(error="not_found", message="System not found.")

        qs = Permission.objects.filter(system=system).select_related("category").order_by("codename")
        if category_id := request.GET.get("category_id"):
            qs = qs.filter(category_id=category_id)
        if is_active := request.GET.get("is_active"):
            qs = qs.filter(is_active=is_active.lower() == "true")

        return ResponseProvider.success(
            permissions=[_permission_payload(permission) for permission in qs]
        )
    except Exception as e:
        logger.exception("permission_list_view: %s", e)
        return ResponseProvider.server_error()


@user_login_required(required_permission="permission.manage")
@require_POST
def permission_create_view(request: ExtendedRequest, system_id: str) -> JsonResponse:
    system = _get_system(system_id)
    if not system:
        return ResponseProvider.not_found(error="not_found", message="System not found.")

    try:
        category = None
        if category_id := request.data.get("category_id"):
            category = _get_category(category_id)
            if not category or category.system_id != system.id:
                return ResponseProvider.bad_request(
                    error="invalid_category",
                    message="Category not found for this system.",
                )

        permission = permission_service.create_permission(
            system=system,
            codename=request.data.get("codename", ""),
            name=request.data.get("name", ""),
            category=category,
            description=request.data.get("description", ""),
            is_read_only=request.data.get("is_read_only", False),
            is_sensitive=request.data.get("is_sensitive", False),
            is_active=request.data.get("is_active", True),
            performed_by=request.system_user,
        )
        return ResponseProvider.created(**_permission_payload(permission))
    except PermissionServiceError as e:
        return ResponseProvider.bad_request(error="permission_management_error", message=str(e))
    except Exception as e:
        logger.exception("permission_create_view: %s", e)
        return ResponseProvider.server_error()


@user_login_required(required_permission="permission.view")
@require_GET
def permission_detail_view(request: ExtendedRequest, permission_id: str) -> JsonResponse:
    try:
        permission = _get_permission(permission_id)
        if not permission:
            return ResponseProvider.not_found(error="not_found", message="Permission not found.")
        return ResponseProvider.success(**_permission_payload(permission))
    except Exception as e:
        logger.exception("permission_detail_view: %s", e)
        return ResponseProvider.server_error()


@user_login_required(required_permission="permission.manage")
@require_http_methods(["PATCH"])
def permission_update_view(request: ExtendedRequest, permission_id: str) -> JsonResponse:
    permission = _get_permission(permission_id)
    if not permission:
        return ResponseProvider.not_found(error="not_found", message="Permission not found.")

    try:
        category = UNSET
        if "category_id" in request.data:
            category_id = request.data.get("category_id")
            if category_id:
                category = _get_category(category_id)
                if not category or category.system_id != permission.system_id:
                    return ResponseProvider.bad_request(
                        error="invalid_category",
                        message="Category not found for this system.",
                    )

        permission = permission_service.update_permission(
            permission=permission,
            performed_by=request.system_user,
            category=category,
            name=request.data.get("name"),
            description=request.data.get("description"),
            is_read_only=request.data.get("is_read_only"),
            is_sensitive=request.data.get("is_sensitive"),
            is_active=request.data.get("is_active"),
        )
        return ResponseProvider.success(**_permission_payload(permission))
    except PermissionServiceError as e:
        return ResponseProvider.bad_request(error="permission_management_error", message=str(e))
    except Exception as e:
        logger.exception("permission_update_view: %s", e)
        return ResponseProvider.server_error()


@user_login_required(required_permission="role.view")
@require_GET
def role_list_view(request: ExtendedRequest, system_id: str) -> JsonResponse:
    try:
        system = _get_system(system_id)
        if not system:
            return ResponseProvider.not_found(error="not_found", message="System not found.")

        qs = Role.objects.filter(system=system).select_related(
            "country",
            "parent_role",
            "created_by_org",
        ).prefetch_related("role_permissions__permission").order_by("name")

        if country_id := request.GET.get("country_id"):
            qs = qs.filter(country_id=country_id)
        if is_active := request.GET.get("is_active"):
            qs = qs.filter(is_active=is_active.lower() == "true")
        if is_system_defined := request.GET.get("is_system_defined"):
            qs = qs.filter(is_system_defined=is_system_defined.lower() == "true")

        return ResponseProvider.success(
            roles=[_role_payload(role) for role in qs]
        )
    except Exception as e:
        logger.exception("role_list_view: %s", e)
        return ResponseProvider.server_error()


@user_login_required(required_permission="role.view")
@require_GET
def role_detail_view(request: ExtendedRequest, role_id: str) -> JsonResponse:
    try:
        role = _get_role(role_id)
        if not role:
            return ResponseProvider.not_found(error="not_found", message="Role not found.")
        return ResponseProvider.success(**_role_payload(role))
    except Exception as e:
        logger.exception("role_detail_view: %s", e)
        return ResponseProvider.server_error()


@user_login_required(required_permission="role.manage")
@require_POST
def role_create_view(request: ExtendedRequest, system_id: str) -> JsonResponse:
    system = _get_system(system_id)
    if not system:
        return ResponseProvider.not_found(error="not_found", message="System not found.")

    try:
        data = request.data
        country = _get_country(data) if data.get("country_id") or data.get("country") else None
        if (data.get("country_id") or data.get("country")) and not country:
            return ResponseProvider.bad_request(error="invalid_country", message="Country not found.")

        parent_role = None
        if parent_role_id := data.get("parent_role_id"):
            parent_role = _get_role(parent_role_id)
            if not parent_role or parent_role.system_id != system.id:
                return ResponseProvider.bad_request(error="invalid_parent_role", message="Parent role not found.")

        created_by_org = None
        if data.get("organization_id") or data.get("organization"):
            created_by_org = _get_organization(data)
            if not created_by_org or created_by_org.system_id != system.id:
                return ResponseProvider.bad_request(error="invalid_organization", message="Organization not found.")

        role = permission_service.create_role(
            system=system,
            name=data.get("name", ""),
            slug=data.get("slug"),
            permission_codenames=data.get("permission_codenames", []),
            performed_by=request.system_user,
            country=country,
            parent_role=parent_role,
            description=data.get("description", ""),
            is_system_defined=data.get("is_system_defined", False),
            created_by_org=created_by_org,
            mfa_required=data.get("mfa_required", False),
            mfa_allowed_methods=data.get("mfa_allowed_methods", []),
            mfa_reauth_window_minutes=data.get("mfa_reauth_window_minutes", 0),
            is_active=data.get("is_active", True),
        )
        role = _get_role(str(role.id))
        return ResponseProvider.created(**_role_payload(role))
    except PermissionServiceError as e:
        return ResponseProvider.bad_request(error="permission_management_error", message=str(e))
    except Exception as e:
        logger.exception("role_create_view: %s", e)
        return ResponseProvider.server_error()


@user_login_required(required_permission="role.manage")
@require_http_methods(["PATCH"])
def role_update_view(request: ExtendedRequest, role_id: str) -> JsonResponse:
    role = _get_role(role_id)
    if not role:
        return ResponseProvider.not_found(error="not_found", message="Role not found.")

    try:
        data = request.data
        parent_role = UNSET
        if "parent_role_id" in data:
            parent_role_id = data.get("parent_role_id")
            if parent_role_id:
                parent_role = _get_role(parent_role_id)
                if not parent_role or parent_role.system_id != role.system_id:
                    return ResponseProvider.bad_request(
                        error="invalid_parent_role",
                        message="Parent role not found.",
                    )

        role = permission_service.update_role(
            role=role,
            performed_by=request.system_user,
            name=data.get("name"),
            description=data.get("description"),
            parent_role=parent_role,
            mfa_required=data.get("mfa_required"),
            mfa_allowed_methods=data.get("mfa_allowed_methods"),
            mfa_reauth_window_minutes=data.get("mfa_reauth_window_minutes"),
            is_active=data.get("is_active"),
            permission_codenames=data.get("permission_codenames"),
        )
        role = _get_role(str(role.id))
        return ResponseProvider.success(**_role_payload(role))
    except PermissionServiceError as e:
        return ResponseProvider.bad_request(error="permission_management_error", message=str(e))
    except Exception as e:
        logger.exception("role_update_view: %s", e)
        return ResponseProvider.server_error()


@user_login_required(required_permission="role.manage")
@require_POST
def role_deactivate_view(request: ExtendedRequest, role_id: str) -> JsonResponse:
    role = _get_role(role_id)
    if not role:
        return ResponseProvider.not_found(error="not_found", message="Role not found.")

    try:
        role = permission_service.deactivate_role(role=role, performed_by=request.system_user)
        role = _get_role(str(role.id))
        return ResponseProvider.success(**_role_payload(role))
    except PermissionServiceError as e:
        return ResponseProvider.bad_request(error="permission_management_error", message=str(e))
    except Exception as e:
        logger.exception("role_deactivate_view: %s", e)
        return ResponseProvider.server_error()


@user_login_required(required_permission="role.manage")
@require_POST
def role_reactivate_view(request: ExtendedRequest, role_id: str) -> JsonResponse:
    role = _get_role(role_id)
    if not role:
        return ResponseProvider.not_found(error="not_found", message="Role not found.")

    try:
        role = permission_service.reactivate_role(role=role, performed_by=request.system_user)
        role = _get_role(str(role.id))
        return ResponseProvider.success(**_role_payload(role))
    except PermissionServiceError as e:
        return ResponseProvider.bad_request(error="permission_management_error", message=str(e))
    except Exception as e:
        logger.exception("role_reactivate_view: %s", e)
        return ResponseProvider.server_error()


@user_login_required(required_permission="permission_override.view")
@require_GET
def override_list_view(request: ExtendedRequest, system_user_id: str) -> JsonResponse:
    try:
        system_user = _get_system_user(system_user_id)
        if not system_user:
            return ResponseProvider.not_found(error="not_found", message="System user not found.")

        qs = system_user.permission_overrides.select_related("permission", "granted_by").order_by("-created_at")
        if is_active := request.GET.get("is_active"):
            qs = qs.filter(is_active=is_active.lower() == "true")

        return ResponseProvider.success(
            overrides=[_override_payload(override) for override in qs]
        )
    except Exception as e:
        logger.exception("override_list_view: %s", e)
        return ResponseProvider.server_error()


@user_login_required(required_permission="permission_override.view")
@require_GET
def override_detail_view(request: ExtendedRequest, override_id: str) -> JsonResponse:
    try:
        override = _get_override(override_id)
        if not override:
            return ResponseProvider.not_found(error="not_found", message="Override not found.")
        return ResponseProvider.success(**_override_payload(override))
    except Exception as e:
        logger.exception("override_detail_view: %s", e)
        return ResponseProvider.server_error()


@user_login_required(required_permission="permission_override.manage")
@require_POST
def override_create_view(request: ExtendedRequest, system_user_id: str) -> JsonResponse:
    system_user = _get_system_user(system_user_id)
    if not system_user:
        return ResponseProvider.not_found(error="not_found", message="System user not found.")

    try:
        permission = _get_permission(request.data.get("permission_id", ""))
        if not permission:
            return ResponseProvider.bad_request(error="invalid_permission", message="Permission not found.")

        override = permission_service.grant_permission_override(
            system_user=system_user,
            permission=permission,
            effect=request.data.get("effect", ""),
            performed_by=request.system_user,
            reason=request.data.get("reason", ""),
            expires_at=_parse_datetime(request.data.get("expires_at")),
        )
        override = _get_override(str(override.id))
        return ResponseProvider.created(**_override_payload(override))
    except PermissionServiceError as e:
        return ResponseProvider.bad_request(error="permission_management_error", message=str(e))
    except Exception as e:
        logger.exception("override_create_view: %s", e)
        return ResponseProvider.server_error()


@user_login_required(required_permission="permission_override.manage")
@require_POST
def override_revoke_view(request: ExtendedRequest, override_id: str) -> JsonResponse:
    override = _get_override(override_id)
    if not override:
        return ResponseProvider.not_found(error="not_found", message="Override not found.")

    try:
        override = permission_service.revoke_permission_override(
            override=override,
            performed_by=request.system_user,
        )
        override = _get_override(str(override.id))
        return ResponseProvider.success(**_override_payload(override))
    except PermissionServiceError as e:
        return ResponseProvider.bad_request(error="permission_management_error", message=str(e))
    except Exception as e:
        logger.exception("override_revoke_view: %s", e)
        return ResponseProvider.server_error()
