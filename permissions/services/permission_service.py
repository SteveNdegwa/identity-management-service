from typing import Optional

from django.db import transaction
from django.utils.text import slugify

from accounts.models import SystemUser
from audit.models import AuditEventType, AuditLog
from base.models import Country
from organizations.models import Organization
from permissions.models import (
    PermissionCategory,
    Permission,
    Role,
    RolePermission,
    UserPermissionOverride,
)
from systems.models import System


class PermissionServiceError(Exception):
    pass


UNSET = object()


class PermissionService:
    @transaction.atomic
    def create_category(
        self,
        *,
        system: System,
        name: str,
        slug: Optional[str] = None,
        description: str = "",
        performed_by: Optional[SystemUser] = None,
    ) -> PermissionCategory:
        clean_name = (name or "").strip()
        if not clean_name:
            raise PermissionServiceError("Category name is required.")

        category = PermissionCategory.objects.create(
            system=system,
            name=clean_name,
            slug=self._unique_category_slug(system, slug or clean_name),
            description=description,
        )
        self._audit(
            AuditEventType.SYSTEM_SETTINGS_CHANGED,
            actor_system_user=performed_by,
            subject=category,
            payload={"action": "permission_category_created"},
        )
        return category

    @transaction.atomic
    def update_category(
        self,
        *,
        category: PermissionCategory,
        performed_by: Optional[SystemUser] = None,
        name: Optional[str] = None,
        description: Optional[str] = None,
    ) -> PermissionCategory:
        updated = []

        if name is not None:
            clean_name = name.strip()
            if not clean_name:
                raise PermissionServiceError("Category name cannot be blank.")
            if clean_name != category.name:
                category.slug = self._unique_category_slug(
                    category.system,
                    clean_name,
                    exclude_id=category.id,
                )
                updated.append("slug")
            category.name = clean_name
            updated.append("name")

        if description is not None:
            category.description = description
            updated.append("description")

        if updated:
            category.save(update_fields=updated)
            self._audit(
                AuditEventType.SYSTEM_SETTINGS_CHANGED,
                actor_system_user=performed_by,
                subject=category,
                payload={"action": "permission_category_updated", "updated_fields": updated},
            )

        return category

    @transaction.atomic
    def create_permission(
        self,
        *,
        system: System,
        codename: str,
        name: str,
        category: Optional[PermissionCategory] = None,
        description: str = "",
        is_read_only: bool = False,
        is_sensitive: bool = False,
        is_active: bool = True,
        performed_by: Optional[SystemUser] = None,
    ) -> Permission:
        clean_codename = (codename or "").strip()
        clean_name = (name or "").strip()
        if not clean_codename:
            raise PermissionServiceError("Permission codename is required.")
        if not clean_name:
            raise PermissionServiceError("Permission name is required.")

        permission = Permission.objects.create(
            system=system,
            category=category,
            codename=clean_codename,
            name=clean_name,
            description=description,
            is_read_only=is_read_only,
            is_sensitive=is_sensitive,
            is_active=is_active,
        )
        self._audit(
            AuditEventType.SYSTEM_SETTINGS_CHANGED,
            actor_system_user=performed_by,
            subject=permission,
            payload={"action": "permission_created"},
        )
        return permission

    @transaction.atomic
    def update_permission(
        self,
        *,
        permission: Permission,
        performed_by: Optional[SystemUser] = None,
        category=UNSET,
        name: Optional[str] = None,
        description: Optional[str] = None,
        is_read_only: Optional[bool] = None,
        is_sensitive: Optional[bool] = None,
        is_active: Optional[bool] = None,
    ) -> Permission:
        updated = []

        if category is not UNSET:
            permission.category = category
            updated.append("category")
        if name is not None:
            clean_name = name.strip()
            if not clean_name:
                raise PermissionServiceError("Permission name cannot be blank.")
            permission.name = clean_name
            updated.append("name")
        if description is not None:
            permission.description = description
            updated.append("description")
        if is_read_only is not None:
            permission.is_read_only = is_read_only
            updated.append("is_read_only")
        if is_sensitive is not None:
            permission.is_sensitive = is_sensitive
            updated.append("is_sensitive")
        if is_active is not None:
            permission.is_active = is_active
            updated.append("is_active")

        if updated:
            permission.save(update_fields=updated)
            self._audit(
                AuditEventType.SYSTEM_SETTINGS_CHANGED,
                actor_system_user=performed_by,
                subject=permission,
                payload={"action": "permission_updated", "updated_fields": updated},
            )

        return permission

    @transaction.atomic
    def create_role(
        self,
        *,
        system: System,
        name: str,
        permission_codenames: list[str],
        performed_by: Optional[SystemUser] = None,
        slug: Optional[str] = None,
        country: Optional[Country] = None,
        parent_role: Optional[Role] = None,
        description: str = "",
        is_system_defined: bool = False,
        created_by_org: Optional[Organization] = None,
        mfa_required: bool = False,
        mfa_allowed_methods: Optional[list] = None,
        mfa_reauth_window_minutes: int = 0,
        is_active: bool = True,
    ) -> Role:
        clean_name = (name or "").strip()
        if not clean_name:
            raise PermissionServiceError("Role name is required.")

        role = Role.objects.create(
            system=system,
            country=country,
            name=clean_name,
            slug=self._unique_role_slug(system, country, slug or clean_name),
            description=description,
            parent_role=parent_role,
            mfa_required=mfa_required,
            mfa_allowed_methods=mfa_allowed_methods or [],
            mfa_reauth_window_minutes=mfa_reauth_window_minutes,
            is_system_defined=is_system_defined,
            created_by_org=created_by_org,
            is_active=is_active,
        )
        self._sync_role_permissions(
            role=role,
            permission_codenames=permission_codenames,
            granted_by=performed_by.user if performed_by and performed_by.user_id else None,
        )

        self._audit(
            AuditEventType.ROLE_CREATED,
            actor_system_user=performed_by,
            subject=role,
            payload={
                "permissions": permission_codenames,
                "country": country.code if country else None,
            },
        )
        return role

    @transaction.atomic
    def update_role(
        self,
        *,
        role: Role,
        performed_by: Optional[SystemUser] = None,
        name: Optional[str] = None,
        description: Optional[str] = None,
        parent_role=UNSET,
        mfa_required: Optional[bool] = None,
        mfa_allowed_methods: Optional[list] = None,
        mfa_reauth_window_minutes: Optional[int] = None,
        is_active: Optional[bool] = None,
        permission_codenames: Optional[list[str]] = None,
    ) -> Role:
        if role.is_system_defined:
            raise PermissionServiceError(
                "System-defined roles cannot be modified."
            )

        updated = []

        if name is not None:
            clean_name = name.strip()
            if not clean_name:
                raise PermissionServiceError("Role name cannot be blank.")
            if clean_name != role.name:
                role.slug = self._unique_role_slug(
                    role.system,
                    role.country,
                    clean_name,
                    exclude_id=role.id,
                )
                updated.append("slug")
            role.name = clean_name
            updated.append("name")
        if description is not None:
            role.description = description
            updated.append("description")
        if parent_role is not UNSET:
            if parent_role is not None and parent_role.id == role.id:
                raise PermissionServiceError("Role cannot be its own parent.")
            role.parent_role = parent_role
            updated.append("parent_role")
        if mfa_required is not None:
            role.mfa_required = mfa_required
            updated.append("mfa_required")
        if mfa_allowed_methods is not None:
            role.mfa_allowed_methods = mfa_allowed_methods
            updated.append("mfa_allowed_methods")
        if mfa_reauth_window_minutes is not None:
            role.mfa_reauth_window_minutes = mfa_reauth_window_minutes
            updated.append("mfa_reauth_window_minutes")
        if is_active is not None:
            role.is_active = is_active
            updated.append("is_active")

        if updated:
            role.save(update_fields=updated)

        if permission_codenames is not None:
            self._sync_role_permissions(
                role=role,
                permission_codenames=permission_codenames,
                granted_by=performed_by.user if performed_by and performed_by.user_id else None,
            )
            updated.append("permissions")

        if updated:
            self._audit(
                AuditEventType.ROLE_UPDATED,
                actor_system_user=performed_by,
                subject=role,
                payload={"updated_fields": updated},
            )

        return role

    @transaction.atomic
    def deactivate_role(
        self,
        *,
        role: Role,
        performed_by: Optional[SystemUser] = None,
    ) -> Role:
        if role.is_system_defined:
            raise PermissionServiceError("System-defined roles cannot be deactivated.")
        if not role.is_active:
            raise PermissionServiceError("Role is already inactive.")

        role.is_active = False
        role.save(update_fields=["is_active"])
        self._audit(
            AuditEventType.ROLE_DELETED,
            actor_system_user=performed_by,
            subject=role,
            payload={"action": "deactivated"},
        )
        return role

    @transaction.atomic
    def reactivate_role(
        self,
        *,
        role: Role,
        performed_by: Optional[SystemUser] = None,
    ) -> Role:
        if role.is_system_defined:
            raise PermissionServiceError("System-defined roles cannot be reactivated here.")
        if role.is_active:
            raise PermissionServiceError("Role is already active.")

        role.is_active = True
        role.save(update_fields=["is_active"])
        self._audit(
            AuditEventType.ROLE_UPDATED,
            actor_system_user=performed_by,
            subject=role,
            payload={"action": "reactivated"},
        )
        return role

    @transaction.atomic
    def grant_permission_override(
        self,
        *,
        system_user: SystemUser,
        permission: Permission,
        effect: str,
        performed_by: Optional[SystemUser] = None,
        reason: str = "",
        expires_at=None,
    ) -> UserPermissionOverride:
        if permission.system_id != system_user.system_id:
            raise PermissionServiceError("Permission must belong to the same system as the user.")

        override, _ = UserPermissionOverride.objects.update_or_create(
            system_user=system_user,
            permission=permission,
            defaults={
                "effect": effect,
                "reason": reason,
                "expires_at": expires_at,
                "is_active": True,
                "granted_by": performed_by,
            },
        )

        self._invalidate_cache(str(system_user.id))
        self._audit(
            AuditEventType.OVERRIDE_CREATED,
            actor_system_user=performed_by,
            subject=override,
            payload={
                "effect": effect,
                "permission": permission.codename,
                "system_user_id": str(system_user.id),
            },
        )
        return override

    @transaction.atomic
    def revoke_permission_override(
        self,
        *,
        override: UserPermissionOverride,
        performed_by: Optional[SystemUser] = None,
    ) -> UserPermissionOverride:
        if not override.is_active:
            raise PermissionServiceError("Override is already inactive.")

        override.is_active = False
        override.save(update_fields=["is_active"])

        self._invalidate_cache(str(override.system_user_id))
        self._audit(
            AuditEventType.OVERRIDE_REVOKED,
            actor_system_user=performed_by,
            subject=override,
            payload={"permission": override.permission.codename},
        )
        return override

    @staticmethod
    def _sync_role_permissions(
        *,
        role: Role,
        permission_codenames: list[str],
        granted_by=None,
    ) -> None:
        permissions = list(
            Permission.objects.filter(
                system=role.system,
                codename__in=permission_codenames,
                is_active=True,
            )
        )
        found = {permission.codename for permission in permissions}
        missing = sorted(set(permission_codenames) - found)
        if missing:
            raise PermissionServiceError(
                f"Permissions not found in {role.system.name}: {', '.join(missing)}"
            )

        active_by_id = {permission.id for permission in permissions}
        existing = {
            rp.permission_id: rp
            for rp in RolePermission.objects.filter(role=role)
        }

        for permission in permissions:
            rp = existing.get(permission.id)
            if rp:
                if not rp.is_active:
                    rp.is_active = True
                    rp.save(update_fields=["is_active"])
            else:
                RolePermission.objects.create(
                    role=role,
                    permission=permission,
                    granted_by=granted_by,
                    is_active=True,
                )

        for permission_id, rp in existing.items():
            if permission_id not in active_by_id and rp.is_active:
                rp.is_active = False
                rp.save(update_fields=["is_active"])

    @staticmethod
    def _invalidate_cache(system_user_id: str):
        try:
            from permissions.services.permission_resolver import PermissionResolverService
            PermissionResolverService().invalidate_cache(system_user_id)
        except Exception:
            pass

    @staticmethod
    def _unique_category_slug(system: System, raw_value: str, exclude_id=None) -> str:
        base_slug = slugify(raw_value) or "category"
        candidate = base_slug
        suffix = 2
        while True:
            qs = PermissionCategory.objects.filter(system=system, slug=candidate)
            if exclude_id:
                qs = qs.exclude(id=exclude_id)
            if not qs.exists():
                return candidate
            candidate = f"{base_slug}-{suffix}"
            suffix += 1

    @staticmethod
    def _unique_role_slug(system: System, country: Optional[Country], raw_value: str, exclude_id=None) -> str:
        base_slug = slugify(raw_value) or "role"
        candidate = base_slug
        suffix = 2
        while True:
            qs = Role.objects.filter(system=system, country=country, slug=candidate)
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
