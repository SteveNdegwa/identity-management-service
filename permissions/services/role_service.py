from typing import Optional

from django.db import transaction

from accounts.models import User, SystemUser
from audit.models import AuditEventType, AuditLog
from base.models import Country
from permissions.models import Role, Permission, RolePermission, UserPermissionOverride
from systems.models import System


class RoleService:

    @transaction.atomic
    def create_role(
        self,
        system: System,
        name: str,
        slug: str,
        permission_codenames: list[str],
        country: Optional[Country] = None,
        parent_role: Optional[Role] = None,
        is_system_defined: bool = False,
        mfa_required: bool = False,
        mfa_allowed_methods: list = None,
        created_by: Optional[User] = None,
        org=None,
    ) -> Role:
        role = Role.objects.create(
            system=system,
            country=country,
            name=name,
            slug=slug,
            parent_role=parent_role,
            is_system_defined=is_system_defined,
            mfa_required=mfa_required,
            mfa_allowed_methods=mfa_allowed_methods or [],
            created_by_org=org,
        )
        self._assign_permissions(role, permission_codenames, created_by)

        self._audit(
            AuditEventType.ROLE_CREATED,
            actor=created_by,
            payload={
                "role": name,
                "system": system.name,
                "country": country.code if country else None,
                "permissions": permission_codenames,
                "mfa_required": mfa_required,
            },
        )
        return role

    @transaction.atomic
    def update_role_permissions(
        self,
        role: Role,
        add_codenames: list[str] = None,
        remove_codenames: list[str] = None,
        updated_by: Optional[User] = None,
    ) -> Role:
        if role.is_system_defined:
            raise PermissionError(
                "System-defined roles cannot be modified. "
                "Create a custom role based on this one instead."
            )

        if add_codenames:
            self._assign_permissions(role, add_codenames, updated_by)

        if remove_codenames:
            perms = Permission.objects.filter(
                system=role.system, codename__in=remove_codenames
            )
            RolePermission.objects.filter(
                role=role, permission__in=perms
            ).update(is_active=False)

        self._invalidate_cache_for_role(role)

        self._audit(
            AuditEventType.ROLE_UPDATED,
            actor=updated_by,
            payload={
                "role": role.name,
                "added": add_codenames,
                "removed": remove_codenames,
            },
        )
        return role

    @transaction.atomic
    def grant_permission_override(
        self,
        system_user: SystemUser,
        org,
        country: Country,
        permission_codename: str,
        effect: str,
        granted_by: Optional[SystemUser] = None,
        reason: str = "",
        expires_at=None,
    ) -> UserPermissionOverride:
        try:
            perm = Permission.objects.get(
                system=org.system, codename=permission_codename
            )
        except Permission.DoesNotExist:
            raise ValueError(
                f"Permission '{permission_codename}' does not exist in {org.system.name}."
            )

        override, _ = UserPermissionOverride.objects.update_or_create(
            system_user=system_user,
            organization=org,
            country=country,
            permission=perm,
            defaults={
                "effect": effect,
                "reason": reason,
                "expires_at": expires_at,
                "is_active": True,
                "granted_by": granted_by,
            },
        )

        # noinspection PyBroadException
        try:
            from permissions.services.permission_resolver import PermissionResolverService
            PermissionResolverService().invalidate_cache(
                str(system_user.id)
            )
        except Exception:
            pass

        self._audit(
            AuditEventType.OVERRIDE_CREATED,
            actor=granted_by.user if granted_by else None,
            payload={
                "effect": effect,
                "codename": permission_codename,
                "user": str(system_user.id),
                "org": str(org.id),
                "country": country.code,
                "reason": reason,
                "expires_at": expires_at.isoformat() if expires_at else None,
            },
        )
        return override

    @transaction.atomic
    def revoke_permission_override(
        self,
        override: UserPermissionOverride,
        revoked_by: Optional[SystemUser] = None,
    ) -> None:
        system_user = override.system_user
        org = override.organization
        country = override.country
        codename = override.permission.codename

        override.is_active = False
        override.save(update_fields=["is_active"])

        # noinspection PyBroadException
        try:
            from permissions.services.permission_resolver import PermissionResolverService
            PermissionResolverService().invalidate_cache(
                str(system_user.id)
            )
        except Exception:
            pass

        self._audit(
            AuditEventType.OVERRIDE_REVOKED,
            actor=revoked_by.user if revoked_by else None,
            payload={
                "codename": codename,
                "user": str(system_user.id),
                "org": str(org.id),
                "country": country.code,
            },
        )

    @staticmethod
    def _assign_permissions(
        role: Role,
        codenames: list[str],
        created_by: Optional[User],
    ):
        perms = Permission.objects.filter(
            system=role.system,
            codename__in=codenames,
            is_active=True,
        )
        found = {p.codename for p in perms}
        missing = set(codenames) - found
        if missing:
            raise ValueError(
                f"Permissions not found in {role.system.name}: {missing}"
            )

        for perm in perms:
            RolePermission.objects.get_or_create(
                role=role,
                permission=perm,
                defaults={
                    "granted_by": created_by,
                    "is_active": True,
                },
            )

    @staticmethod
    def _invalidate_cache_for_role(role: Role):
        # noinspection PyBroadException
        try:
            from permissions.services.permission_resolver import PermissionResolverService
            svc = PermissionResolverService()
            # memberships = OrganizationMembership.objects.filter(
            #     role=role, is_active=True
            # ).select_related("system_user", "organization", "country")
            # for m in memberships:
            #     svc.invalidate_cache(
            #         str(m.system_user.id), str(m.organization.id), m.country.code
            #     )
        except Exception:
            pass

    @staticmethod
    def _audit(event_type, actor=None, payload=None):
        AuditLog.objects.create(
            event_type=event_type,
            actor_user_id=actor.id if actor else None,
            actor_email=actor.get_email() or "" if actor else "",
            payload=payload or {},
        )
