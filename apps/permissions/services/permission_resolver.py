from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional

from django.db import models
from django.utils import timezone

from apps.accounts.models import SystemUser
from apps.permissions.models import Permission, UserPermissionOverride


@dataclass
class ResolvedContext:
    system_user_id: str
    organization_id: str
    country_code: str
    role: Optional[str]
    role_id: Optional[str]
    permissions: set[str] = field(default_factory=set)
    accessible_branch_ids: Optional[list] = None
    status: str = ""
    resolved_at: str = ""


class PermissionResolverService:

    def __init__(self, cache=None):
        self._cache = cache

    def resolve(self, system_user: SystemUser) -> ResolvedContext:
        key = self._key(system_user.id)
        if self._cache:
            cached = self._cache.get(key)
            if cached:
                return cached

        result = self._resolve_uncached(system_user)

        if self._cache:
            self._cache.set(key, result, timeout=300)

        return result

    def check(self, system_user: SystemUser, codename: str) -> bool:
        return codename in self.resolve(system_user).permissions

    def invalidate_cache(self, system_user_id: str):
        if self._cache:
            self._cache.delete(self._key(system_user_id))

    def _resolve_uncached(self, system_user: SystemUser) -> ResolvedContext:
        ctx = ResolvedContext(
            system_user_id=str(system_user.id),
            organization_id=str(system_user.organization.id),
            country_code=system_user.country.code,
            role=system_user.role.name,
            role_id=str(system_user.role.id),
            resolved_at=timezone.now().isoformat(),
            status=system_user.status,
        )

        # Collect all permission IDs including parent chain
        perm_ids = system_user.role.get_all_permission_ids()

        # Resolve codenames
        permissions = set(
            Permission.objects.filter(
                id__in=perm_ids, is_active=True
            ).values_list("codename", flat=True)
        )

        # Apply overrides
        permissions = self._apply_overrides(permissions, system_user)
        ctx.permissions = permissions

        # Branch access
        if system_user.all_branches:
            ctx.accessible_branch_ids = None
        else:
            ctx.accessible_branch_ids = [
                str(bg.branch_id)
                for bg in system_user.branch_access.all()
            ]

        return ctx

    @staticmethod
    def _apply_overrides(permissions: set[str], system_user: SystemUser) -> set[str]:
        now = timezone.now()
        overrides = UserPermissionOverride.objects.filter(
            system_user=system_user,
            is_active=True,
        ).filter(
            models.Q(expires_at__isnull=True) | models.Q(expires_at__gt=now)
        ).select_related("permission")

        for override in overrides:
            codename = override.permission.codename
            if override.effect == "grant":
                permissions.add(codename)
            elif override.effect == "deny":
                permissions.discard(codename)
        return permissions

    @staticmethod
    def _key(system_user_id: str) -> str:
        return f"perm:{system_user_id}"