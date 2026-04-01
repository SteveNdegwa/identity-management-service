from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional

from django.db import models
from django.utils import timezone

from apps.accounts.models import SystemUser
from apps.organizations.models import OrganizationMembership
from apps.permissions.models import Permission, UserPermissionOverride, Role


@dataclass
class ResolvedContext:
    system_user_id: str
    organization_id: str
    country_code: str
    role: Optional[str]
    role_id: Optional[str]
    permissions: set[str] = field(default_factory=set)
    accessible_branch_ids: Optional[list] = None
    is_suspended: bool = False
    resolved_at: str = ""


class PermissionResolverService:

    def __init__(self, cache=None):
        self._cache = cache

    def resolve(
        self,
        system_user: SystemUser,
        organization_id: str,
        country_code: str,
    ) -> ResolvedContext:
        key = self._key(system_user.id, organization_id, country_code)
        if self._cache:
            cached = self._cache.get(key)
            if cached:
                return cached

        result = self._resolve_uncached(system_user, organization_id, country_code)

        if self._cache:
            self._cache.set(key, result, timeout=300)

        return result

    def check(
        self,
        system_user: SystemUser,
        organization_id: str,
        country_code: str,
        codename: str,
    ) -> bool:
        return codename in self.resolve(system_user, organization_id, country_code).permissions

    def invalidate_cache(
        self,
        system_user_id: str,
        organization_id: str,
        country_code: str,
    ):
        if self._cache:
            self._cache.delete(self._key(system_user_id, organization_id, country_code))

    def invalidate_all_for_user(self, system_user: SystemUser):
        if not self._cache:
            return
        for m in system_user.org_memberships.filter(is_active=True).select_related("country"):
            self.invalidate_cache(
                str(system_user.id), str(m.organization_id), m.country.code
            )

    def _resolve_uncached(
        self,
        system_user: SystemUser,
        organization_id: str,
        country_code: str,
    ) -> ResolvedContext:
        ctx = ResolvedContext(
            system_user_id=str(system_user.id),
            organization_id=organization_id,
            country_code=country_code,
            role=None,
            role_id=None,
            resolved_at=timezone.now().isoformat(),
        )

        if system_user.is_suspended:
            ctx.is_suspended = True
            return ctx

        try:
            membership = (
                OrganizationMembership.objects
                .select_related("role", "country")
                .prefetch_related("branch_grants__branch")
                .get(
                    system_user=system_user,
                    organization_id=organization_id,
                    country__code=country_code,
                    is_active=True,
                )
            )
        except OrganizationMembership.DoesNotExist:
            return ctx

        if membership.is_expired():
            return ctx

        role: Role = membership.role
        ctx.role = role.slug
        ctx.role_id = str(role.id)

        # Collect all permission IDs including parent chain
        perm_ids = role.get_all_permission_ids()

        # Resolve codenames
        permissions = set(
            Permission.objects.filter(
                id__in=perm_ids, is_active=True
            ).values_list("codename", flat=True)
        )

        # Apply overrides
        permissions = self._apply_overrides(
            permissions, system_user, organization_id, country_code
        )
        ctx.permissions = permissions

        # Branch access
        if membership.all_branches:
            ctx.accessible_branch_ids = None
        else:
            ctx.accessible_branch_ids = [
                str(bg.branch_id)
                for bg in membership.branch_grants.all()
            ]

        return ctx

    @staticmethod
    def _apply_overrides(
        permissions: set[str],
        system_user: SystemUser,
        organization_id: str,
        country_code: str,
    ) -> set[str]:
        now = timezone.now()
        overrides = UserPermissionOverride.objects.filter(
            system_user=system_user,
            organization_id=organization_id,
            country__code=country_code,
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
    def _key(system_user_id, organization_id, country_code) -> str:
        return f"perm:{system_user_id}:{organization_id}:{country_code}"