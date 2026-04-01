from typing import Optional
from django.db import transaction
from django.utils import timezone

from apps.accounts.models import SystemUser
from apps.base.models import Country
from apps.organizations.models import (
    Organization,
    Branch,
    OrganizationMembership,
    MembershipBranchAccess,
    OrganizationSettings, OrganizationCountry,
)
from apps.permissions.models import Role
from apps.systems.models import System, SystemSettings
from apps.audit.models import AuditLog, AuditEventType


class OrganizationService:

    @transaction.atomic
    def create_organization(
            self,
            system: System,
            name: str,
            slug: str,
            countries: list[Country],
            owner: Optional[SystemUser] = None,
            description: str = "",
            logo_url: str = "",
            website: str = "",
    ) -> Organization:
        country_ids = list({c.id for c in countries})

        valid_country_ids = set(
            system.available_countries
            .filter(id__in=country_ids)
            .values_list("id", flat=True)
        )

        invalid_ids = set(country_ids) - valid_country_ids
        if invalid_ids:
            invalid_countries = [c.name for c in countries if c.id in invalid_ids]
            raise ValueError(
                f"{system.name} is not available in: {', '.join(invalid_countries)}."
            )

        org = Organization.objects.create(
            system=system,
            name=name,
            slug=slug,
            owner=owner,
            description=description,
            logo_url=logo_url,
            website=website,
        )

        OrganizationCountry.objects.bulk_create([
            OrganizationCountry(
                organization=org,
                country_id=cid,
            )
            for cid in country_ids
        ])

        self._audit(
            AuditEventType.ORG_CREATED,
            actor=owner,
            subject=org,
            payload={
                "name": name,
                "countries": [c.code for c in countries],
            },
        )

        return org

    @transaction.atomic
    def activate_in_country(
        self,
        org: Organization,
        country: Country,
        registration_number: str = "",
        tax_id: str = "",
    ) -> OrganizationCountry:
        if not org.system.available_countries.filter(id=country.id).exists():
            raise ValueError(
                f"{org.system.name} is not available in {country.name}."
            )
        oc, _ = OrganizationCountry.objects.get_or_create(
            organization=org,
            country=country,
            defaults={
                "registration_number": registration_number,
                "tax_id": tax_id,
            },
        )
        return oc

    def set_setting(
        self,
        org: Organization,
        key: str,
        value: str,
        value_type: str = "string",
        updated_by: Optional[SystemUser] = None,
        is_secret: bool = False,
        description: str = "",
    ) -> OrganizationSettings:
        setting, _ = OrganizationSettings.objects.update_or_create(
            organization=org,
            key=key,
            defaults={
                "value": value,
                "value_type": value_type,
                "updated_by": updated_by,
                "is_secret": is_secret,
                "description": description,
            },
        )
        self._audit(
            AuditEventType.ORG_SETTINGS_CHANGED,
            actor=updated_by,
            subject=org,
            payload={
                "key": key,
                "value": "***" if is_secret else value,
            },
        )
        return setting

    @staticmethod
    def get_setting(org: Organization, key: str, default=None):
        try:
            return OrganizationSettings.objects.get(
                organization=org, key=key
            ).typed_value()
        except OrganizationSettings.DoesNotExist:
            pass
        try:
            return SystemSettings.objects.get(
                system=org.system, key=key
            ).typed_value()
        except SystemSettings.DoesNotExist:
            return default

    @transaction.atomic
    def create_branch(
        self,
        org: Organization,
        country: Country,
        name: str,
        code: str = "",
        parent: Optional[Branch] = None,
        address: str = "",
        metadata: dict = None,
    ) -> Branch:
        if not org.countries.filter(id=country.id).exists():
            raise ValueError(
                f"{org.name} is not active in {country.name}."
            )
        branch = Branch.objects.create(
            organization=org,
            country=country,
            name=name,
            code=code,
            parent=parent,
            address=address,
            metadata=metadata or {},
        )
        self._audit(
            AuditEventType.BRANCH_CREATED,
            subject=branch,
            payload={"org": org.name, "country": country.code, "name": name},
        )
        return branch

    def update_branch(
        self,
        branch: Branch,
        updated_by: Optional[SystemUser] = None,
        **fields,
    ) -> Branch:
        allowed = {
            "name", "code", "address", "is_active", "metadata",
            "parent", "latitude", "longitude"
        }
        updated = []
        for key, value in fields.items():
            if key in allowed:
                setattr(branch, key, value)
                updated.append(key)
        if updated:
            branch.save(update_fields=updated)
            self._audit(
                AuditEventType.BRANCH_UPDATED,
                actor=updated_by,
                subject=branch,
                payload={"updated_fields": updated},
            )
        return branch

    @transaction.atomic
    def add_member(
        self,
        system_user: SystemUser,
        org: Organization,
        country: Country,
        role: Role,
        invited_by: Optional[SystemUser] = None,
        all_branches: bool = True,
        branch_ids: Optional[list] = None,
        expires_at=None,
    ) -> OrganizationMembership:
        if system_user.system_id != org.system_id:
            raise ValueError(
                "SystemUser and Organization must belong to the same System."
            )
        if role.system_id != org.system_id:
            raise ValueError(
                "Role must belong to the same System as the Organization."
            )
        if not org.countries.filter(id=country.id).exists():
            raise ValueError(
                f"{org.name} is not active in {country.name}."
            )

        membership, created = OrganizationMembership.objects.get_or_create(
            system_user=system_user,
            organization=org,
            country=country,
            defaults={
                "role": role,
                "invited_by": invited_by,
                "all_branches": all_branches,
                "expires_at": expires_at,
                "is_active": True,
                "invite_accepted_at": timezone.now(),
            },
        )

        if not created:
            membership.role = role
            membership.is_active = True
            membership.expires_at = expires_at
            membership.all_branches = all_branches
            membership.save(update_fields=[
                "role",
                "is_active",
                "expires_at",
                "all_branches"
            ])

        if not all_branches and branch_ids:
            MembershipBranchAccess.objects.filter(membership=membership).delete()
            for bid in branch_ids:
                MembershipBranchAccess.objects.get_or_create(
                    membership=membership,
                    branch_id=bid,
                    defaults={"granted_by": invited_by},
                )

        self._invalidate_perm_cache(system_user, org, country)
        self._audit(
            AuditEventType.MEMBER_ADDED,
            actor=invited_by,
            subject=system_user,
            payload={
                "org": org.name,
                "country": country.code,
                "role": role.name,
                "all_branches": all_branches,
            },
        )
        return membership

    @transaction.atomic
    def change_member_role(
        self,
        membership: OrganizationMembership,
        new_role: Role,
        changed_by: Optional[SystemUser] = None,
        reason: str = "",
    ) -> OrganizationMembership:
        if new_role.system_id != membership.organization.system_id:
            raise ValueError("New role must belong to the same system.")

        old_role_name = membership.role.name
        membership.role = new_role
        membership.save(update_fields=["role"])

        self._invalidate_perm_cache(
            membership.system_user, membership.organization, membership.country
        )
        self._audit(
            AuditEventType.MEMBER_ROLE_CHANGED,
            actor=changed_by,
            subject=membership.system_user,
            payload={
                "old_role": old_role_name,
                "new_role": new_role.name,
                "org": membership.organization.name,
                "country": membership.country.code,
                "reason": reason,
            },
        )
        return membership

    @transaction.atomic
    def remove_member(
        self,
        membership: OrganizationMembership,
        removed_by: Optional[SystemUser] = None,
        reason: str = "",
    ) -> None:
        membership.is_active = False
        membership.save(update_fields=["is_active"])

        self._invalidate_perm_cache(
            membership.system_user, membership.organization, membership.country
        )
        self._audit(
            AuditEventType.MEMBER_REMOVED,
            actor=removed_by,
            subject=membership.system_user,
            payload={
                "org": membership.organization.name,
                "country": membership.country.code,
                "reason": reason,
            },
        )

    @transaction.atomic
    def set_branch_access(
        self,
        membership: OrganizationMembership,
        all_branches: bool,
        branch_ids: Optional[list] = None,
        changed_by: Optional[SystemUser] = None,
    ) -> OrganizationMembership:
        membership.all_branches = all_branches
        membership.save(update_fields=["all_branches"])

        MembershipBranchAccess.objects.filter(membership=membership).delete()
        if not all_branches and branch_ids:
            for bid in branch_ids:
                MembershipBranchAccess.objects.get_or_create(
                    membership=membership,
                    branch_id=bid,
                    defaults={"granted_by": changed_by},
                )

        self._invalidate_perm_cache(
            membership.system_user, membership.organization, membership.country
        )
        self._audit(
            AuditEventType.MEMBER_BRANCH_CHANGED,
            actor=changed_by,
            subject=membership.system_user,
            payload={
                "all_branches": all_branches,
                "branch_ids": branch_ids or [],
            },
        )
        return membership

    @staticmethod
    def _invalidate_perm_cache(system_user: SystemUser, org: Organization, country: Country):
        # noinspection PyBroadException
        try:
            from apps.permissions.services.permission_resolver import PermissionResolverService
            PermissionResolverService().invalidate_cache(
                str(system_user.id), str(org.id), country.code
            )
        except Exception:
            pass

    @staticmethod
    def _audit(event_type, actor=None, subject=None, payload=None):
        actor_user = actor.user if actor and hasattr(actor, "user") else None
        AuditLog.objects.create(
            event_type=event_type,
            actor_user_id=actor_user.id if actor_user else None,
            actor_email=actor_user.get_email() or "" if actor_user else "",
            actor_system_user_id=actor.id if actor else None,
            subject_type=type(subject).__name__ if subject else "",
            subject_id=str(subject.id) if subject else "",
            subject_label=str(subject) if subject else "",
            payload=payload or {},
        )


