from typing import Optional

from django.db import transaction
from django.utils import timezone
from django.utils.text import slugify

from accounts.models import SystemUser
from audit.models import AuditLog, AuditEventType
from base.models import Country
from organizations.models import (
    Organization,
    OrganizationCountry,
    OrganizationSettings,
    Branch,
)
from systems.models import System


class OrganizationServiceError(Exception):
    pass


class OrganizationService:

    @transaction.atomic
    def update_organization(
            self,
            organization: Organization,
            performed_by: SystemUser,
            name: Optional[str] = None,
            description: Optional[str] = None,
            logo_url: Optional[str] = None,
            website: Optional[str] = None,
    ) -> Organization:
        updated = []

        if name is not None:
            name = name.strip()
            if not name:
                raise OrganizationServiceError("Organization name cannot be blank.")
            # Regenerate slug only if name actually changed
            if name != organization.name:
                new_slug = self._unique_slug(organization.system, name, exclude_id=organization.id)
                organization.slug = new_slug
                updated.append("slug")
            organization.name = name
            updated.append("name")

        if description is not None:
            organization.description = description
            updated.append("description")

        if logo_url is not None:
            organization.logo_url = logo_url
            updated.append("logo_url")

        if website is not None:
            organization.website = website
            updated.append("website")

        if updated:
            organization.save(update_fields=updated)
            self._audit(
                AuditEventType.ORG_UPDATED,
                actor_system_user=performed_by,
                subject=organization,
                payload={"updated_fields": updated},
            )

        return organization

    @transaction.atomic
    def deactivate_organization(
            self,
            organization: Organization,
            performed_by: SystemUser,
    ) -> Organization:
        if not organization.is_active:
            raise OrganizationServiceError("Organization is already inactive.")

        organization.is_active = False
        organization.save(update_fields=["is_active"])

        self._audit(
            AuditEventType.ORG_DEACTIVATED,
            actor_system_user=performed_by,
            subject=organization,
            payload={"name": organization.name},
        )

        return organization

    @transaction.atomic
    def reactivate_organization(
            self,
            organization: Organization,
            performed_by: SystemUser,
    ) -> Organization:
        if organization.is_active:
            raise OrganizationServiceError("Organization is already active.")

        organization.is_active = True
        organization.save(update_fields=["is_active"])

        self._audit(
            AuditEventType.ORG_REACTIVATED,
            actor_system_user=performed_by,
            subject=organization,
            payload={"name": organization.name},
        )

        return organization

    @transaction.atomic
    def add_country(
            self,
            organization: Organization,
            country: Country,
            performed_by: SystemUser,
            registration_number: str = "",
            tax_id: str = "",
    ) -> OrganizationCountry:
        if not organization.system.available_countries.filter(id=country.id).exists():
            raise OrganizationServiceError(
                f"{organization.system.name} is not available in {country.name}."
            )

        if OrganizationCountry.objects.filter(organization=organization, country=country).exists():
            raise OrganizationServiceError(
                f"{organization.name} already operates in {country.name}."
            )

        org_country = OrganizationCountry.objects.create(
            organization=organization,
            country=country,
            registration_number=registration_number,
            tax_id=tax_id,
            approval_status=OrganizationCountry.ApprovalStatus.APPROVED,
            approved_at=timezone.now(),
            approved_by=performed_by,
            is_active=True,
        )

        self._audit(
            AuditEventType.ORG_COUNTRY_ADDED,
            actor_system_user=performed_by,
            subject=org_country,
            payload={
                "organization": organization.name,
                "country": country.name,
            },
        )

        return org_country

    @transaction.atomic
    def update_country(
            self,
            org_country: OrganizationCountry,
            performed_by: SystemUser,
            registration_number: Optional[str] = None,
            tax_id: Optional[str] = None,
    ) -> OrganizationCountry:
        updated = []
        if registration_number is not None:
            org_country.registration_number = registration_number
            updated.append("registration_number")
        if tax_id is not None:
            org_country.tax_id = tax_id
            updated.append("tax_id")
        if updated:
            org_country.save(update_fields=updated)
            self._audit(
                AuditEventType.ORG_COUNTRY_UPDATED,
                actor_system_user=performed_by,
                subject=org_country,
                payload={"updated_fields": updated},
            )

        return org_country

    @transaction.atomic
    def deactivate_country(
            self,
            org_country: OrganizationCountry,
            performed_by: SystemUser,
    ) -> OrganizationCountry:
        if not org_country.is_active:
            raise OrganizationServiceError("This country entry is already inactive.")

        org_country.is_active = False
        org_country.save(update_fields=["is_active"])

        self._audit(
            AuditEventType.ORG_COUNTRY_DEACTIVATED,
            actor_system_user=performed_by,
            subject=org_country,
            payload={"country": org_country.country.name},
        )

        return org_country

    @transaction.atomic
    def create_branch(
            self,
            organization: Organization,
            country: Country,
            performed_by: SystemUser,
            name: str,
            code: str = "",
            parent: Optional[Branch] = None,
            metadata: Optional[dict] = None,
    ) -> Branch:
        if not name.strip():
            raise OrganizationServiceError("Branch name is required.")

        if not OrganizationCountry.objects.filter(
            organization=organization,
            country=country,
            is_active=True,
            approval_status=OrganizationCountry.ApprovalStatus.APPROVED,
        ).exists():
            raise OrganizationServiceError(
                f"{organization.name} is not approved to operate in {country.name}. "
                "Complete country onboarding first."
            )

        if code:
            if Branch.objects.filter(
                organization=organization, country=country, code=code,
            ).exists():
                raise OrganizationServiceError(
                    f"A branch with code '{code}' already exists for {organization.name} in {country.name}."
                )

        if parent:
            if parent.organization_id != organization.id:
                raise OrganizationServiceError("Parent branch belongs to a different organization.")
            if parent.country_id != country.id:
                raise OrganizationServiceError("Parent branch is in a different country.")

        branch = Branch.objects.create(
            organization=organization,
            country=country,
            name=name.strip(),
            code=code.strip(),
            parent=parent,
            is_active=True,
            metadata=metadata or {},
        )

        self._audit(
            AuditEventType.BRANCH_CREATED,
            actor_system_user=performed_by,
            subject=branch,
            payload={
                "organization": organization.name,
                "country": country.name,
                "name": branch.name,
            },
        )

        return branch

    @transaction.atomic
    def update_branch(
            self,
            branch: Branch,
            performed_by: SystemUser,
            name: Optional[str] = None,
            code: Optional[str] = None,
            parent: Optional[Branch] = None,
            metadata: Optional[dict] = None,
    ) -> Branch:
        updated = []

        if name is not None:
            if not name.strip():
                raise OrganizationServiceError("Branch name cannot be blank.")
            branch.name = name.strip()
            updated.append("name")

        if code is not None:
            new_code = code.strip()
            if new_code and new_code != branch.code:
                if Branch.objects.filter(
                    organization=branch.organization,
                    country=branch.country,
                    code=new_code,
                ).exclude(id=branch.id).exists():
                    raise OrganizationServiceError(
                        f"A branch with code '{new_code}' already exists in this country."
                    )
            branch.code = new_code
            updated.append("code")

        if parent is not None:
            if parent.id == branch.id:
                raise OrganizationServiceError("A branch cannot be its own parent.")
            if parent.organization_id != branch.organization_id:
                raise OrganizationServiceError("Parent branch belongs to a different organization.")
            if parent.country_id != branch.country_id:
                raise OrganizationServiceError("Parent branch is in a different country.")
            if self._is_descendant(branch, parent):
                raise OrganizationServiceError("Cannot set a descendant as the parent (circular reference).")
            branch.parent = parent
            updated.append("parent")

        if metadata is not None:
            branch.metadata = metadata
            updated.append("metadata")

        if updated:
            branch.save(update_fields=updated)
            self._audit(
                AuditEventType.BRANCH_UPDATED,
                actor_system_user=performed_by,
                subject=branch,
                payload={"updated_fields": updated},
            )

        return branch

    @transaction.atomic
    def deactivate_branch(
            self,
            branch: Branch,
            performed_by: SystemUser,
    ) -> Branch:
        if not branch.is_active:
            raise OrganizationServiceError("Branch is already inactive.")

        branch.is_active = False
        branch.save(update_fields=["is_active"])

        self._audit(
            AuditEventType.BRANCH_DEACTIVATED,
            actor_system_user=performed_by,
            subject=branch,
            payload={"name": branch.name},
        )

        return branch

    @transaction.atomic
    def reactivate_branch(
            self,
            branch: Branch,
            performed_by: SystemUser,
    ) -> Branch:
        if branch.is_active:
            raise OrganizationServiceError("Branch is already active.")

        branch.is_active = True
        branch.save(update_fields=["is_active"])

        self._audit(
            AuditEventType.BRANCH_REACTIVATED,
            actor_system_user=performed_by,
            subject=branch,
            payload={"name": branch.name},
        )

        return branch

    @transaction.atomic
    def set_setting(
            self,
            organization: Organization,
            performed_by: SystemUser,
            key: str,
            value: str,
            value_type: str = OrganizationSettings.ValueType.STRING,
            description: str = "",
            is_secret: bool = False,
    ) -> OrganizationSettings:
        if not key.strip():
            raise OrganizationServiceError("Setting key cannot be blank.")

        setting, created = OrganizationSettings.objects.update_or_create(
            organization=organization,
            key=key.strip(),
            defaults={
                "value": value,
                "value_type": value_type,
                "description": description,
                "is_secret": is_secret,
                "updated_by": performed_by,
            },
        )

        self._audit(
            AuditEventType.ORG_SETTINGS_CHANGED,
            actor_system_user=performed_by,
            subject=setting,
            payload={
                "key": key,
                "created": created,
            },
        )

        return setting

    @transaction.atomic
    def delete_setting(
            self,
            organization: Organization,
            performed_by: SystemUser,
            key: str,
    ):
        deleted, _ = OrganizationSettings.objects.filter(
            organization=organization,
            key=key,
        ).delete()
        if not deleted:
            raise OrganizationServiceError(f"Setting '{key}' not found.")

        self._audit(
            AuditEventType.ORG_SETTING_DELETED,
            actor_system_user=performed_by,
            subject=organization,
            payload={"key": key},
        )

    @staticmethod
    def _unique_slug(system: System, name: str, exclude_id: Optional[str] = None) -> str:
        base = slugify(name)[:110]
        slug = base
        i = 1
        qs = Organization.objects.filter(system=system, slug=slug)
        if exclude_id:
            qs = qs.exclude(id=exclude_id)
        while qs.exists():
            slug = f"{base}-{i}"
            i += 1
            qs = Organization.objects.filter(system=system, slug=slug)
            if exclude_id:
                qs = qs.exclude(id=exclude_id)
        return slug

    @staticmethod
    def _is_descendant(branch: Branch, candidate_parent: Branch) -> bool:
        current = candidate_parent
        visited = set()
        while current is not None:
            if current.id == branch.id:
                return True
            if current.id in visited:
                break
            visited.add(current.id)
            current = current.parent
        return False

    @staticmethod
    def _audit(
            event_type: str,
            actor_system_user: Optional[SystemUser] = None,
            subject=None,
            ip: str = "",
            payload: dict = None,
            outcome: str = "success",
    ):
        AuditLog.objects.create(
            event_type=event_type,
            actor_user_id=actor_system_user.user.id if actor_system_user and actor_system_user.user else None,
            actor_email=actor_system_user.user.get_email() if actor_system_user and actor_system_user.user else "",
            actor_system_user_id=actor_system_user.id if actor_system_user else None,
            actor_ip=ip or None,
            subject_type=type(subject).__name__ if subject else "",
            subject_id=str(subject.id) if subject else "",
            subject_label=str(subject) if subject else "",
            payload=payload or {},
            outcome=outcome,
        )
