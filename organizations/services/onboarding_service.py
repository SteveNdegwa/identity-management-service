import datetime
from typing import Optional

from django.core.files.uploadedfile import UploadedFile
from django.db import transaction
from django.utils import timezone
from django.utils.text import slugify

from accounts.models import SystemUser
from base.models import Country
from organizations.models import (
    Organization,
    OrganizationCountry,
    OrganizationOnboarding,
    OrganizationOnboardingCountry,
    OnboardingStatus,
    OnboardingDocument,
    DocumentStatus,
    OnboardingActivity,
    OnboardingActivityType,
    DocumentRequest,
    MANDATORY_DOCUMENT_TYPES,
    MANDATORY_DOCUMENT_LABELS,
)
from systems.models import System


class OnboardingError(Exception):
    pass


DocumentInput = dict[str,UploadedFile]


class OnboardingService:

    @transaction.atomic
    def create_application(
        self,
        system: System,
        contact_system_user: SystemUser,
        countries: list[dict],
        legal_name: str,
        documents: DocumentInput,
        organization: Optional[Organization] = None,
        trading_name: str = "",
        organization_type: str = "",
        products_needed: Optional[list[str]] = None,
        monthly_transaction_volume: str = "",
        staff_size: str = "",
        pain_points: Optional[list[str]] = None,
        contact_email: str = "",
        contact_phone: str = "",
        website: str = "",
        description: str = "",
        metadata: Optional[dict] = None,
    ) -> OrganizationOnboarding:
        if not legal_name.strip():
            raise OnboardingError("Legal name is required.")

        if not countries:
            raise OnboardingError("At least one country is required.")

        self._validate_mandatory_documents(documents)
        products_needed = self._validate_multi_select(
            values=products_needed or [],
            allowed=OrganizationOnboarding.ProductNeed.values,
            field_name="products_needed",
        )
        pain_points = self._validate_multi_select(
            values=pain_points or [],
            allowed=OrganizationOnboarding.PainPoint.values,
            field_name="pain_points",
        )
        self._validate_choice(
            value=organization_type,
            allowed=OrganizationOnboarding.OrganizationType.values,
            field_name="organization_type",
        )
        self._validate_choice(
            value=monthly_transaction_volume,
            allowed=OrganizationOnboarding.MonthlyTransactionVolume.values,
            field_name="monthly_transaction_volume",
        )
        self._validate_choice(
            value=staff_size,
            allowed=OrganizationOnboarding.StaffSize.values,
            field_name="staff_size",
        )

        if organization and organization.system_id != system.id:
            raise OnboardingError("Selected organization does not belong to this system.")

        seen_country_ids = set()
        for country_data in countries:
            country = country_data["country"]
            if country.id in seen_country_ids:
                raise OnboardingError("Duplicate countries are not allowed.")
            seen_country_ids.add(country.id)
            self._assert_country_can_onboard(
                system=system,  
                country=country,
                contact_system_user=contact_system_user,
                organization=organization,
            )

        onboarding = OrganizationOnboarding.objects.create(
            system=system,
            contact_system_user=contact_system_user,
            organization=organization,
            status=OnboardingStatus.DRAFT,
            legal_name=legal_name.strip(),
            trading_name=trading_name,
            organization_type=organization_type,
            products_needed=products_needed,
            monthly_transaction_volume=monthly_transaction_volume,
            staff_size=staff_size,
            pain_points=pain_points,
            contact_email=contact_email,
            contact_phone=contact_phone,
            website=website,
            description=description,
            metadata=metadata or {},
        )

        for country_data in countries:
            self._create_country_request(
                onboarding=onboarding,
                country=country_data["country"],
                registration_number=country_data.get("registration_number", ""),
                tax_id=country_data.get("tax_id", ""),
                address=country_data.get("address", ""),
                metadata=country_data.get("metadata") or {},
            )

        for doc_type, file in documents.items():
            self._create_document(
                onboarding=onboarding,
                uploaded_by=contact_system_user,
                document_type=doc_type,
                file=file,
            )

        self._log(
            onboarding=onboarding,
            activity_type=OnboardingActivityType.CREATED,
            performed_by=contact_system_user,
            description="Onboarding application created",
            new_status=OnboardingStatus.DRAFT,
        )
        return onboarding

    @transaction.atomic
    def update_application(
            self,
            onboarding: OrganizationOnboarding,
            performed_by: SystemUser,
            **fields
    ) -> OrganizationOnboarding:
        if not onboarding.is_editable_by_applicant:
            raise OnboardingError(f"Application cannot be edited in status '{onboarding.status}'.")

        country_fields = {"country", "country_id", "countries", "registration_number", "tax_id", "address"}
        if country_fields.intersection(fields):
            raise OnboardingError("Country details must be changed through the onboarding country endpoints.")

        allowed = {
            "legal_name", "trading_name", "organization_type", "products_needed",
            "monthly_transaction_volume", "staff_size", "pain_points",
            "contact_email", "contact_phone", "website",
            "description", "metadata"
        }
        updated = []
        for k,v in fields.items():
            if k in allowed:
                if k == "products_needed":
                    v = self._validate_multi_select(
                        values=v or [],
                        allowed=OrganizationOnboarding.ProductNeed.values,
                        field_name="products_needed",
                    )
                elif k == "pain_points":
                    v = self._validate_multi_select(
                        values=v or [],
                        allowed=OrganizationOnboarding.PainPoint.values,
                        field_name="pain_points",
                    )
                elif k == "organization_type":
                    self._validate_choice(
                        v or "",
                        OrganizationOnboarding.OrganizationType.values,
                        "organization_type"
                    )
                elif k == "monthly_transaction_volume":
                    self._validate_choice(
                        v or "",
                        OrganizationOnboarding.MonthlyTransactionVolume.values,
                        "monthly_transaction_volume",
                    )
                elif k == "staff_size":
                    self._validate_choice(
                        v or "",
                        OrganizationOnboarding.StaffSize.values,
                        "staff_size"
                    )
                setattr(onboarding,k,v)
                updated.append(k)

        if updated:
            onboarding.save(update_fields=updated)
            self._log(
                onboarding=onboarding,
                activity_type=OnboardingActivityType.UPDATED,
                performed_by=performed_by,
                description="Application details updated.",
                payload={"updated_fields":updated},
            )
        return onboarding

    @transaction.atomic
    def add_country(
        self,
        onboarding: OrganizationOnboarding,
        performed_by: SystemUser,
        country: Country,
        registration_number: str = "",
        tax_id: str = "",
        address: str = "",
        metadata: Optional[dict] = None,
    ) -> OrganizationOnboardingCountry:
        if not onboarding.is_editable_by_applicant:
            raise OnboardingError(f"Application cannot be edited in status '{onboarding.status}'.")

        if onboarding.country_requests.filter(country=country).exists():
            raise OnboardingError(f"{country.name} already exists on this onboarding application.")

        self._assert_country_can_onboard(
            system=onboarding.system,
            country=country,
            contact_system_user=onboarding.contact_system_user,
            organization=onboarding.organization,
            exclude_onboarding_ids=[onboarding.id],
        )

        created = self._create_country_request(
            onboarding=onboarding,
            country=country,
            registration_number=registration_number,
            tax_id=tax_id,
            address=address,
            metadata=metadata or {},
        )
        self._log(
            onboarding=onboarding,
            activity_type=OnboardingActivityType.CREATED,
            performed_by=performed_by,
            description=f"Country added to onboarding application: {country.code}.",
            payload={"country_request_id": str(created.id), "country_code": country.code},
        )
        return created

    @transaction.atomic
    def update_country(
        self,
        country_request: OrganizationOnboardingCountry,
        performed_by: SystemUser,
        country: Optional[Country] = None,
        registration_number: Optional[str] = None,
        tax_id: Optional[str] = None,
        address: Optional[str] = None,
        metadata: Optional[dict] = None,
    ) -> OrganizationOnboardingCountry:
        onboarding = country_request.onboarding
        if not onboarding.is_editable_by_applicant:
            raise OnboardingError(f"Application cannot be edited in status '{onboarding.status}'.")

        updated = []
        if country and country.id != country_request.country_id:
            if onboarding.country_requests.exclude(id=country_request.id).filter(country=country).exists():
                raise OnboardingError(f"{country.name} already exists on this onboarding application.")
            self._assert_country_can_onboard(
                system=onboarding.system,
                country=country,
                contact_system_user=onboarding.contact_system_user,
                organization=onboarding.organization,
                exclude_onboarding_ids=[onboarding.id],
            )
            country_request.country = country
            updated.append("country")

        for field, value in (
            ("registration_number", registration_number),
            ("tax_id", tax_id),
            ("address", address),
            ("metadata", metadata),
        ):
            if value is not None:
                setattr(country_request, field, value)
                updated.append(field)

        if updated:
            country_request.save(update_fields=updated)
            self._log(
                onboarding=onboarding,
                activity_type=OnboardingActivityType.UPDATED,
                performed_by=performed_by,
                description="Onboarding country details updated.",
                payload={"updated_fields": updated},
            )
        return country_request

    @transaction.atomic
    def create_country_application_for_onboarded_organization(
        self,
        organization: Organization,
        contact_system_user: SystemUser,
        country: Country,
        documents: DocumentInput,
        registration_number: str = "",
        tax_id: str = "",
        address: str = "",
        metadata: Optional[dict] = None,
    ) -> OrganizationOnboarding:
        if organization.system_id != contact_system_user.system_id:
            raise OnboardingError("Organization does not belong to this system user.")
        if not organization.verified:
            raise OnboardingError("Organization must be onboarded before adding a new country through this flow.")

        self._validate_mandatory_documents(documents)
        self._assert_country_can_onboard(
            system=organization.system,
            country=country,
            contact_system_user=contact_system_user,
            organization=organization,
        )

        onboarding = OrganizationOnboarding.objects.create(
            system=organization.system,
            contact_system_user=contact_system_user,
            organization=organization,
            status=OnboardingStatus.DRAFT,
            legal_name=organization.name,
            trading_name=organization.name,
            contact_email=contact_system_user.provisioning_email or contact_system_user.user.email,
            website=organization.website,
            description=organization.description,
            metadata=metadata or {},
        )
        self._create_country_request(
            onboarding=onboarding,
            country=country,
            registration_number=registration_number,
            tax_id=tax_id,
            address=address,
            metadata=metadata or {},
        )
        for doc_type, file in documents.items():
            self._create_document(
                onboarding=onboarding,
                uploaded_by=contact_system_user,
                document_type=doc_type,
                file=file,
            )
        self._log(
            onboarding=onboarding,
            activity_type=OnboardingActivityType.CREATED,
            performed_by=contact_system_user,
            description=f"New country onboarding request created for {organization.name}: {country.code}.",
            new_status=OnboardingStatus.DRAFT,
            payload={"organization_id": str(organization.id)},
        )
        return onboarding

    @transaction.atomic
    def remove_country(
        self,
        country_request: OrganizationOnboardingCountry,
        performed_by: SystemUser,
    ) -> None:
        onboarding = country_request.onboarding
        if not onboarding.is_editable_by_applicant:
            raise OnboardingError(f"Application cannot be removed in status '{onboarding.status}'.")
        if onboarding.country_requests.count() <= 1:
            raise OnboardingError("At least one country is required.")

        country_request_id = str(country_request.id)
        country_code = country_request.country.code
        country_request.delete()
        self._log(
            onboarding=onboarding,
            activity_type=OnboardingActivityType.UPDATED,
            performed_by=performed_by,
            description=f"Editable onboarding application removed for {country_code}.",
            payload={"removed_country_request_id": country_request_id, "country_code": country_code},
        )

    @transaction.atomic
    def submit(self, onboarding: OrganizationOnboarding, performed_by: SystemUser) -> OrganizationOnboarding:
        if onboarding.status not in (OnboardingStatus.DRAFT,OnboardingStatus.DOCUMENTS_REQUESTED):
            raise OnboardingError(f"Cannot submit an application in status '{onboarding.status}'.")

        if not onboarding.country_requests.exists():
            raise OnboardingError("At least one country is required.")
        self._assert_mandatory_documents_present(onboarding)

        prev = onboarding.status
        onboarding.status = OnboardingStatus.SUBMITTED
        onboarding.submitted_at = timezone.now()
        onboarding.save(update_fields=["status","submitted_at"])

        self._log(
            onboarding=onboarding,
            activity_type=OnboardingActivityType.SUBMITTED,
            performed_by=performed_by,
            description="Application submitted for review.",
            previous_status=prev,
            new_status=OnboardingStatus.SUBMITTED,
        )
        return onboarding

    @transaction.atomic
    def start_review(self, onboarding: OrganizationOnboarding, performed_by: SystemUser) -> OrganizationOnboarding:
        if onboarding.status != OnboardingStatus.SUBMITTED:
            raise OnboardingError("Can only start review on a submitted application.")

        prev = onboarding.status
        onboarding.status = OnboardingStatus.UNDER_REVIEW
        onboarding.assigned_to = performed_by
        onboarding.reviewed_at = timezone.now()
        onboarding.save(update_fields=["status","assigned_to","reviewed_at"])

        self._log(
            onboarding=onboarding,
            activity_type=OnboardingActivityType.ASSIGNED,
            performed_by=performed_by,
            description=f"Review started and assigned to {performed_by.full_name}.",
            previous_status=prev,
            new_status=OnboardingStatus.UNDER_REVIEW,
            payload={"assigned_to_id":str(performed_by.id)},
        )
        return onboarding

    @transaction.atomic
    def request_documents(
            self,
            onboarding: OrganizationOnboarding,
            performed_by: SystemUser,
            document_type: str,
            reason: str,
            label: str = "",
            deadline: Optional[datetime.datetime] = None,
            applicant_notes: str = ""
    ) -> DocumentRequest:
        if onboarding.status not in (OnboardingStatus.UNDER_REVIEW,OnboardingStatus.SUBMITTED):
            raise OnboardingError("Can only request documents while reviewing an application.")

        if not reason.strip():
            raise OnboardingError("A reason for the document request is required.")

        doc_request = DocumentRequest.objects.create(
            onboarding=onboarding,
            document_type=document_type,
            label=label,
            reason=reason,
            requested_by=performed_by,
            deadline=deadline,
        )

        prev = onboarding.status
        onboarding.status = OnboardingStatus.DOCUMENTS_REQUESTED
        if applicant_notes:
            onboarding.applicant_notes = (onboarding.applicant_notes+f"\n\n{applicant_notes}").strip()
        onboarding.save(update_fields=["status","applicant_notes"])

        self._log(
            onboarding=onboarding,
            activity_type=OnboardingActivityType.DOCUMENT_REQUESTED,
            performed_by=performed_by,
            description=f"Additional document requested: {document_type}. Reason: {reason}",
            previous_status=prev,
            new_status=OnboardingStatus.DOCUMENTS_REQUESTED,
            payload={
                "document_request_id":str(doc_request.id),
                "document_type":document_type,
                "reason":reason,
                "deadline":deadline.isoformat() if deadline else None,
            },
        )
        return doc_request

    @transaction.atomic
    def approve(
            self,
            onboarding: OrganizationOnboarding,
            performed_by: SystemUser,
            internal_notes: str = ""
    ) -> OrganizationOnboarding:
        if onboarding.status != OnboardingStatus.UNDER_REVIEW:
            raise OnboardingError("Can only approve an application that is under review.")

        if onboarding.documents.filter(status=DocumentStatus.PENDING).exists():
            raise OnboardingError("All documents must be reviewed before approval.")

        prev = onboarding.status
        onboarding.status = OnboardingStatus.APPROVED
        onboarding.completed_at = timezone.now()
        if internal_notes:
            onboarding.internal_notes = (onboarding.internal_notes+f"\n\n{internal_notes}").strip()
        onboarding.save(update_fields=["status","completed_at","internal_notes"])

        self._log(
            onboarding=onboarding,
            activity_type=OnboardingActivityType.APPROVED,
            performed_by=performed_by,
            description="Application approved.",
            previous_status=prev,
            new_status=OnboardingStatus.APPROVED,
        )
        return onboarding

    @transaction.atomic
    def reject(
            self,
            onboarding: OrganizationOnboarding,
            performed_by: SystemUser,
            reason: str,
            applicant_notes: str = "",
            internal_notes: str = ""
    ) -> OrganizationOnboarding:
        if onboarding.status not in (OnboardingStatus.UNDER_REVIEW, OnboardingStatus.SUBMITTED):
            raise OnboardingError("Can only reject a submitted or under-review application.")

        if not reason.strip():
            raise OnboardingError("A rejection reason is required.")

        prev = onboarding.status
        onboarding.status = OnboardingStatus.REJECTED
        onboarding.completed_at = timezone.now()
        onboarding.applicant_notes =(applicant_notes or reason).strip()
        if internal_notes:
            onboarding.internal_notes = (onboarding.internal_notes+f"\n\n{internal_notes}").strip()
        onboarding.save(update_fields=["status","completed_at","applicant_notes","internal_notes"])

        self._log(
            onboarding=onboarding,
            activity_type=OnboardingActivityType.REJECTED,
            performed_by=performed_by,
            description=f"Application rejected. Reason: {reason}",
            previous_status=prev,
            new_status=OnboardingStatus.REJECTED,
            payload={"reason":reason},
        )
        return onboarding

    @transaction.atomic
    def complete_onboarding(self, onboarding: OrganizationOnboarding, performed_by: SystemUser) -> Organization:
        if onboarding.status != OnboardingStatus.APPROVED:
            raise OnboardingError("Can only complete an approved application.")

        if onboarding.organization_id and onboarding.created_organization_id:
            return onboarding.organization
        if onboarding.created_organization_id:
            return onboarding.created_organization

        if onboarding.organization_id:
            org = onboarding.organization
        else:
            slug = self._unique_slug(onboarding.system,onboarding.legal_name)
            org = Organization.objects.create(
                system=onboarding.system,
                name=onboarding.trading_name or onboarding.legal_name,
                slug=slug,
                description=onboarding.description,
                website=onboarding.website,
                verified=True,
                verified_at=timezone.now(),
                verified_by=performed_by,
                onboarding=onboarding,
            )
            onboarding.organization = org

        country_requests = list(onboarding.country_requests.select_related("country").all())
        if not country_requests:
            raise OnboardingError("At least one country is required.")

        for country_request in country_requests:
            OrganizationCountry.objects.update_or_create(
                organization=org,
                country=country_request.country,
                defaults={
                    "registration_number": country_request.registration_number,
                    "tax_id": country_request.tax_id,
                    "approval_status": OrganizationCountry.ApprovalStatus.APPROVED,
                    "approved_at": timezone.now(),
                    "approved_by": performed_by,
                    "source_onboarding": onboarding,
                    "is_active": True,
                },
            )

        onboarding.status = OnboardingStatus.ONBOARDED
        onboarding.save(update_fields=["status", "organization"])

        self._log(
            onboarding=onboarding,
            activity_type=OnboardingActivityType.ONBOARDED,
            performed_by=performed_by,
            description=f"Organisation '{org.name}' onboarded.",
            previous_status=OnboardingStatus.APPROVED,
            new_status=OnboardingStatus.ONBOARDED,
            payload={
                "organization_id": str(org.id),
                "slug": org.slug,
                "country_codes": [country_request.country.code for country_request in country_requests],
            },
        )
        return org

    @transaction.atomic
    def upload_document(
            self,
            onboarding: OrganizationOnboarding,
            uploaded_by: SystemUser,
            document_type: str,
            file: UploadedFile,
            label: str = "",
            expires_at: Optional[datetime.datetime]=None,
            fulfils_request_id:Optional[str] = None
    ) -> OnboardingDocument:
        if not onboarding.is_editable_by_applicant:
            raise OnboardingError(f"Documents cannot be uploaded in status '{onboarding.status}'.")

        if not file:
            raise OnboardingError("file is required.")

        previous = onboarding.documents.filter(document_type=document_type).order_by("-created_at").first()
        doc = self._create_document(
            onboarding=onboarding,
            uploaded_by=uploaded_by,
            document_type=document_type,
            file=file,
            label=label,
            expires_at=expires_at,
            replaces=previous,
        )

        if fulfils_request_id:
            DocumentRequest.objects.filter(
                id=fulfils_request_id,
                onboarding=onboarding,
                fulfilled_at__isnull=True
            ).update(
                fulfilled_by_document=doc,
                fulfilled_at=timezone.now()
            )
        else:
            DocumentRequest.objects.filter(
                onboarding=onboarding,
                document_type=document_type,
                fulfilled_at__isnull=True
            ).update(
                fulfilled_by_document=doc,
                fulfilled_at=timezone.now()
            )

        self._log(
            onboarding=onboarding,
            activity_type=OnboardingActivityType.DOCUMENT_UPLOADED,
            performed_by=uploaded_by,
            description=f"Document uploaded: {doc.get_document_type_display()} ({file.name}).",
            document=doc,
            payload={
                "document_id":str(doc.id),
                "document_type":document_type,
                "file_name":file.name,
                "replaces":str(previous.id) if previous else None,
            },
        )
        return doc

    @transaction.atomic
    def remove_document(
        self,
        document: OnboardingDocument,
        performed_by: SystemUser,
    ) -> None:
        onboarding = document.onboarding
        if not onboarding.is_editable_by_applicant:
            raise OnboardingError(f"Documents cannot be removed in status '{onboarding.status}'.")
        if document.document_type in MANDATORY_DOCUMENT_TYPES:
            raise OnboardingError("Mandatory documents cannot be removed. Upload an updated document instead.")

        document_id = str(document.id)
        document_type = document.document_type
        file_name = document.file_name
        self._log(
            onboarding=onboarding,
            activity_type=OnboardingActivityType.UPDATED,
            performed_by=performed_by,
            description=f"Document removed: {document.get_document_type_display()} ({file_name}).",
            document=document,
            payload={
                "removed_document_id": document_id,
                "document_type": document_type,
                "file_name": file_name,
            },
        )
        document.delete()

    @transaction.atomic
    def review_document(
            self,
            document: OnboardingDocument,
            reviewed_by: SystemUser,
            approved: bool,
            notes: str = ""
    ) -> OnboardingDocument:
        if document.status not in (DocumentStatus.PENDING,DocumentStatus.REJECTED):
            raise OnboardingError(f"Document is already in status '{document.status}'.")

        document.status = DocumentStatus.APPROVED if approved else DocumentStatus.REJECTED
        document.reviewed_by = reviewed_by
        document.reviewed_at = timezone.now()
        document.review_notes = notes
        document.save(update_fields=["status","reviewed_by","reviewed_at","review_notes"])

        self._log(
            onboarding=document.onboarding,
            activity_type=OnboardingActivityType.DOCUMENT_REVIEWED,
            performed_by=reviewed_by,
            description=f"Document {'approved' if approved else 'rejected'}: "
                        f"{document.get_document_type_display()}. {notes}".strip(),
            document=document,
            payload={
                "document_id":str(document.id),
                "document_type":document.document_type,
                "approved":approved,
                "notes":notes,
            },
        )
        return document

    @transaction.atomic
    def add_note(
            self,
            onboarding: OrganizationOnboarding,
            performed_by: SystemUser,
            note: str,
            internal: bool = False
    ) -> OnboardingActivity:
        if not note.strip():
            raise OnboardingError("Note cannot be empty.")
        if internal:
            onboarding.internal_notes = (onboarding.internal_notes+f"\n\n{note}").strip()
            onboarding.save(update_fields=["internal_notes"])
        else:
            onboarding.applicant_notes = (onboarding.applicant_notes+f"\n\n{note}").strip()
            onboarding.save(update_fields=["applicant_notes"])
        return self._log(
            onboarding=onboarding,
            activity_type=OnboardingActivityType.NOTE_ADDED,
            performed_by=performed_by,
            description=f"{'Internal note' if internal else 'Note'} added.",
            payload={"internal":internal,"note":note},
        )

    @staticmethod
    def _validate_mandatory_documents(documents: DocumentInput) -> None:
        missing = []
        for doc_type in MANDATORY_DOCUMENT_TYPES:
            if not documents.get(doc_type):
                missing.append(MANDATORY_DOCUMENT_LABELS[doc_type])
        if missing:
            raise OnboardingError(
                f"The following documents are required to submit an application: {', '.join(missing)}."
            )

    @staticmethod
    def _assert_mandatory_documents_present(onboarding: OrganizationOnboarding) -> None:
        missing = []
        for doc_type in MANDATORY_DOCUMENT_TYPES:
            if not onboarding.documents.filter(document_type=doc_type).exclude(
                    status=DocumentStatus.REJECTED).exists():
                missing.append(MANDATORY_DOCUMENT_LABELS[doc_type])
        if missing:
            raise OnboardingError(
                f"Cannot submit: the following mandatory documents are missing or rejected and must be re-uploaded: "
                f"{', '.join(missing)}."
            )

    @staticmethod
    def _create_document(
        onboarding: OrganizationOnboarding,
        uploaded_by: SystemUser,
        document_type: str,
        file: UploadedFile,
        label: str = "",
        expires_at: Optional[datetime.datetime] = None,
        replaces: Optional[OnboardingDocument] = None,
    )->OnboardingDocument:
        if hasattr(file, "seek"):
            file.seek(0)
        return OnboardingDocument.objects.create(
            onboarding=onboarding,
            document_type=document_type,
            label=label,
            file=file,
            file_name=file.name,
            file_size=file.size,
            mime_type=file.content_type,
            status=DocumentStatus.PENDING,
            uploaded_by=uploaded_by,
            expires_at=expires_at,
            replaces=replaces,
        )

    @staticmethod
    def _create_country_request(
        onboarding: OrganizationOnboarding,
        country: Country,
        registration_number: str = "",
        tax_id: str = "",
        address: str = "",
        metadata: Optional[dict] = None,
    ) -> OrganizationOnboardingCountry:
        return OrganizationOnboardingCountry.objects.create(
            onboarding=onboarding,
            country=country,
            registration_number=registration_number,
            tax_id=tax_id,
            address=address,
            metadata=metadata or {},
        )

    @staticmethod
    def _unique_slug(system: System, name: str) -> str:
        base = slugify(name)[:110]
        slug = base
        i = 1
        while Organization.objects.filter(system=system,slug=slug).exists():
            slug=f"{base}-{i}"
            i+=1
        return slug

    @staticmethod
    def _validate_choice(value: str, allowed: list[str], field_name: str) -> None:
        if value and value not in allowed:
            raise OnboardingError(f"Invalid {field_name}.")

    @staticmethod
    def _validate_multi_select(values: list[str], allowed: list[str], field_name: str) -> list[str]:
        invalid = [value for value in values if value not in allowed]
        if invalid:
            raise OnboardingError(f"Invalid {field_name}: {', '.join(invalid)}.")
        return values

    @staticmethod
    def _active_statuses() -> list[str]:
        return [
            OnboardingStatus.DRAFT,
            OnboardingStatus.SUBMITTED,
            OnboardingStatus.DOCUMENTS_REQUESTED,
            OnboardingStatus.UNDER_REVIEW,
            OnboardingStatus.APPROVED,
        ]

    def _assert_country_can_onboard(
        self,
        system: System,
        country: Country,
        contact_system_user: SystemUser,
        organization: Optional[Organization] = None,
        exclude_onboarding_ids: Optional[list] = None,
    ) -> None:
        existing_country_requests = OrganizationOnboardingCountry.objects.filter(
            onboarding__system=system,
            country=country,
            onboarding__status__in=self._active_statuses(),
        )
        if exclude_onboarding_ids:
            existing_country_requests = existing_country_requests.exclude(onboarding_id__in=exclude_onboarding_ids)
        if organization:
            if OrganizationCountry.objects.filter(
                organization=organization,
                country=country,
                approval_status=OrganizationCountry.ApprovalStatus.APPROVED,
                is_active=True,
            ).exists():
                raise OnboardingError(
                    f"{organization.name} is already approved for {country.name}."
                )
            existing_country_requests = existing_country_requests.filter(onboarding__organization=organization)
        else:
            existing_country_requests = existing_country_requests.filter(
                onboarding__contact_system_user=contact_system_user,
                onboarding__organization__isnull=True,
            )

        existing_country_request = existing_country_requests.select_related("onboarding").first()
        if existing_country_request:
            existing_onboarding = existing_country_request.onboarding
            raise OnboardingError(
                f"You already have an active onboarding application for {country.name} "
                f"(status: {existing_onboarding.get_status_display()})."
            )

    @staticmethod
    def _log(
        onboarding: OrganizationOnboarding,
        activity_type: str,
        performed_by: Optional[SystemUser] = None,
        description: str = "",
        previous_status: str = "",
        new_status: str = "",
        document: Optional[OnboardingDocument] = None,
        payload: Optional[dict] = None,
    )->OnboardingActivity:
        return OnboardingActivity.objects.create(
            onboarding=onboarding,
            activity_type=activity_type,
            performed_by=performed_by,
            description=description,
            previous_status=previous_status,
            new_status=new_status,
            document=document,
            payload=payload or {},
        )
