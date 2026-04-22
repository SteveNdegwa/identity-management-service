import datetime
from typing import Optional
from django.core.files.uploadedfile import UploadedFile
from django.db import transaction
from django.utils import timezone
from django.utils.text import slugify

from apps.accounts.models import SystemUser
from apps.base.models import Country
from apps.organizations.models import (
    Organization,
    OrganizationCountry,
    OrganizationOnboarding,
    OnboardingStatus,
    OnboardingDocument,
    DocumentStatus,
    OnboardingActivity,
    OnboardingActivityType,
    DocumentRequest,
    MANDATORY_DOCUMENT_TYPES,
    MANDATORY_DOCUMENT_LABELS,
)
from apps.systems.models import System
from organizations.models import DocumentType


class OnboardingError(Exception):
    pass


DocumentInput = dict[str,UploadedFile]


class OnboardingService:

    @transaction.atomic
    def create_application(
        self,
        system: System,
        country: Country,
        contact_system_user: SystemUser,
        legal_name: str,
        documents: DocumentInput,
        trading_name: str = "",
        registration_number: str = "",
        tax_id: str = "",
        address: str = "",
        contact_email: str = "",
        contact_phone: str = "",
        website: str = "",
        description: str = "",
        metadata: Optional[dict] = None,
    ) -> OrganizationOnboarding:
        if not legal_name.strip():
            raise OnboardingError("Legal name is required.")

        self._validate_mandatory_documents(documents)

        existing = OrganizationOnboarding.objects.filter(
            system=system,
            country=country,
            contact_system_user=contact_system_user,
            status__in=[
                OnboardingStatus.DRAFT,
                OnboardingStatus.SUBMITTED,
                OnboardingStatus.DOCUMENTS_REQUESTED,
                OnboardingStatus.UNDER_REVIEW,
                OnboardingStatus.APPROVED,
            ],
        ).first()
        if existing:
            raise OnboardingError(
                f"You already have an active onboarding application for {country.name} "
                f"(status: {existing.get_status_display()})."
            )

        onboarding = OrganizationOnboarding.objects.create(
            system=system,
            country=country,
            contact_system_user=contact_system_user,
            status=OnboardingStatus.DRAFT,
            legal_name=legal_name.strip(),
            trading_name=trading_name,
            registration_number=registration_number,
            tax_id=tax_id,
            address=address,
            contact_email=contact_email,
            contact_phone=contact_phone,
            website=website,
            description=description,
            metadata=metadata or {},
        )

        for doc_type in DocumentType.values:
            file = documents[doc_type]
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

        allowed = {
            "legal_name", "trading_name", "registration_number", "tax_id",
            "address", "contact_email", "contact_phone", "website",
            "description", "metadata"
        }
        updated = []
        for k,v in fields.items():
            if k in allowed:
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
    def submit(self, onboarding: OrganizationOnboarding, performed_by: SystemUser) -> OrganizationOnboarding:
        if onboarding.status not in (OnboardingStatus.DRAFT,OnboardingStatus.DOCUMENTS_REQUESTED):
            raise OnboardingError(f"Cannot submit an application in status '{onboarding.status}'.")

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

        if onboarding.created_organization_id:
            return onboarding.created_organization

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

        OrganizationCountry.objects.create(
            organization=org,
            country=onboarding.country,
            registration_number=onboarding.registration_number,
            tax_id=onboarding.tax_id,
        )

        onboarding.status = OnboardingStatus.ONBOARDED
        onboarding.save(update_fields=["status"])

        self._log(
            onboarding=onboarding,
            activity_type=OnboardingActivityType.ONBOARDED,
            performed_by=performed_by,
            description=f"Organisation '{org.name}' created and onboarded.",
            previous_status=OnboardingStatus.APPROVED,
            new_status=OnboardingStatus.ONBOARDED,
            payload={"organization_id":str(org.id),"slug":slug},
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
    def _unique_slug(system: System, name: str) -> str:
        base = slugify(name)[:110]
        slug = base
        i = 1
        while Organization.objects.filter(system=system,slug=slug).exists():
            slug=f"{base}-{i}"
            i+=1
        return slug

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