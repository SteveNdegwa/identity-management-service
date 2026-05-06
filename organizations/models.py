import json

from django.db import models
from django.utils import timezone

from base.models import BaseModel


class Organization(BaseModel):
    system = models.ForeignKey(
        "systems.System",
        on_delete=models.CASCADE,
        related_name="organizations"
    )
    name = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    slug = models.SlugField(max_length=120)
    logo_url = models.URLField(blank=True)
    website = models.URLField(blank=True)
    countries = models.ManyToManyField(
        "base.Country",
        through="OrganizationCountry",
        related_name="organizations"
    )
    is_active = models.BooleanField(default=True)
    verified = models.BooleanField(default=False)
    verified_at = models.DateTimeField(null=True, blank=True)
    verified_by = models.ForeignKey(
        "accounts.SystemUser",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="verified_organizations",
    )
    onboarding = models.OneToOneField(
        "organizations.OrganizationOnboarding",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="created_organization",
    )

    class Meta:
        db_table = "organizations_organization"
        unique_together = [("system", "slug")]

    def __str__(self):
        return f"{self.name} ({self.system})"


class OrganizationCountry(BaseModel):
    class ApprovalStatus(models.TextChoices):
        PENDING = "pending", "Pending"
        APPROVED = "approved", "Approved"
        REJECTED = "rejected", "Rejected"

    organization = models.ForeignKey(
        Organization,
        on_delete=models.CASCADE,
        related_name="organization_countries"
    )
    country = models.ForeignKey(
        "base.Country",
        on_delete=models.CASCADE,
        related_name="organization_countries"
    )
    registration_number = models.CharField(max_length=120, blank=True)
    tax_id = models.CharField(max_length=120, blank=True)
    approval_status = models.CharField(
        max_length=20,
        choices=ApprovalStatus.choices,
        default=ApprovalStatus.APPROVED,
        db_index=True,
    )
    approved_at = models.DateTimeField(null=True, blank=True)
    approved_by = models.ForeignKey(
        "accounts.SystemUser",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="approved_organization_countries",
    )
    source_onboarding = models.ForeignKey(
        "organizations.OrganizationOnboarding",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="country_results",
    )
    is_active = models.BooleanField(default=True)
    activated_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "organizations_organization_country"
        unique_together = [("organization", "country")]
        verbose_name_plural = "Organization countries"

    def __str__(self):
        return f"{self.organization.name} - {self.country.code}"


class Branch(BaseModel):
    organization = models.ForeignKey(
        Organization,
        on_delete=models.CASCADE,
        related_name="branches"
    )
    country = models.ForeignKey(
        "base.Country",
        on_delete=models.PROTECT,
        related_name="branches"
    )
    name = models.CharField(max_length=255)
    code = models.CharField(max_length=40, blank=True)
    parent = models.ForeignKey(
        "self",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="children"
    )
    is_active = models.BooleanField(default=True)
    metadata = models.JSONField(default=dict, blank=True)

    class Meta:
        db_table = "organizations_branch"
        unique_together = [("organization", "country", "code")]

    def __str__(self):
        return f"{self.name} ({self.organization.name}, {self.country.code})"


class OrganizationSettings(BaseModel):
    class ValueType(models.TextChoices):
        STRING = "string", "String"
        INTEGER = "integer", "Integer"
        BOOLEAN = "boolean", "Boolean"
        JSON = "json", "JSON"
        URL = "url", "URL"

    organization = models.ForeignKey(
        Organization,
        on_delete=models.CASCADE,
        related_name="settings"
    )
    key = models.CharField(max_length=120)
    value = models.TextField()
    value_type = models.CharField(
        max_length=20,
        choices=ValueType.choices,
        default=ValueType.STRING
    )
    description = models.TextField(blank=True)
    is_secret = models.BooleanField(default=False)
    updated_by = models.ForeignKey(
        "accounts.SystemUser",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
    )

    class Meta:
        db_table = "organizations_settings"
        unique_together = [("organization", "key")]
        verbose_name_plural = "Organization settings"

    def __str__(self):
        return f"{self.organization.name}.{self.key}"

    def typed_value(self):
        if self.value_type == self.ValueType.BOOLEAN:
            return self.value.lower() in ("true", "1", "yes")
        if self.value_type == self.ValueType.INTEGER:
            return int(self.value)
        if self.value_type == self.ValueType.JSON:
            return json.loads(self.value)
        return self.value


class OnboardingStatus(models.TextChoices):
    DRAFT = "draft", "Draft"
    SUBMITTED = "submitted", "Submitted — Awaiting Review"
    DOCUMENTS_REQUESTED = "documents_requested", "Additional Documents Requested"
    UNDER_REVIEW = "under_review", "Under Review"
    APPROVED = "approved", "Approved"
    REJECTED = "rejected", "Rejected"
    ONBOARDED = "onboarded", "Onboarded"


class OrganizationOnboarding(BaseModel):
    class OrganizationType(models.TextChoices):
        BANK = "bank", "Bank"
        MICROFINANCE_BANK = "microfinance_bank", "Microfinance Bank"
        MICROFINANCE = "microfinance", "Microfinance"
        MOBILE_LENDER = "mobile_lender", "Mobile Lender"
        INSURANCE = "insurance", "Insurance"
        SACCO = "sacco", "SACCO"
        RESELLER = "reseller", "Reseller"
        OTHER = "other", "Other"

    class ProductNeed(models.TextChoices):
        STATEMENT_ANALYSIS = "statement_analysis", "Statement analysis"
        KYC_KYB_CHECKS = "kyc_kyb_checks", "KYC / KYB checks"
        MACRO_INSIGHTS = "macro_insights", "Macro insights"
        CUSTOM_DATA_ANALYSIS = "custom_data_analysis", "Custom data analysis"
        FRAUD_CHECKS = "fraud_checks", "Fraud checks"

    class MonthlyTransactionVolume(models.TextChoices):
        BELOW_500 = "below_500", "Below 500"
        FROM_501_TO_2500 = "501_to_2500", "501 - 2,500"
        FROM_2501_TO_5000 = "2501_to_5000", "2,501 - 5,000"
        FROM_5001_TO_10000 = "5001_to_10000", "5,001 - 10,000"
        FROM_10001_TO_30000 = "10001_to_30000", "10,001 - 30,000"
        ABOVE_30000 = "above_30000", "Above 30,000"

    class StaffSize(models.TextChoices):
        FROM_1_TO_5 = "1_to_5", "1-5"
        FROM_6_TO_20 = "6_to_20", "6-20"
        FROM_21_TO_50 = "21_to_50", "21-50"
        FROM_50_TO_100 = "50_to_100", "50-100"
        ABOVE_100 = "above_100", "Above 100"

    class PainPoint(models.TextChoices):
        MANUAL_ANALYSIS = "manual_analysis", "Manual analysis"
        HIGH_NPL = "high_npl", "High NPL"
        SLOW_CREDIT_DECISION = "slow_credit_decision", "Slow credit decision"
        FRAUD = "fraud", "Fraud"
        MANUAL_ONBOARDING = "manual_onboarding", "Manual onboarding"
        MANUAL_VERIFICATIONS = "manual_verifications", "Manual verifications"

    system = models.ForeignKey(
        "systems.System",
        on_delete=models.CASCADE,
        related_name="onboardings"
    )
    status = models.CharField(
        max_length=30,
        choices=OnboardingStatus.choices,
        default=OnboardingStatus.DRAFT,
        db_index=True,
    )
    contact_system_user = models.ForeignKey(
        "accounts.SystemUser",
        on_delete=models.PROTECT,
        related_name="submitted_onboardings",
    )
    organization = models.ForeignKey(
        Organization,
        null=True,
        blank=True,
        on_delete=models.PROTECT,
        related_name="onboarding_requests",
    )
    legal_name = models.CharField(max_length=255)
    trading_name = models.CharField(max_length=255, blank=True)
    organization_type = models.CharField(
        max_length=40,
        choices=OrganizationType.choices,
        blank=True,
    )
    products_needed = models.JSONField(default=list, blank=True)
    monthly_transaction_volume = models.CharField(
        max_length=20,
        choices=MonthlyTransactionVolume.choices,
        blank=True,
    )
    staff_size = models.CharField(
        max_length=20,
        choices=StaffSize.choices,
        blank=True,
    )
    pain_points = models.JSONField(default=list, blank=True)
    contact_email = models.EmailField(blank=True)
    contact_phone = models.CharField(max_length=30, blank=True)
    website = models.URLField(blank=True)
    description = models.TextField(blank=True)
    metadata = models.JSONField(default=dict, blank=True)
    applicant_notes = models.TextField(blank=True)
    internal_notes = models.TextField(blank=True)
    submitted_at = models.DateTimeField(null=True, blank=True)
    reviewed_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    assigned_to = models.ForeignKey(
        "accounts.SystemUser",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="assigned_onboardings",
    )

    class Meta:
        db_table = "organizations_onboarding"
        indexes = [
            models.Index(fields=["system", "status"]),
            models.Index(fields=["contact_system_user"]),
        ]

    def __str__(self):
        return f"{self.legal_name} — {self.status}"

    @property
    def is_editable_by_applicant(self):
        return self.status in (OnboardingStatus.DRAFT, OnboardingStatus.DOCUMENTS_REQUESTED)

    @property
    def editable_by_client(self):
        return self.is_editable_by_applicant

    @property
    def is_active(self):
        return self.status not in (OnboardingStatus.REJECTED, OnboardingStatus.ONBOARDED)


class OrganizationOnboardingCountry(BaseModel):
    onboarding = models.ForeignKey(
        OrganizationOnboarding,
        on_delete=models.CASCADE,
        related_name="country_requests",
    )
    country = models.ForeignKey(
        "base.Country",
        on_delete=models.PROTECT,
        related_name="onboarding_country_requests",
    )
    registration_number = models.CharField(max_length=120, blank=True)
    tax_id = models.CharField(max_length=120, blank=True)
    address = models.TextField(blank=True)
    metadata = models.JSONField(default=dict, blank=True)

    class Meta:
        db_table = "organizations_onboarding_country"
        unique_together = [("onboarding", "country")]
        indexes = [
            models.Index(fields=["onboarding", "country"]),
        ]
        verbose_name_plural = "Onboarding countries"

    def __str__(self):
        return f"{self.onboarding.legal_name} / {self.country.code}"


class DocumentType(models.TextChoices):
    BUSINESS_REGISTRATION = "business_registration", "Business Registration Certificate"
    KRA_PIN = "kra_pin", "KRA PIN Certificate"
    TAX_COMPLIANCE = "tax_compliance", "Tax Compliance Certificate"
    MEMORANDUM = "memorandum", "Memorandum & Articles of Association"
    DIRECTOR_ID = "director_id", "Director National ID / Passport"
    LICENCE = "licence", "Operating Licence"
    OTHER = "other", "Other"


MANDATORY_DOCUMENT_TYPES: list[str] = [
    DocumentType.BUSINESS_REGISTRATION,
    DocumentType.KRA_PIN,
]

MANDATORY_DOCUMENT_LABELS: dict[str, str] = {
    DocumentType.BUSINESS_REGISTRATION: "Business Registration Certificate",
    DocumentType.KRA_PIN: "KRA PIN Certificate",
}


class DocumentStatus(models.TextChoices):
    PENDING = "pending", "Pending Review"
    APPROVED = "approved", "Approved"
    REJECTED = "rejected", "Rejected"
    EXPIRED = "expired", "Expired"


class OnboardingDocument(BaseModel):
    onboarding = models.ForeignKey(
        OrganizationOnboarding,
        on_delete=models.CASCADE,
        related_name="documents"
    )
    document_type = models.CharField(max_length=40, choices=DocumentType.choices)
    label = models.CharField(max_length=120, blank=True)
    file = models.FileField(upload_to="onboarding/documents/")
    file_name = models.CharField(max_length=255, blank=True)
    file_size = models.PositiveIntegerField(null=True, blank=True)
    mime_type = models.CharField(max_length=80, blank=True)
    status = models.CharField(
        max_length=20,
        choices=DocumentStatus.choices,
        default=DocumentStatus.PENDING,
        db_index=True
    )
    uploaded_by = models.ForeignKey(
        "accounts.SystemUser",
        on_delete=models.PROTECT,
        related_name="uploaded_documents"
    )
    uploaded_at = models.DateTimeField(auto_now_add=True)
    reviewed_by = models.ForeignKey(
        "accounts.SystemUser",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="reviewed_documents"
    )
    reviewed_at = models.DateTimeField(null=True, blank=True)
    review_notes = models.TextField(blank=True)
    replaces = models.ForeignKey(
        "self",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="replaced_by",
    )
    expires_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = "organizations_onboarding_document"
        indexes = [
            models.Index(fields=["onboarding", "document_type"]),
            models.Index(fields=["onboarding", "status"]),
        ]

    def __str__(self):
        return f"{self.document_type} — {self.onboarding}"

    @property
    def is_expired(self):
        return self.expires_at is not None and timezone.now() > self.expires_at

    def save(self, *args, **kwargs):
        if self.file:
            self.file_name = self.file.name
            self.file_size = self.file.size
            self.mime_type = getattr(self.file.file, "content_type", "")
        if not self.label and self.document_type:
            self.label = self.get_document_type_display()
        super().save(*args, **kwargs)


class OnboardingActivityType(models.TextChoices):
    CREATED = "created", "Application created"
    UPDATED = "updated", "Application updated"
    SUBMITTED = "submitted", "Application submitted"
    DOCUMENT_UPLOADED = "document_uploaded", "Document uploaded"
    DOCUMENT_REVIEWED = "document_reviewed", "Document reviewed"
    DOCUMENT_REQUESTED = "document_requested", "Additional document requested"
    NOTE_ADDED = "note_added", "Note added"
    ASSIGNED = "assigned", "Assigned to reviewer"
    APPROVED = "approved", "Application approved"
    REJECTED = "rejected", "Application rejected"
    ONBOARDED = "onboarded", "Organisation onboarded"


class OnboardingActivity(BaseModel):
    onboarding = models.ForeignKey(
        OrganizationOnboarding,
        on_delete=models.CASCADE,
        related_name="activities"
    )
    activity_type = models.CharField(
        max_length=40,
        choices=OnboardingActivityType.choices,
        db_index=True
    )
    performed_by = models.ForeignKey(
        "accounts.SystemUser",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="onboarding_activities"
    )
    description = models.TextField(blank=True)
    payload = models.JSONField(default=dict, blank=True)
    previous_status = models.CharField(max_length=30, blank=True)
    new_status = models.CharField(max_length=30, blank=True)
    document = models.ForeignKey(
        OnboardingDocument,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="activities"
    )

    class Meta:
        db_table = "organizations_onboarding_activity"
        ordering = ["-created_at"]
        verbose_name_plural = "Onboarding activities"
        indexes = [
            models.Index(fields=["onboarding", "activity_type"]),
            models.Index(fields=["onboarding", "created_at"]),
        ]

    def __str__(self):
        return f"{self.activity_type} — {self.onboarding} @ {self.created_at}"


class DocumentRequest(BaseModel):
    onboarding = models.ForeignKey(
        OrganizationOnboarding,
        on_delete=models.CASCADE,
        related_name="document_requests"
    )
    document_type = models.CharField(max_length=40, choices=DocumentType.choices)
    label = models.CharField(max_length=120, blank=True)
    reason = models.TextField()
    requested_by  = models.ForeignKey(
        "accounts.SystemUser",
        on_delete=models.PROTECT,
        related_name="issued_document_requests",
    )
    requested_at = models.DateTimeField(auto_now_add=True)
    fulfilled_by_document = models.ForeignKey(
        OnboardingDocument,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="fulfils_request",
    )
    fulfilled_at = models.DateTimeField(null=True, blank=True)
    deadline = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = "organizations_document_request"
        indexes = [models.Index(fields=["onboarding", "fulfilled_at"])]

    def __str__(self):
        return f"Request for {self.document_type} on {self.onboarding}"

    @property
    def is_fulfilled(self):
        return self.fulfilled_at is not None

    @property
    def is_overdue(self):
        return self.deadline is not None and not self.is_fulfilled and timezone.now() > self.deadline
