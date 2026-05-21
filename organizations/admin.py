from django.contrib import admin

from .models import (
    Organization,
    OrganizationCountry,
    Branch,
    OrganizationSettings,
    OrganizationOnboarding,
    OrganizationOnboardingCountry,
    OnboardingDocument,
    OnboardingActivity,
    OnboardingServiceProduct,
    OnboardingServiceSelection,
    OnboardingPayment,
    OnboardingVerificationCheck,
    OnboardingVerificationRun,
)


class OrganizationCountryInline(admin.TabularInline):
    model = OrganizationCountry
    extra = 0
    autocomplete_fields = ("country", "approved_by", "source_onboarding")
    readonly_fields = ("activated_at",)
    ordering = ("-activated_at",)


class BranchInline(admin.TabularInline):
    model = Branch
    extra = 0
    autocomplete_fields = ("country", "parent")
    ordering = ("name",)


class OrganizationSettingsInline(admin.TabularInline):
    model = OrganizationSettings
    extra = 0
    autocomplete_fields = ("updated_by",)
    ordering = ("key",)


@admin.register(Organization)
class OrganizationAdmin(admin.ModelAdmin):
    list_display = ("name", "system", "slug", "is_active", "verified", "verified_at")
    list_filter = ("is_active", "verified", "system")
    search_fields = ("name", "slug")
    ordering = ("name",)
    autocomplete_fields = ("system", "verified_by", "onboarding")

    inlines = (
        OrganizationCountryInline,
        BranchInline,
        OrganizationSettingsInline,
    )

    fieldsets = (
        ("Basic Information", {
            "fields": ("system", "name", "slug", "description", "logo_url", "website")
        }),
        ("Status", {
            "fields": ("is_active", "verified", "verified_at", "verified_by", "onboarding")
        }),
        ("Audit", {
            "fields": ("created_at", "updated_at")
        }),
    )

    readonly_fields = ("created_at", "updated_at")

    def get_queryset(self, request):
        return super().get_queryset(request).select_related("system")


@admin.register(OrganizationCountry)
class OrganizationCountryAdmin(admin.ModelAdmin):
    list_display = ("organization", "country", "registration_number", "tax_id", "approval_status", "is_active")
    list_filter = ("country", "approval_status", "is_active")
    search_fields = ("organization__name", "registration_number", "tax_id")
    ordering = ("organization",)
    autocomplete_fields = ("organization", "country", "approved_by", "source_onboarding")

    fieldsets = (
        ("Details", {
            "fields": ("organization", "country", "registration_number", "tax_id", "is_active")
        }),
        ("Approval", {
            "fields": ("approval_status", "approved_at", "approved_by", "source_onboarding")
        }),
        ("Audit", {
            "fields": ("created_at", "updated_at")
        }),
    )

    readonly_fields = ("created_at", "updated_at")

    def get_queryset(self, request):
        return super().get_queryset(request).select_related("organization", "country", "approved_by", "source_onboarding")


@admin.register(Branch)
class BranchAdmin(admin.ModelAdmin):
    list_display = ("name", "organization", "country", "code", "is_active")
    list_filter = ("country", "is_active")
    search_fields = ("name", "code")
    ordering = ("name",)
    autocomplete_fields = ("organization", "country", "parent")

    fieldsets = (
        ("Branch Details", {
            "fields": ("organization", "country", "name", "code", "parent", "metadata", "is_active")
        }),
        ("Audit", {
            "fields": ("created_at", "updated_at")
        }),
    )

    readonly_fields = ("created_at", "updated_at")

    def get_queryset(self, request):
        return super().get_queryset(request).select_related(
            "organization", "country", "parent"
        )


@admin.register(OrganizationSettings)
class OrganizationSettingsAdmin(admin.ModelAdmin):
    list_display = ("organization", "key", "value_type", "is_secret")
    list_filter = ("value_type", "is_secret")
    search_fields = ("key", "value")
    ordering = ("organization", "key")
    autocomplete_fields = ("organization", "updated_by")

    fieldsets = (
        ("Settings", {
            "fields": (
                "organization",
                "key",
                "value",
                "value_type",
                "description",
                "is_secret",
                "updated_by",
            )
        }),
        ("Audit", {
            "fields": ("created_at", "updated_at")
        }),
    )

    readonly_fields = ("created_at", "updated_at")

    def get_queryset(self, request):
        return super().get_queryset(request).select_related("organization")


class OnboardingDocumentInline(admin.TabularInline):
    model = OnboardingDocument
    extra = 0
    autocomplete_fields = ("uploaded_by", "reviewed_by", "replaces")
    readonly_fields = ("uploaded_at", "file_name", "file_size", "mime_type")
    ordering = ("-uploaded_at",)


class OnboardingActivityInline(admin.TabularInline):
    model = OnboardingActivity
    extra = 0
    autocomplete_fields = ("performed_by", "document")
    readonly_fields = ("created_at",)
    ordering = ("-created_at",)


class OnboardingCountryInline(admin.TabularInline):
    model = OrganizationOnboardingCountry
    extra = 0
    autocomplete_fields = ("country",)
    ordering = ("created_at",)


class OnboardingServiceSelectionInline(admin.TabularInline):
    model = OnboardingServiceSelection
    extra = 0
    autocomplete_fields = ("service", "selected_by")
    ordering = ("service__sort_order",)


class OnboardingPaymentInline(admin.TabularInline):
    model = OnboardingPayment
    extra = 0
    autocomplete_fields = ("recorded_by",)
    readonly_fields = ("paid_at",)
    ordering = ("-created_at",)


class OnboardingVerificationRunInline(admin.TabularInline):
    model = OnboardingVerificationRun
    extra = 0
    autocomplete_fields = ("verification_check", "triggered_by")
    readonly_fields = ("triggered_at", "completed_at")
    ordering = ("-created_at",)


@admin.register(OrganizationOnboarding)
class OrganizationOnboardingAdmin(admin.ModelAdmin):
    list_display = (
        "legal_name",
        "system",
        "status",
        "contact_system_user",
        "organization",
        "organization_type",
        "submitted_at",
    )
    list_filter = ("status", "system", "organization_type", "monthly_transaction_volume", "staff_size")
    search_fields = ("legal_name", "trading_name", "contact_email", "contact_phone")
    ordering = ("-created_at",)
    autocomplete_fields = (
        "system",
        "contact_system_user",
        "organization",
        "assigned_to",
    )

    inlines = (
        OnboardingCountryInline,
        OnboardingServiceSelectionInline,
        OnboardingPaymentInline,
        OnboardingVerificationRunInline,
        OnboardingDocumentInline,
        OnboardingActivityInline,
    )

    fieldsets = (
        ("Onboarding Info", {
            "fields": ("system", "status", "contact_system_user", "organization", "assigned_to")
        }),
        ("Business Details", {
            "fields": (
                "legal_name",
                "trading_name",
                "organization_type",
                "website",
                "description",
            )
        }),
        ("Business Profile", {
            "fields": (
                "products_needed",
                "monthly_transaction_volume",
                "staff_size",
                "pain_points",
            )
        }),
        ("Contact Details", {
            "fields": ("contact_email", "contact_phone")
        }),
        ("Metadata", {
            "fields": ("metadata",)
        }),
        ("Notes", {
            "fields": ("applicant_notes", "internal_notes")
        }),
        ("Timestamps", {
            "fields": ("submitted_at", "reviewed_at", "completed_at")
        }),
        ("Audit", {
            "fields": ("created_at", "updated_at")
        }),
    )

    readonly_fields = ("created_at", "updated_at")

    def get_queryset(self, request):
        return (
            super()
            .get_queryset(request)
            .select_related("system", "contact_system_user", "organization", "assigned_to")
            .prefetch_related(
                "country_requests",
                "documents",
                "activities",
                "service_selections",
                "payments",
                "verification_runs",
            )
        )


@admin.register(OrganizationOnboardingCountry)
class OrganizationOnboardingCountryAdmin(admin.ModelAdmin):
    list_display = ("onboarding", "country", "registration_number", "tax_id", "created_at")
    list_filter = ("country",)
    search_fields = ("onboarding__legal_name", "registration_number", "tax_id")
    ordering = ("onboarding", "country")
    autocomplete_fields = ("onboarding", "country")
    readonly_fields = ("created_at", "updated_at")

    fieldsets = (
        ("Country", {
            "fields": ("onboarding", "country", "registration_number", "tax_id", "address", "metadata")
        }),
        ("Audit", {
            "fields": ("created_at", "updated_at")
        }),
    )

    def get_queryset(self, request):
        return super().get_queryset(request).select_related("onboarding", "country")


@admin.register(OnboardingDocument)
class OnboardingDocumentAdmin(admin.ModelAdmin):
    list_display = (
        "document_type",
        "onboarding",
        "status",
        "uploaded_by",
        "uploaded_at",
        "is_expired",
    )
    list_filter = ("status", "document_type")
    search_fields = ("label", "file_name", "onboarding__legal_name")
    ordering = ("-uploaded_at",)
    autocomplete_fields = ("onboarding", "uploaded_by", "reviewed_by", "replaces")

    fieldsets = (
        ("Document Info", {
            "fields": (
                "onboarding",
                "document_type",
                "label",
                "file",
                "file_name",
                "file_size",
                "mime_type",
                "status",
                "expires_at",
            )
        }),
        ("Review", {
            "fields": (
                "uploaded_by",
                "uploaded_at",
                "reviewed_by",
                "reviewed_at",
                "review_notes",
                "replaces",
            )
        }),
        ("Audit", {
            "fields": ("created_at", "updated_at")
        }),
    )

    readonly_fields = (
        "created_at",
        "updated_at",
        "uploaded_at",
        "file_name",
        "file_size",
        "mime_type",
    )

    def get_queryset(self, request):
        return super().get_queryset(request).select_related("onboarding", "uploaded_by", "reviewed_by", "replaces")


@admin.register(OnboardingActivity)
class OnboardingActivityAdmin(admin.ModelAdmin):
    list_display = ("activity_type", "onboarding", "performed_by", "created_at")
    list_filter = ("activity_type",)
    search_fields = ("description", "onboarding__legal_name")
    ordering = ("-created_at",)
    autocomplete_fields = ("onboarding", "performed_by", "document")

    fieldsets = (
        ("Activity", {
            "fields": (
                "onboarding",
                "activity_type",
                "performed_by",
                "description",
                "payload",
                "previous_status",
                "new_status",
                "document",
            )
        }),
        ("Audit", {
            "fields": ("created_at", "updated_at")
        }),
    )

    readonly_fields = ("created_at", "updated_at")

    def get_queryset(self, request):
        return super().get_queryset(request).select_related("onboarding", "performed_by", "document")


@admin.register(OnboardingServiceProduct)
class OnboardingServiceProductAdmin(admin.ModelAdmin):
    list_display = ("name", "code", "system", "amount", "tax_amount", "currency", "is_active", "sort_order")
    list_filter = ("system", "currency", "is_active")
    search_fields = ("name", "code", "description")
    ordering = ("sort_order", "name")
    autocomplete_fields = ("system",)
    readonly_fields = ("created_at", "updated_at")


@admin.register(OnboardingPayment)
class OnboardingPaymentAdmin(admin.ModelAdmin):
    list_display = ("onboarding", "status", "method", "total_amount", "currency", "external_reference", "paid_at")
    list_filter = ("status", "method", "currency")
    search_fields = ("onboarding__legal_name", "external_reference")
    ordering = ("-created_at",)
    autocomplete_fields = ("onboarding", "recorded_by")
    readonly_fields = ("created_at", "updated_at", "paid_at")


@admin.register(OnboardingVerificationCheck)
class OnboardingVerificationCheckAdmin(admin.ModelAdmin):
    list_display = ("name", "code", "system", "trigger_mode", "required_for_onboarding", "is_active", "sort_order")
    list_filter = ("system", "trigger_mode", "required_for_onboarding", "is_active")
    search_fields = ("name", "code", "integration_code")
    ordering = ("sort_order", "name")
    autocomplete_fields = ("system",)
    readonly_fields = ("created_at", "updated_at")


@admin.register(OnboardingVerificationRun)
class OnboardingVerificationRunAdmin(admin.ModelAdmin):
    list_display = ("onboarding", "verification_check", "status", "trigger_mode", "external_reference", "triggered_at", "completed_at")
    list_filter = ("status", "trigger_mode", "verification_check")
    search_fields = ("onboarding__legal_name", "verification_check__code", "external_reference")
    ordering = ("-created_at",)
    autocomplete_fields = ("onboarding", "verification_check", "triggered_by")
    readonly_fields = ("created_at", "updated_at", "triggered_at", "completed_at")
