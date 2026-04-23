from django.contrib import admin

from .models import (
    Organization,
    OrganizationCountry,
    Branch,
    OrganizationSettings,
    OrganizationOnboarding,
    OnboardingDocument,
    OnboardingActivity,
    DocumentRequest,
)


class OrganizationCountryInline(admin.TabularInline):
    model = OrganizationCountry
    extra = 0
    autocomplete_fields = ("country",)
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
    list_display = ("name", "system", "slug", "is_active", "verified")
    list_filter = ("is_active", "verified", "system")
    search_fields = ("name", "slug")
    ordering = ("name",)
    autocomplete_fields = ("system", "verified_by")

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
            "fields": ("is_active", "verified", "verified_at", "verified_by")
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
    list_display = ("organization", "country", "registration_number", "tax_id", "is_active")
    list_filter = ("country", "is_active")
    search_fields = ("registration_number", "tax_id")
    ordering = ("organization",)
    autocomplete_fields = ("organization", "country")

    fieldsets = (
        ("Details", {
            "fields": ("organization", "country", "registration_number", "tax_id", "is_active")
        }),
        ("Audit", {
            "fields": ("created_at", "updated_at")
        }),
    )

    readonly_fields = ("created_at", "updated_at")

    def get_queryset(self, request):
        return super().get_queryset(request).select_related("organization", "country")


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


class DocumentRequestInline(admin.TabularInline):
    model = DocumentRequest
    extra = 0
    autocomplete_fields = ("requested_by", "fulfilled_by_document")
    readonly_fields = ("requested_at",)
    ordering = ("-requested_at",)


@admin.register(OrganizationOnboarding)
class OrganizationOnboardingAdmin(admin.ModelAdmin):
    list_display = (
        "legal_name",
        "system",
        "country",
        "status",
        "contact_system_user",
        "submitted_at",
    )
    list_filter = ("status", "system", "country")
    search_fields = ("legal_name", "trading_name", "registration_number", "tax_id")
    ordering = ("-created_at",)
    autocomplete_fields = (
        "system",
        "country",
        "contact_system_user",
        "assigned_to",
    )

    inlines = (
        OnboardingDocumentInline,
        OnboardingActivityInline,
        DocumentRequestInline,
    )

    fieldsets = (
        ("Onboarding Info", {
            "fields": ("system", "country", "status", "contact_system_user", "assigned_to")
        }),
        ("Business Details", {
            "fields": (
                "legal_name",
                "trading_name",
                "registration_number",
                "tax_id",
                "website",
                "description",
            )
        }),
        ("Contact Details", {
            "fields": ("address", "contact_email", "contact_phone")
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
            .select_related("system", "country", "contact_system_user", "assigned_to")
            .prefetch_related(
                "documents",
                "activities",
                "document_requests",
            )
        )


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
    search_fields = ("label", "file_name")
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
        return super().get_queryset(request).select_related("onboarding", "uploaded_by")


@admin.register(OnboardingActivity)
class OnboardingActivityAdmin(admin.ModelAdmin):
    list_display = ("activity_type", "onboarding", "performed_by", "created_at")
    list_filter = ("activity_type",)
    search_fields = ("description",)
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
        return super().get_queryset(request).select_related("onboarding", "performed_by")


@admin.register(DocumentRequest)
class DocumentRequestAdmin(admin.ModelAdmin):
    list_display = (
        "document_type",
        "onboarding",
        "requested_by",
        "fulfilled_at",
        "is_fulfilled",
    )
    list_filter = ("document_type",)
    search_fields = ("reason",)
    ordering = ("-requested_at",)
    autocomplete_fields = (
        "onboarding",
        "requested_by",
        "fulfilled_by_document",
    )

    fieldsets = (
        ("Request Details", {
            "fields": (
                "onboarding",
                "document_type",
                "label",
                "reason",
                "requested_by",
                "requested_at",
            )
        }),
        ("Fulfillment", {
            "fields": ("fulfilled_by_document", "fulfilled_at", "deadline")
        }),
        ("Audit", {
            "fields": ("created_at", "updated_at")
        }),
    )

    readonly_fields = ("created_at", "updated_at", "requested_at")

    def get_queryset(self, request):
        return super().get_queryset(request).select_related(
            "onboarding",
            "requested_by",
            "fulfilled_by_document",
        )