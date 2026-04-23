from django.contrib import admin
from django.utils.html import format_html

from .models import System, SystemClient, SystemSettings, SystemWebhook


class SystemClientInline(admin.TabularInline):
    model = SystemClient
    extra = 0
    show_change_link = True
    fields = (
        "name",
        "client_id",
        "client_type",
        "is_active",
    )
    readonly_fields = ("client_id",)


class SystemSettingsInline(admin.TabularInline):
    model = SystemSettings
    extra = 0
    show_change_link = True
    fields = (
        "key",
        "value_type",
        "is_secret",
    )


class SystemWebhookInline(admin.TabularInline):
    model = SystemWebhook
    extra = 0
    show_change_link = True
    fields = (
        "name",
        "endpoint_url",
        "is_active",
        "last_response_code",
        "consecutive_failures",
    )
    readonly_fields = (
        "last_response_code",
        "consecutive_failures",
    )


@admin.register(System)
class SystemAdmin(admin.ModelAdmin):
    list_display = (
        "name",
        "slug",
        "realm",
        "password_type",
        "is_active_colored",
        "registration_open",
        "mfa_required",
    )
    list_filter = (
        "is_active",
        "registration_open",
        "requires_approval",
        "mfa_required",
        "password_type",
    )
    search_fields = (
        "name",
        "slug",
        "description",
    )
    ordering = ("name",)
    filter_horizontal = ("available_countries",)
    inlines = (
        SystemClientInline,
        SystemSettingsInline,
        SystemWebhookInline,
    )

    readonly_fields = (
        "realm",
        "created_at",
        "updated_at",
    )

    fieldsets = (
        ("Core", {
            "fields": (
                "realm",
                "name",
                "slug",
                "description",
                "logo_url",
                "website",
                "is_active",
            )
        }),
        ("Authentication", {
            "fields": (
                "password_type",
                "allow_password_login",
                "allow_passwordless_login",
                "allow_magic_link_login",
                "allow_social_login",
                "passwordless_only",
            )
        }),
        ("MFA", {
            "fields": (
                "mfa_required",
                "mfa_required_enforced",
                "allowed_mfa_methods",
            )
        }),
        ("Rules", {
            "fields": (
                "registration_open",
                "requires_approval",
                "required_identifier_types",
                "allowed_login_identifier_types",
            )
        }),
        ("Audit", {
            "fields": (
                "created_at",
                "updated_at",
            )
        }),
    )

    def get_queryset(self, request):
        qs = super().get_queryset(request)
        return qs.select_related("realm").prefetch_related(
            "clients",
            "settings",
            "webhooks",
            "available_countries",
        )

    def is_active_colored(self, obj):
        if obj.is_active:
            return format_html('<span style="color:green;font-weight:600">Active</span>')
        return format_html('<span style="color:red;font-weight:600">Inactive</span>')

    is_active_colored.short_description = "Status"


@admin.register(SystemClient)
class SystemClientAdmin(admin.ModelAdmin):
    list_display = (
        "name",
        "system",
        "client_id_short",
        "client_type",
        "is_active",
    )
    list_filter = (
        "client_type",
        "is_active",
        "system",
    )
    search_fields = (
        "name",
        "client_id",
    )
    ordering = ("system", "name")

    readonly_fields = (
        "client_id",
        "client_secret_hash",
        "created_at",
        "updated_at",
    )

    fieldsets = (
        ("Core", {
            "fields": (
                "system",
                "name",
                "client_id",
                "client_type",
                "is_active",
            )
        }),
        ("Security", {
            "fields": (
                "client_secret_hash",
            )
        }),
        ("OAuth", {
            "fields": (
                "redirect_uris",
                "logout_uris",
                "allowed_scopes",
            )
        }),
        ("Token TTL", {
            "fields": (
                "access_token_ttl",
                "refresh_token_ttl",
                "id_token_ttl",
            )
        }),
        ("Overrides", {
            "fields": (
                "override_allowed_login_identifier_types",
                "override_allow_passwordless_login",
                "override_allow_magic_link_login",
                "override_allow_social_login",
                "override_allowed_social_providers",
            )
        }),
        ("Audit", {
            "fields": (
                "created_at",
                "updated_at",
            )
        }),
    )

    def get_queryset(self, request):
        return super().get_queryset(request).select_related("system")

    def client_id_short(self, obj):
        return obj.client_id[:10]

    client_id_short.short_description = "Client ID"


@admin.register(SystemSettings)
class SystemSettingsAdmin(admin.ModelAdmin):
    list_display = (
        "system",
        "key",
        "value_type",
        "is_secret",
    )
    list_filter = (
        "system",
        "value_type",
        "is_secret",
    )
    search_fields = (
        "key",
        "value",
    )
    ordering = ("system", "key")

    readonly_fields = (
        "created_at",
        "updated_at",
    )

    fieldsets = (
        ("Core", {
            "fields": (
                "system",
                "key",
                "value",
                "value_type",
            )
        }),
        ("Meta", {
            "fields": (
                "description",
                "is_secret",
            )
        }),
        ("Audit", {
            "fields": (
                "created_at",
                "updated_at",
            )
        }),
    )

    def get_queryset(self, request):
        return super().get_queryset(request).select_related("system")


@admin.register(SystemWebhook)
class SystemWebhookAdmin(admin.ModelAdmin):
    list_display = (
        "name",
        "system",
        "endpoint_url",
        "is_active",
        "last_response_code",
        "consecutive_failures",
    )
    list_filter = (
        "system",
        "is_active",
    )
    search_fields = (
        "name",
        "endpoint_url",
    )
    ordering = ("system", "name")

    readonly_fields = (
        "last_triggered_at",
        "last_response_code",
        "consecutive_failures",
        "created_at",
        "updated_at",
    )

    fieldsets = (
        ("Core", {
            "fields": (
                "system",
                "name",
                "endpoint_url",
                "is_active",
            )
        }),
        ("Security", {
            "fields": (
                "secret_encrypted",
            )
        }),
        ("Events", {
            "fields": (
                "event_types",
            )
        }),
        ("Health", {
            "fields": (
                "last_triggered_at",
                "last_response_code",
                "consecutive_failures",
            )
        }),
        ("Audit", {
            "fields": (
                "created_at",
                "updated_at",
            )
        }),
    )

    def get_queryset(self, request):
        return super().get_queryset(request).select_related("system")