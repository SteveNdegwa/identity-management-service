from django.contrib import admin
from django.db.models import Prefetch
from django.utils.html import format_html

from .models import (
    User,
    UserIdentifier,
    SystemUser,
    SocialAccount,
    SystemUserStatus,
)


class UserIdentifierInline(admin.TabularInline):
    model = UserIdentifier
    fk_name = "user"
    extra = 0

    autocomplete_fields = ["added_by_system", "disassociated_by"]

    readonly_fields = (
        "value_normalised",
        "verified_at",
        "is_active_display",
        "created_at",
        "updated_at",
    )

    fields = (
        "identifier_type",
        "value",
        "value_normalised",
        "is_primary",
        "is_verified",
        "verified_at",
        "disassociated_at",
        "disassociation_reason",
        "added_by_system",
        "is_active_display",
    )

    def is_active_display(self, obj):
        return obj.disassociated_at is None

    is_active_display.short_description = "Active"

    def has_add_permission(self, request, obj=None):
        return False


class SystemUserInline(admin.TabularInline):
    model = SystemUser
    extra = 0
    fk_name = "user"

    autocomplete_fields = [
        "system",
        "organization",
        "country",
        "role",
        "provisioned_by",
        "suspended_by",
    ]

    readonly_fields = (
        "registered_at",
        "last_login_at",
        "status_badge",
    )

    fields = (
        "system",
        "organization",
        "country",
        "role",
        "status",
        "status_badge",
        "all_branches",
        "registered_at",
        "last_login_at",
    )

    def status_badge(self, obj):
        color_map = {
            SystemUserStatus.ACTIVE: "green",
            SystemUserStatus.PENDING: "orange",
            SystemUserStatus.INVITED: "blue",
            SystemUserStatus.SUSPENDED: "red",
            SystemUserStatus.REMOVED: "gray",
        }

        color = color_map.get(obj.status, "black")

        return format_html(
            '<b style="color:{}">{}</b>',
            color,
            obj.get_status_display(),
        )

    status_badge.short_description = "Status"

    def has_add_permission(self, request, obj=None):
        return False


class SocialAccountInline(admin.TabularInline):
    model = SocialAccount
    extra = 0
    readonly_fields = ("created_at", "updated_at")

    fields = (
        "provider",
        "uid",
        "access_token",
        "refresh_token",
        "token_expires_at",
        "created_at",
    )


@admin.register(User)
class UserAdmin(admin.ModelAdmin):
    list_display = (
        "id",
        "realm",
        "primary_country",
        "email_display",
        "phone_display",
        "is_active",
        "is_locked_display",
        "created_at",
    )

    list_filter = (
        "is_active",
        "realm",
        "primary_country",
        "created_at",
    )

    search_fields = (
        "identifiers__value",
        "identifiers__value_normalised",
        "id",
    )

    inlines = (
        UserIdentifierInline,
        SystemUserInline,
        SocialAccountInline,
    )

    readonly_fields = (
        "id",
        "created_at",
        "updated_at",
        "last_login",
        "failed_login_attempts",
        "locked_until",
        "is_locked_display",
    )

    raw_id_fields = ("realm", "primary_country")
    list_select_related = ("realm", "primary_country")

    fieldsets = (
        ("Identity", {
            "fields": (
                "id",
                "realm",
                "primary_country",
            )
        }),
        ("Status", {
            "fields": (
                "is_active",
                "last_login",
                "failed_login_attempts",
                "locked_until",
                "is_locked_display",
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
        return super().get_queryset(request).select_related(
            "realm",
            "primary_country",
        ).prefetch_related(
            Prefetch(
                "identifiers",
                queryset=UserIdentifier.all_objects.all()
            )
        )

    def email_display(self, obj):
        return obj.get_email()

    email_display.short_description = "Email"

    def phone_display(self, obj):
        return obj.get_phone()

    phone_display.short_description = "Phone"

    def is_locked_display(self, obj):
        return obj.is_locked()

    is_locked_display.boolean = True
    is_locked_display.short_description = "Locked"


@admin.register(UserIdentifier)
class UserIdentifierAdmin(admin.ModelAdmin):
    list_display = (
        "id",
        "user",
        "realm",
        "identifier_type",
        "value",
        "is_primary",
        "is_verified",
        "status_display",
        "created_at",
    )

    list_filter = (
        "identifier_type",
        "is_primary",
        "is_verified",
        "realm",
    )

    search_fields = (
        "value",
        "value_normalised",
        "user__id",
    )

    raw_id_fields = (
        "user",
        "realm",
        "added_by_system",
        "disassociated_by",
    )

    list_select_related = (
        "user",
        "realm",
    )

    readonly_fields = (
        "value_normalised",
        "created_at",
        "updated_at",
    )

    fieldsets = (
        ("Identifier", {
            "fields": (
                "user",
                "realm",
                "identifier_type",
                "value",
                "value_normalised",
            )
        }),
        ("Verification", {
            "fields": (
                "is_primary",
                "is_verified",
                "verified_at",
            )
        }),
        ("Lifecycle", {
            "fields": (
                "disassociated_at",
                "disassociation_reason",
                "added_by_system",
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
        return super().get_queryset(request).select_related("user", "realm")

    def status_display(self, obj):
        if obj.disassociated_at:
            return format_html('<span style="color:red">DISASSOCIATED</span>')
        return format_html('<span style="color:green">ACTIVE</span>')


@admin.register(SystemUser)
class SystemUserAdmin(admin.ModelAdmin):
    list_display = (
        "id",
        "user",
        "system",
        "organization",
        "country",
        "role",
        "status_badge",
        "created_at",
    )

    list_filter = (
        "status",
        "system",
        "organization",
        "country",
        "role",
    )

    search_fields = (
        "first_name",
        "last_name",
        "display_name",
        "provisioning_email",
        "external_ref",
    )

    autocomplete_fields = (
        "user",
        "system",
        "organization",
        "country",
        "role",
        "provisioned_by",
        "suspended_by",
    )

    filter_horizontal = ("branch_access",)

    readonly_fields = (
        "id",
        "registered_at",
        "last_login_at",
        "claim_token_hash",
        "claim_token_lookup_id",
        "created_at",
        "updated_at",
        "status_badge",
    )

    list_select_related = (
        "user",
        "system",
        "organization",
        "country",
        "role",
    )

    fieldsets = (
        ("Identity", {
            "fields": (
                "user",
                "system",
                "organization",
                "country",
                "role",
            )
        }),
        ("Status", {
            "fields": (
                "status",
                "registered_at",
                "last_login_at",
            )
        }),
        ("Security", {
            "fields": (
                "claim_token_hash",
                "claim_token_lookup_id",
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
        return super().get_queryset(request).select_related(
            "user",
            "system",
            "organization",
            "country",
            "role",
        )

    def status_badge(self, obj):
        color_map = {
            SystemUserStatus.ACTIVE: "green",
            SystemUserStatus.PENDING: "orange",
            SystemUserStatus.INVITED: "blue",
            SystemUserStatus.SUSPENDED: "red",
            SystemUserStatus.REMOVED: "gray",
        }

        color = color_map.get(obj.status, "black")

        return format_html(
            '<span style="padding:2px 6px;border-radius:4px;background:{};color:white;">{}</span>',
            color,
            obj.get_status_display(),
        )

    status_badge.short_description = "Status"


@admin.register(SocialAccount)
class SocialAccountAdmin(admin.ModelAdmin):
    list_display = (
        "id",
        "user",
        "provider",
        "uid",
        "token_status",
        "created_at",
    )

    list_filter = ("provider",)

    search_fields = ("uid", "user__id")

    raw_id_fields = ("user",)

    list_select_related = ("user",)

    readonly_fields = ("created_at", "updated_at")

    fieldsets = (
        ("Account", {
            "fields": (
                "user",
                "provider",
                "uid",
            )
        }),
        ("Tokens", {
            "fields": (
                "access_token",
                "refresh_token",
                "token_expires_at",
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
        return super().get_queryset(request).select_related("user")

    def token_status(self, obj):
        if obj.token_expires_at and obj.token_expires_at < obj.updated_at:
            return format_html('<span style="color:red">Expired</span>')
        return format_html('<span style="color:green">Active</span>')

    token_status.short_description = "Token"