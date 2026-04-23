from django.contrib import admin
from django.utils.html import format_html

from .models import (
    PermissionCategory,
    Permission,
    Role,
    RolePermission,
    UserPermissionOverride,
)


@admin.register(PermissionCategory)
class PermissionCategoryAdmin(admin.ModelAdmin):
    list_display = ("system", "name", "slug", "created_at", "updated_at")
    search_fields = ("name", "slug")
    list_filter = ("system",)
    ordering = ("system", "name")

    readonly_fields = (
        "id",
        "created_at",
        "updated_at",
    )

    fieldsets = (
        ("Core", {
            "fields": ("system", "name", "slug", "description")
        }),
        ("Audit", {
            "fields": ("created_at", "updated_at")
        }),
    )

    def get_queryset(self, request):
        return super().get_queryset(request).select_related("system")


class RolePermissionInlineForPermission(admin.TabularInline):
    model = RolePermission
    extra = 0
    autocomplete_fields = ("role",)
    readonly_fields = ("granted_at",)

    fields = (
        "role",
        "is_active",
        "granted_at",
    )


@admin.register(Permission)
class PermissionAdmin(admin.ModelAdmin):
    list_display = (
        "system",
        "codename",
        "name",
        "category",
        "is_read_only",
        "is_sensitive",
        "is_active",
        "created_at",
    )
    list_filter = ("system", "category", "is_read_only", "is_sensitive", "is_active")
    search_fields = ("codename", "name")
    ordering = ("system", "codename")

    inlines = (RolePermissionInlineForPermission,)

    readonly_fields = (
        "id",
        "created_at",
        "updated_at",
    )

    fieldsets = (
        ("Core", {
            "fields": ("system", "category", "codename", "name", "description")
        }),
        ("Flags", {
            "fields": ("is_read_only", "is_sensitive", "is_active")
        }),
        ("Audit", {
            "fields": ("created_at", "updated_at")
        }),
    )

    def get_queryset(self, request):
        return super().get_queryset(request).select_related("system", "category")


@admin.register(RolePermission)
class RolePermissionAdmin(admin.ModelAdmin):
    list_display = ("role", "permission", "is_active", "granted_at")
    list_filter = ("is_active", "role", "permission")
    search_fields = ("role__name", "permission__codename")
    ordering = ("-granted_at",)

    readonly_fields = (
        "id",
        "granted_at",
        "created_at",
        "updated_at",
    )

    fieldsets = (
        ("Core", {
            "fields": ("role", "permission", "is_active")
        }),
        ("Grant Info", {
            "fields": ("conditions", "granted_by", "granted_at")
        }),
        ("Audit", {
            "fields": ("created_at", "updated_at")
        }),
    )

    def get_queryset(self, request):
        return super().get_queryset(request).select_related(
            "role",
            "permission",
            "granted_by",
        )


class RolePermissionInline(admin.TabularInline):
    model = RolePermission
    extra = 0
    autocomplete_fields = ("permission",)
    readonly_fields = ("granted_at",)


@admin.register(Role)
class RoleAdmin(admin.ModelAdmin):
    list_display = (
        "system",
        "name",
        "slug",
        "country",
        "status_badge",
        "is_system_defined",
        "created_at",
    )
    list_filter = ("system", "country", "is_active", "is_system_defined")
    search_fields = ("name", "slug")
    ordering = ("system", "name")

    inlines = (RolePermissionInline,)

    readonly_fields = (
        "id",
        "created_at",
        "updated_at",
    )

    fieldsets = (
        ("Core", {
            "fields": ("system", "country", "name", "slug", "description")
        }),
        ("Hierarchy", {
            "fields": ("parent_role",)
        }),
        ("MFA", {
            "fields": ("mfa_required", "mfa_allowed_methods", "mfa_reauth_window_minutes")
        }),
        ("Meta", {
            "fields": ("is_system_defined", "created_by_org", "is_active")
        }),
        ("Audit", {
            "fields": ("created_at", "updated_at")
        }),
    )

    def status_badge(self, obj):
        color = "green" if obj.is_active else "red"
        label = "Active" if obj.is_active else "Inactive"
        return format_html(
            '<span style="color:{};font-weight:bold;">{}</span>',
            color,
            label,
        )

    status_badge.short_description = "Status"

    def get_queryset(self, request):
        return (
            super()
            .get_queryset(request)
            .select_related("system", "country", "parent_role")
            .prefetch_related("role_permissions")
        )


@admin.register(UserPermissionOverride)
class UserPermissionOverrideAdmin(admin.ModelAdmin):
    list_display = (
        "system_user",
        "permission",
        "effect",
        "is_active",
        "expiry_status",
    )
    list_filter = ("effect", "is_active")
    search_fields = ("system_user__id", "permission__codename")

    readonly_fields = (
        "id",
        "created_at",
        "updated_at",
    )

    fieldsets = (
        ("Core", {
            "fields": ("system_user", "permission", "effect")
        }),
        ("Override", {
            "fields": ("reason", "expires_at", "is_active", "granted_by")
        }),
        ("Audit", {
            "fields": ("created_at", "updated_at")
        }),
    )

    def expiry_status(self, obj):
        if obj.is_expired:
            return format_html('<span style="color:red;font-weight:bold;">Expired</span>')
        return format_html('<span style="color:green;font-weight:bold;">Valid</span>')

    expiry_status.short_description = "Expiry"

    def get_queryset(self, request):
        return super().get_queryset(request).select_related(
            "system_user",
            "permission",
            "granted_by",
        )