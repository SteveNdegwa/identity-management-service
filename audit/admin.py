from django.contrib import admin
from django.utils.html import format_html

from .models import (
    AuditLog,
    RequestLog,
    ModelAuditLog,
    ModelAuditConfiguration,
    ModelAuditSeverity,
)


@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    list_display = (
        "event_type",
        "outcome_badge",
        "actor_user_id",
        "system_id",
        "organization_id",
        "country_code",
        "created_at",
    )

    list_filter = (
        "event_type",
        "outcome",
        "system_id",
        "organization_id",
        "country_code",
        "created_at",
    )

    search_fields = (
        "actor_user_id",
        "subject_id",
        "system_name",
        "organization_name",
    )

    readonly_fields = (
        "id",
        "created_at",
        "updated_at",
        "payload",
        "failure_reason",
    )

    ordering = ("-created_at",)
    date_hierarchy = "created_at"

    fieldsets = (
        ("Event", {
            "fields": (
                "event_type",
                "outcome",
                "actor_user_id",
                "subject_id",
            )
        }),
        ("Context", {
            "fields": (
                "system_id",
                "system_name",
                "organization_id",
                "organization_name",
                "country_code",
            )
        }),
        ("Payload", {
            "fields": ("payload",),
        }),
        ("Result", {
            "fields": ("failure_reason",),
        }),
        ("Audit", {
            "fields": (
                "created_at",
                "updated_at",
            ),
        }),
    )

    def get_queryset(self, request):
        return super().get_queryset(request).only(
            "id",
            "event_type",
            "outcome",
            "actor_user_id",
            "subject_id",
            "system_id",
            "system_name",
            "organization_id",
            "organization_name",
            "country_code",
            "created_at",
            "failure_reason",
            "payload",
        )

    def outcome_badge(self, obj):
        color_map = {
            "success": "green",
            "failure": "red",
            "partial": "orange",
        }
        color = color_map.get(obj.outcome, "gray")

        return format_html(
            '<span style="color:{};font-weight:bold;">{}</span>',
            color,
            obj.get_outcome_display(),
        )

    outcome_badge.short_description = "Outcome"


@admin.register(RequestLog)
class RequestLogAdmin(admin.ModelAdmin):
    list_display = (
        "request_id",
        "request_method",
        "request_path",
        "user_id",
        "colored_status",
        "time_taken",
        "started_at",
    )

    list_filter = (
        "request_method",
        "response_status",
        "is_authenticated",
        "started_at",
    )

    search_fields = (
        "request_id",
        "request_path",
        "user_id",
        "system_user_id",
    )

    readonly_fields = (
        "request_id",
        "id",
        "request_data",
        "response_data",
        "exception_traceback",
        "started_at",
        "ended_at",
        "time_taken",
    )

    ordering = ("-started_at",)
    date_hierarchy = "started_at"

    fieldsets = (
        ("Request", {
            "fields": (
                "request_id",
                "request_method",
                "request_path",
                "request_data",
            )
        }),
        ("Response", {
            "fields": (
                "response_status",
                "response_data",
                "exception_traceback",
                "time_taken",
            )
        }),
        ("User Context", {
            "fields": (
                "user_id",
                "system_user_id",
                "is_authenticated",
            )
        }),
        ("Audit", {
            "fields": (
                "started_at",
                "ended_at",
            )
        }),
    )

    def get_queryset(self, request):
        return super().get_queryset(request).only(
            "id",
            "request_id",
            "request_method",
            "request_path",
            "user_id",
            "system_user_id",
            "response_status",
            "time_taken",
            "started_at",
            "ended_at",
            "is_authenticated",
        )

    def colored_status(self, obj):
        if obj.response_status is None:
            return '-'
        code = obj.response_status
        if 200 <= code < 300:
            color = 'green'
        elif 300 <= code < 400:
            color = 'goldenrod'
        elif 400 <= code < 500:
            color = 'darkorange'
        else:
            color = 'red'
        return format_html("<b style='color:{};'>{}</b>", color, code)
    colored_status.short_description = 'Status'


@admin.register(ModelAuditLog)
class ModelAuditLogAdmin(admin.ModelAdmin):
    list_display = (
        "event_type",
        "severity_badge",
        "object_repr",
        "user_id",
        "created_at",
    )

    list_filter = (
        "event_type",
        "severity",
        "created_at",
    )

    search_fields = (
        "object_repr",
        "object_id",
        "user_id",
    )

    readonly_fields = (
        "id",
        "created_at",
        "updated_at",
        "changes",
        "metadata",
    )

    ordering = ("-created_at",)
    date_hierarchy = "created_at"

    fieldsets = (
        ("Event", {
            "fields": (
                "event_type",
                "severity",
                "object_repr",
                "object_id",
                "user_id",
            )
        }),
        ("Changes", {
            "fields": (
                "changes",
                "metadata",
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
        return super().get_queryset(request).only(
            "id",
            "event_type",
            "severity",
            "object_repr",
            "object_id",
            "user_id",
            "created_at",
        )

    def severity_badge(self, obj):
        color_map = {
            ModelAuditSeverity.LOW: "green",
            ModelAuditSeverity.MEDIUM: "blue",
            ModelAuditSeverity.HIGH: "orange",
            ModelAuditSeverity.CRITICAL: "red",
        }

        color = color_map.get(obj.severity, "gray")

        return format_html(
            '<span style="color:{};font-weight:bold;">{}</span>',
            color,
            obj.get_severity_display(),
        )

    severity_badge.short_description = "Severity"


@admin.register(ModelAuditConfiguration)
class ModelAuditConfigurationAdmin(admin.ModelAdmin):
    list_display = (
        "app_label",
        "model_name",
        "is_enabled",
        "track_create",
        "track_update",
        "track_delete",
        "retention_days",
    )

    list_filter = (
        "app_label",
        "is_enabled",
        "track_create",
        "track_update",
        "track_delete",
    )

    search_fields = (
        "app_label",
        "model_name",
    )

    ordering = ("app_label", "model_name")

    readonly_fields = (
        "id",
        "created_at",
        "updated_at",
    )

    fieldsets = (
        ("Model Target", {
            "fields": (
                "app_label",
                "model_name",
            )
        }),
        ("Tracking", {
            "fields": (
                "is_enabled",
                "track_create",
                "track_update",
                "track_delete",
            )
        }),
        ("Retention", {
            "fields": (
                "retention_days",
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
        return super().get_queryset(request).only(
            "id",
            "app_label",
            "model_name",
            "is_enabled",
            "track_create",
            "track_update",
            "track_delete",
            "retention_days",
            "created_at",
            "updated_at",
        )