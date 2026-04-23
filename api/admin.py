from django.contrib import admin
from django.utils.html import format_html
from django.utils import timezone

from .models import (
    RateLimitRule,
    RateLimitAttempt,
    RateLimitBlock,
)


class RateLimitAttemptInline(admin.TabularInline):
    model = RateLimitAttempt
    extra = 0
    ordering = ("-window_start",)
    can_delete = False
    show_change_link = False

    readonly_fields = (
        "key",
        "endpoint",
        "method",
        "count",
        "window_start",
        "last_attempt",
    )

    fields = readonly_fields

    def has_add_permission(self, request, obj=None):
        return False

    def has_change_permission(self, request, obj=None):
        return False


class RateLimitBlockInline(admin.TabularInline):
    model = RateLimitBlock
    extra = 0
    ordering = ("-blocked_until",)
    can_delete = False
    show_change_link = False

    readonly_fields = (
        "key",
        "blocked_until",
        "block_status",
        "created_at",
    )

    fields = readonly_fields

    def has_add_permission(self, request, obj=None):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def block_status(self, obj):
        if obj.blocked_until and obj.blocked_until > timezone.now():
            return format_html(
                '<span style="color:red;font-weight:bold;">ACTIVE</span>'
            )
        return format_html('<span style="color:green;">EXPIRED</span>')


@admin.register(RateLimitRule)
class RateLimitRuleAdmin(admin.ModelAdmin):
    list_display = (
        "name",
        "scope",
        "limit",
        "period_display",
        "is_active",
        "priority",
        "block_duration_minutes",
        "created_at",
    )

    list_filter = (
        "scope",
        "period",
        "is_active",
    )

    search_fields = (
        "name",
        "endpoint_pattern",
    )

    ordering = ("-priority", "name")

    inlines = (
        RateLimitBlockInline,
        RateLimitAttemptInline,
    )

    readonly_fields = (
        "id",
        "created_at",
        "updated_at",
    )

    list_editable = (
        "is_active",
        "priority",
    )

    fieldsets = (
        ("Rule Definition", {
            "fields": (
                "name",
                "scope",
                "endpoint_pattern",
                "limit",
                "period",
                "period_count",
            )
        }),
        ("Behaviour", {
            "fields": (
                "is_active",
                "priority",
                "block_duration_minutes",
            )
        }),
        ("Audit", {
            "fields": (
                "id",
                "created_at",
                "updated_at",
            )
        }),
    )

    def get_queryset(self, request):
        return super().get_queryset(request).only(
            "id",
            "name",
            "scope",
            "endpoint_pattern",
            "limit",
            "period",
            "period_count",
            "is_active",
            "priority",
            "block_duration_minutes",
            "created_at",
            "updated_at",
        )

    def period_display(self, obj):
        return f"{obj.period_count} {obj.period}(s)"

    period_display.short_description = "Period"


@admin.register(RateLimitAttempt)
class RateLimitAttemptAdmin(admin.ModelAdmin):
    list_display = (
        "key",
        "rule",
        "endpoint",
        "method",
        "count",
        "window_start",
        "last_attempt",
        "severity_indicator",
    )

    list_filter = (
        "rule",
        "method",
        "window_start",
    )

    search_fields = (
        "key",
        "endpoint",
        "rule__name",
    )

    ordering = ("-last_attempt",)

    readonly_fields = (
        "id",
        "created_at",
        "updated_at",
        "last_attempt",
    )

    list_select_related = ("rule",)
    date_hierarchy = "window_start"

    fieldsets = (
        ("Request Context", {
            "fields": (
                "rule",
                "key",
                "endpoint",
                "method",
            )
        }),
        ("Rate Data", {
            "fields": (
                "count",
                "window_start",
                "last_attempt",
            )
        }),
        ("Audit", {
            "fields": (
                "id",
                "created_at",
                "updated_at",
            )
        }),
    )

    def get_queryset(self, request):
        return super().get_queryset(request).select_related("rule")

    def severity_indicator(self, obj):
        if obj.count > 100:
            return format_html(
                '<span style="color:red;font-weight:bold;">HIGH</span>'
            )
        if obj.count > 20:
            return format_html('<span style="color:orange;">MED</span>')
        return format_html('<span style="color:green;">LOW</span>')

    severity_indicator.short_description = "Severity"


@admin.register(RateLimitBlock)
class RateLimitBlockAdmin(admin.ModelAdmin):
    list_display = (
        "key",
        "rule",
        "blocked_until",
        "block_status",
        "time_remaining",
        "created_at",
    )

    list_filter = (
        "rule",
        "blocked_until",
    )

    search_fields = (
        "key",
        "rule__name",
    )

    ordering = ("-blocked_until",)

    readonly_fields = (
        "id",
        "created_at",
        "updated_at",
        "time_remaining",
        "block_status",
    )

    list_select_related = ("rule",)
    date_hierarchy = "blocked_until"

    fieldsets = (
        ("Block Details", {
            "fields": (
                "rule",
                "key",
                "blocked_until",
            )
        }),
        ("State", {
            "fields": (
                "block_status",
                "time_remaining",
            )
        }),
        ("Audit", {
            "fields": (
                "id",
                "created_at",
                "updated_at",
            )
        }),
    )

    def get_queryset(self, request):
        return super().get_queryset(request).select_related("rule")

    def block_status(self, obj):
        if obj.blocked_until and obj.blocked_until > timezone.now():
            return format_html(
                '<span style="color:{};font-weight:bold;">{}</span>',
                "red",
                "ACTIVE",
            )
        return format_html(
            '<span style="color:{};">{}</span>',
            "green",
            "EXPIRED",
        )

    def time_remaining(self, obj):
        if not obj.blocked_until:
            return "-"

        remaining = obj.blocked_until - timezone.now()
        seconds = remaining.total_seconds()

        if seconds <= 0:
            return "0s"

        return str(remaining).split(".")[0]

    block_status.short_description = "Status"
    time_remaining.short_description = "Time Remaining"