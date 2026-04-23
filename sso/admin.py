from django.contrib import admin
from django.utils.html import format_html

from .models import (
    BackupCode,
    UserMFA,
    SSOSession,
    SSOSessionSystemAccess,
    SSOSessionMFAVerification,
    PendingContextMFA,
    PendingMFAEnrollment,
    AuthorizationCode,
    TokenSet,
    AccessToken,
    RefreshToken,
    PasswordlessChallenge,
    MagicLink,
    LoginContextSelection,
)


class SSOSessionSystemAccessInline(admin.TabularInline):
    model = SSOSessionSystemAccess
    extra = 0
    readonly_fields = ("last_accessed_at",)


class SSOSessionMFAVerificationInline(admin.TabularInline):
    model = SSOSessionMFAVerification
    extra = 0
    readonly_fields = ("verified_at",)


class TokenSetInline(admin.TabularInline):
    model = TokenSet
    extra = 0
    show_change_link = True
    readonly_fields = ("is_active",)


class LoginContextSelectionInline(admin.TabularInline):
    model = LoginContextSelection
    extra = 0
    readonly_fields = ("selected_at",)


class AccessTokenInline(admin.TabularInline):
    model = AccessToken
    extra = 0
    readonly_fields = ("jti", "is_revoked", "expires_at")


class RefreshTokenInline(admin.TabularInline):
    model = RefreshToken
    extra = 0
    readonly_fields = ("jti", "is_used", "is_revoked", "expires_at")


@admin.register(SSOSession)
class SSOSessionAdmin(admin.ModelAdmin):
    list_display = (
        "id",
        "user",
        "auth_method",
        "is_active_colored",
        "expires_at",
        "last_seen_at",
    )

    list_filter = ("is_active", "auth_method", "initiating_system")
    search_fields = ("session_token_hash", "device_id", "user_agent")

    readonly_fields = (
        "session_token_hash",
        "last_seen_at",
        "revoked_at",
        "system_mfa_satisfied_at",
        "created_at",
        "updated_at",
    )

    inlines = (
        SSOSessionSystemAccessInline,
        SSOSessionMFAVerificationInline,
        TokenSetInline,
        LoginContextSelectionInline,
    )

    fieldsets = (
        ("Core", {"fields": ("user", "initiating_system", "auth_method")}),
        ("Device", {"fields": ("ip_address", "user_agent", "device_id", "device_name")}),
        ("Lifecycle", {"fields": ("is_active", "expires_at", "last_seen_at", "revoked_at", "revoke_reason")}),
        ("MFA", {"fields": ("system_mfa_satisfied_at", "requires_reauth", "reauth_reason")}),
        ("Audit", {"fields": ("created_at", "updated_at")}),
    )

    def is_active_colored(self, obj):
        color = "green" if obj.is_active else "red"
        label = "Active" if obj.is_active else "Inactive"
        return format_html('<span style="color:{}">{}</span>', color, label)

    is_active_colored.short_description = "Status"

    def get_queryset(self, request):
        return (
            super()
            .get_queryset(request)
            .select_related("user", "initiating_system", "country")
            .prefetch_related("token_sets", "accessed_systems")
        )


@admin.register(UserMFA)
class UserMFAAdmin(admin.ModelAdmin):
    list_display = ("user", "method", "is_primary", "is_active", "verified_at")
    list_filter = ("method", "is_primary", "is_active")
    search_fields = ("credential_id", "delivery_target")

    readonly_fields = (
        "last_used_at",
        "verified_at",
        "created_at",
        "updated_at",
    )

    fieldsets = (
        ("Core", {"fields": ("user", "method", "is_primary", "is_active")}),
        ("Credentials", {"fields": ("secret", "credential_id", "delivery_target", "device_name")}),
        ("Activity", {"fields": ("last_used_at", "verified_at")}),
        ("Audit", {"fields": ("created_at", "updated_at")}),
    )


@admin.register(BackupCode)
class BackupCodeAdmin(admin.ModelAdmin):
    list_display = ("user", "is_used", "used_at", "invalidated_at")
    list_filter = ("is_used",)

    readonly_fields = ("created_at", "updated_at")

    fieldsets = (
        ("Core", {"fields": ("user", "code_hash", "is_used")}),
        ("Usage", {"fields": ("used_at", "used_from_ip", "invalidated_at")}),
        ("Audit", {"fields": ("created_at", "updated_at")}),
    )


@admin.register(TokenSet)
class TokenSetAdmin(admin.ModelAdmin):
    list_display = ("user", "client", "is_active")
    list_filter = ("is_active",)

    inlines = (
        AccessTokenInline,
        RefreshTokenInline,
    )

    readonly_fields = ("created_at", "updated_at")

    fieldsets = (
        ("Core", {"fields": ("sso_session", "user", "client", "system_user")}),
        ("Scopes", {"fields": ("scopes", "is_active")}),
        ("Audit", {"fields": ("created_at", "updated_at")}),
    )


@admin.register(AccessToken)
class AccessTokenAdmin(admin.ModelAdmin):
    list_display = ("token_set", "is_revoked", "expires_at")
    list_filter = ("is_revoked",)

    readonly_fields = ("created_at", "updated_at")

    fieldsets = (
        ("Core", {"fields": ("token_set", "token_hash", "jti")}),
        ("Lifecycle", {"fields": ("expires_at", "is_revoked", "revoked_at")}),
        ("Snapshot", {"fields": ("role_snapshot", "permissions_snapshot")}),
        ("Audit", {"fields": ("created_at", "updated_at")}),
    )


@admin.register(RefreshToken)
class RefreshTokenAdmin(admin.ModelAdmin):
    list_display = ("token_set", "is_used", "is_revoked", "expires_at")
    list_filter = ("is_used", "is_revoked")

    readonly_fields = ("created_at", "updated_at")

    fieldsets = (
        ("Core", {"fields": ("token_set", "token_hash", "jti")}),
        ("Lifecycle", {"fields": ("expires_at", "is_used", "is_revoked", "revoked_at")}),
        ("Rotation", {"fields": ("rotated_to",)}),
        ("Audit", {"fields": ("created_at", "updated_at")}),
    )


@admin.register(AuthorizationCode)
class AuthorizationCodeAdmin(admin.ModelAdmin):
    list_display = ("user", "client", "is_used", "expires_at")
    list_filter = ("is_used",)

    readonly_fields = ("created_at", "updated_at")

    fieldsets = (
        ("Core", {"fields": ("code", "user", "client")}),
        ("OAuth", {"fields": ("redirect_uri", "scopes", "state", "nonce")}),
        ("PKCE", {"fields": ("code_challenge", "code_challenge_method")}),
        ("Lifecycle", {"fields": ("expires_at", "is_used", "used_at")}),
        ("Audit", {"fields": ("created_at", "updated_at")}),
    )


@admin.register(PendingContextMFA)
class PendingContextMFAAdmin(admin.ModelAdmin):
    list_display = ("session", "satisfied_at", "expires_at")

    readonly_fields = ("created_at", "updated_at")

    fieldsets = (
        ("Core", {"fields": ("session", "system_user", "client")}),
        ("MFA", {"fields": ("mfa_required_reason", "mfa_allowed_methods", "mfa_reauth_window_minutes")}),
        ("OAuth", {"fields": ("redirect_uri", "scopes", "state", "nonce", "code_challenge", "code_challenge_method")}),
        ("Lifecycle", {"fields": ("expires_at", "satisfied_at")}),
        ("Audit", {"fields": ("created_at", "updated_at")}),
    )


@admin.register(PendingMFAEnrollment)
class PendingMFAEnrollmentAdmin(admin.ModelAdmin):
    list_display = ("session", "completed_at", "expires_at")

    readonly_fields = ("created_at", "updated_at")

    fieldsets = (
        ("Core", {"fields": ("session", "pending_context")}),
        ("MFA", {"fields": ("required_by", "allowed_methods")}),
        ("Lifecycle", {"fields": ("expires_at", "completed_at")}),
        ("Audit", {"fields": ("created_at", "updated_at")}),
    )


@admin.register(PasswordlessChallenge)
class PasswordlessChallengeAdmin(admin.ModelAdmin):
    list_display = ("user", "purpose", "is_used", "expires_at")
    list_filter = ("purpose", "is_used")

    readonly_fields = ("created_at", "updated_at")

    fieldsets = (
        ("Core", {"fields": ("user", "identifier", "client", "sso_session", "user_mfa")}),
        ("Challenge", {"fields": ("purpose", "code_hash", "attempts")}),
        ("Lifecycle", {"fields": ("expires_at", "is_used", "used_at")}),
        ("Audit", {"fields": ("created_at", "updated_at")}),
    )


@admin.register(MagicLink)
class MagicLinkAdmin(admin.ModelAdmin):
    list_display = ("user", "is_used", "expires_at")
    list_filter = ("is_used",)

    readonly_fields = ("created_at", "updated_at")

    fieldsets = (
        ("Core", {"fields": ("user", "identifier", "client", "token_hash")}),
        ("Lifecycle", {"fields": ("scopes", "expires_at", "is_used", "used_at")}),
        ("Audit", {"fields": ("created_at", "updated_at")}),
    )


@admin.register(LoginContextSelection)
class LoginContextSelectionAdmin(admin.ModelAdmin):
    list_display = ("sso_session", "organization", "country", "role", "selected_at")

    readonly_fields = ("created_at", "updated_at")

    fieldsets = (
        ("Core", {"fields": ("sso_session", "system_user")}),
        ("Context", {"fields": ("organization", "country", "role", "role_name_snapshot")}),
        ("Audit", {"fields": ("created_at", "updated_at")}),
    )