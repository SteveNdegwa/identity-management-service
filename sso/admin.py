from django.contrib import admin
from django.utils.html import format_html

from .models import (
    SSOSession,
    SSOSessionSystemAccess,
    SSOSessionMFAVerification,
    PendingContextMFA,
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
    autocomplete_fields = ("system",)
    readonly_fields = ("last_accessed_at",)


class SSOSessionMFAVerificationInline(admin.TabularInline):
    model = SSOSessionMFAVerification
    extra = 0
    autocomplete_fields = ("system",)
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
        ("Context", {"fields": ("country",)}),
        ("Device", {"fields": ("ip_address", "user_agent", "device_id", "device_name")}),
        ("Lifecycle", {"fields": ("is_active", "expires_at", "last_seen_at", "revoked_at", "revoke_reason")}),
        ("Reauthentication", {"fields": ("requires_reauth", "reauth_reason")}),
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


@admin.register(SSOSessionSystemAccess)
class SSOSessionSystemAccessAdmin(admin.ModelAdmin):
    list_display = (
        "session",
        "system",
        "is_active",
        "last_accessed_at",
        "last_token_refreshed_at",
        "last_mfa_verified_at",
    )
    list_filter = ("is_active", "system")
    search_fields = ("session__user__email", "session__device_id", "system__name")
    autocomplete_fields = ("session", "system")
    readonly_fields = ("last_accessed_at", "created_at", "updated_at")

    fieldsets = (
        ("Core", {"fields": ("session", "system", "is_active")}),
        ("Lifecycle", {"fields": ("last_accessed_at", "revoked_at")}),
        ("Refresh and MFA", {"fields": ("last_token_refreshed_at", "last_mfa_verified_at")}),
        ("Audit", {"fields": ("created_at", "updated_at")}),
    )


@admin.register(SSOSessionMFAVerification)
class SSOSessionMFAVerificationAdmin(admin.ModelAdmin):
    list_display = ("session", "system", "method", "verified_at", "ip_address")
    list_filter = ("method", "system")
    search_fields = ("session__user__email", "session__device_id")
    autocomplete_fields = ("session", "system")
    readonly_fields = ("verified_at", "created_at", "updated_at")

    fieldsets = (
        ("Core", {"fields": ("session", "system", "method")}),
        ("Request", {"fields": ("ip_address", "verified_at")}),
        ("Audit", {"fields": ("created_at", "updated_at")}),
    )


@admin.register(TokenSet)
class TokenSetAdmin(admin.ModelAdmin):
    list_display = ("user", "client", "is_active")
    list_filter = ("is_active",)
    search_fields = ("user__email", "client__name", "client__client_id")
    autocomplete_fields = ("sso_session", "user", "client", "system_user")

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
    search_fields = ("token_hash", "jti", "token_set__user__email")
    autocomplete_fields = ("token_set",)

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
    search_fields = ("token_hash", "jti", "token_set__user__email")
    autocomplete_fields = ("token_set", "rotated_to")

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
    search_fields = ("code", "user__email", "client__name", "client__client_id")
    autocomplete_fields = ("user", "client", "sso_session", "system_user")

    readonly_fields = ("created_at", "updated_at")

    fieldsets = (
        ("Core", {"fields": ("code", "user", "client", "sso_session", "system_user")}),
        ("OAuth", {"fields": ("redirect_uri", "scopes", "state", "nonce")}),
        ("PKCE", {"fields": ("code_challenge", "code_challenge_method")}),
        ("Lifecycle", {"fields": ("expires_at", "is_used", "used_at")}),
        ("Audit", {"fields": ("created_at", "updated_at")}),
    )


@admin.register(PendingContextMFA)
class PendingContextMFAAdmin(admin.ModelAdmin):
    list_display = ("session", "system_user", "client", "satisfied_at", "expires_at")
    search_fields = ("session__user__email", "system_user__user__email", "client__name")
    autocomplete_fields = ("session", "system_user", "client")

    readonly_fields = ("created_at", "updated_at")

    fieldsets = (
        ("Core", {"fields": ("session", "system_user", "client")}),
        ("MFA", {"fields": ("mfa_required_reason", "mfa_allowed_methods", "mfa_reauth_window_minutes")}),
        ("OAuth", {"fields": ("redirect_uri", "scopes", "state", "nonce", "code_challenge", "code_challenge_method")}),
        ("Lifecycle", {"fields": ("expires_at", "satisfied_at")}),
        ("Audit", {"fields": ("created_at", "updated_at")}),
    )

@admin.register(PasswordlessChallenge)
class PasswordlessChallengeAdmin(admin.ModelAdmin):
    list_display = ("user", "purpose", "contact_type", "delivery_target", "is_used", "expires_at")
    list_filter = ("purpose", "is_used")
    search_fields = ("user__email", "delivery_target")
    autocomplete_fields = ("user", "client", "sso_session")

    readonly_fields = ("created_at", "updated_at")

    fieldsets = (
        ("Core", {"fields": ("user", "client", "sso_session")}),
        ("Delivery", {"fields": ("contact_type", "delivery_target")}),
        ("Challenge", {"fields": ("purpose", "code_hash", "attempts")}),
        ("Lifecycle", {"fields": ("expires_at", "is_used", "used_at")}),
        ("Request", {"fields": ("ip_requested", "ip_verified")}),
        ("Audit", {"fields": ("created_at", "updated_at")}),
    )


@admin.register(MagicLink)
class MagicLinkAdmin(admin.ModelAdmin):
    list_display = ("user", "client", "contact_type", "delivery_target", "is_used", "expires_at")
    list_filter = ("is_used",)
    search_fields = ("user__email", "delivery_target", "token_hash")
    autocomplete_fields = ("user", "client")

    readonly_fields = ("created_at", "updated_at")

    fieldsets = (
        ("Core", {"fields": ("user", "client", "token_hash")}),
        ("Delivery", {"fields": ("contact_type", "delivery_target")}),
        ("Lifecycle", {"fields": ("scopes", "expires_at", "is_used", "used_at")}),
        ("Request", {"fields": ("ip_requested", "ip_used")}),
        ("Audit", {"fields": ("created_at", "updated_at")}),
    )


@admin.register(LoginContextSelection)
class LoginContextSelectionAdmin(admin.ModelAdmin):
    list_display = ("sso_session", "organization", "country", "role", "selected_at")
    search_fields = ("sso_session__user__email", "system_user__user__email", "organization__name", "role__name")
    autocomplete_fields = ("sso_session", "system_user", "organization", "country", "role")

    readonly_fields = ("created_at", "updated_at")

    fieldsets = (
        ("Core", {"fields": ("sso_session", "system_user")}),
        ("Context", {"fields": ("organization", "country", "role", "role_name_snapshot")}),
        ("Audit", {"fields": ("created_at", "updated_at")}),
    )
