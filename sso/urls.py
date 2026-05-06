from django.urls import path
from . import views

urlpatterns = [
    # ------------------------------------------------------------------
    # Login flows
    # ------------------------------------------------------------------
    path("login/password/",          views.password_login_view,          name="auth-login-password"),
    path("login/pin/",               views.pin_login_view,               name="auth-login-pin"),
    path("login/social/",            views.social_login_view,            name="auth-login-social"),

    # Passwordless OTP (login, not MFA)
    path("passwordless/initiate/",   views.passwordless_initiate_view,   name="auth-passwordless-initiate"),
    path("passwordless/verify/",     views.passwordless_verify_view,     name="auth-passwordless-verify"),

    # Magic link
    path("magic-link/initiate/",     views.magic_link_initiate_view,     name="auth-magic-link-initiate"),
    path("magic-link/verify/",       views.magic_link_verify_view,       name="auth-magic-link-verify"),

    # ------------------------------------------------------------------
    # System-level MFA  (runs before context selection when system.mfa_required)
    #
    # 1. Client receives mfa_required=True from a login or list-contexts call.
    # 2. User picks a method from allowed_methods (email_otp | sms).
    # 3. POST system-mfa/initiate/  →  { challenge_id, masked_destination, expires_in }
    # 4. User enters the OTP.
    # 5. POST system-mfa/verify/    →  same shape as post-login (contexts or next gate)
    # ------------------------------------------------------------------
    path("system-mfa/initiate/",     views.system_mfa_initiate_view,     name="auth-system-mfa-initiate"),
    path("system-mfa/verify/",       views.system_mfa_verify_view,       name="auth-system-mfa-verify"),

    # ------------------------------------------------------------------
    # Context listing & selection
    # ------------------------------------------------------------------
    path("contexts/",                views.list_contexts_view,           name="auth-contexts"),
    path("context/select/",          views.context_select_view,          name="auth-context-select"),

    # ------------------------------------------------------------------
    # Context-level MFA  (runs during context selection when role/org requires MFA)
    #
    # 1. context/select/ returns mfa_required=True + pending_context_id.
    # 2. User picks a method from allowed_methods.
    # 3. POST context-mfa/initiate/  →  { challenge_id, masked_destination, expires_in }
    # 4. User enters the OTP.
    # 5. POST context-mfa/verify/    →  { authorization_code }
    # ------------------------------------------------------------------
    path("context-mfa/initiate/",    views.context_mfa_initiate_view,    name="auth-context-mfa-initiate"),
    path("context-mfa/verify/",      views.context_mfa_verify_view,      name="auth-context-mfa-verify"),

    # ------------------------------------------------------------------
    # OAuth token endpoints
    # ------------------------------------------------------------------
    path("token/",                   views.token_exchange_view,          name="oauth-token"),
    path("token/refresh/",           views.token_refresh_view,           name="oauth-token-refresh"),
    path("revoke/",                  views.token_revoke_view,            name="oauth-revoke"),
    path("introspect/",              views.token_introspect_view,        name="oauth-introspect"),

    # ------------------------------------------------------------------
    # Session management
    #
    # logout/         — revoke the entire SSO session (all systems)
    # logout/system/  — revoke access to one system; session stays alive
    #                   for other systems unless it was the last one
    # logout/all/     — revoke every active session for this user
    # ------------------------------------------------------------------
    path("logout/",                  views.logout_view,                  name="auth-logout"),
    path("logout/system/",           views.logout_system_view,           name="auth-logout-system"),
    path("logout/all/",              views.logout_all_view,              name="auth-logout-all"),
]