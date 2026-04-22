from django.urls import path
from apps.sso import views

urlpatterns = [
    # Login flows
    path("login/password/", views.password_login_view, name="auth-login-password"),
    path("login/pin/", views.pin_login_view, name="auth-login-pin"),
    path("passwordless/initiate/", views.passwordless_initiate_view, name="auth-passwordless-initiate"),
    path("passwordless/verify/", views.passwordless_verify_view, name="auth-passwordless-verify"),
    path("magic-link/initiate/", views.magic_link_initiate_view, name="auth-magic-link-initiate"),
    path("magic-link/verify/", views.magic_link_verify_view, name="auth-magic-link-verify"),

    # System-level MFA (before context selection)
    path("system-mfa/otp/initiate/", views.system_mfa_otp_initiate_view, name="auth-system-mfa-otp-initiate"),
    path("system-mfa/otp/verify/", views.system_mfa_otp_verify_view, name="auth-system-mfa-otp-verify"),
    path("system-mfa/code/verify/", views.system_mfa_code_verify_view, name="auth-system-mfa-code-verify"),

    # Context selection
    path("contexts/", views.list_contexts_view, name="auth-contexts"),
    path("context/select/", views.context_select_view, name="auth-context-select"),

    # Role/org-level MFA (after context selection)
    path("context-mfa/otp/initiate/", views.context_mfa_otp_initiate_view, name="auth-context-mfa-otp-initiate"),
    path("context-mfa/otp/verify/", views.context_mfa_otp_verify_view, name="auth-context-mfa-otp-verify"),
    path("context-mfa/code/verify/", views.context_mfa_code_verify_view, name="auth-context-mfa-code-verify"),

    # MFA enrollment and management
    path("mfa/enroll/initiate/", views.mfa_enroll_initiate_view, name="auth-mfa-enroll-initiate"),
    path("mfa/enroll/verify/", views.mfa_enroll_verify_view, name="auth-mfa-enroll-verify"),
    path("mfa/", views.mfa_list_view, name="auth-mfa-list"),
    path("mfa/primary/", views.mfa_set_primary_view, name="auth-mfa-set-primary"),
    path("mfa/remove/", views.mfa_remove_view, name="auth-mfa-remove"),

    # OAuth token endpoints
    path("token/", views.token_exchange_view, name="oauth-token"),
    path("token/refresh/", views.token_refresh_view, name="oauth-token-refresh"),
    path("revoke/", views.token_revoke_view, name="oauth-revoke"),
    path("introspect/", views.token_introspect_view, name="oauth-introspect"),

    # Session management
    path("logout/", views.logout_view, name="auth-logout"),
    path("logout/all/", views.logout_all_view, name="auth-logout-all"),
]