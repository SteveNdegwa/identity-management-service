import uuid

from django.db import models
from django.utils import timezone

from base.models import BaseModel


class MFAMethod(models.TextChoices):
    SMS = "sms", "SMS OTP"
    EMAIL = "email_otp", "Email OTP"


class SSOSession(BaseModel):
    class AuthMethod(models.TextChoices):
        PASSWORD = "password", "Password"
        PIN = "pin", "PIN"
        SOCIAL = "social", "Social Login"
        MAGIC_LINK = "magic_link", "Magic Link"
        SMS_OTP = "sms_otp", "SMS OTP"
        EMAIL_OTP = "email_otp", "Email OTP"

    user = models.ForeignKey(
        "accounts.User",
        on_delete=models.CASCADE,
        related_name="sso_sessions",
    )
    initiating_system = models.ForeignKey(
        "systems.System",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="initiated_sessions",
    )

    session_token_hash = models.CharField(max_length=128, unique=True, db_index=True)

    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True)
    device_id = models.CharField(max_length=120, blank=True, db_index=True)
    device_name = models.CharField(max_length=120, blank=True)

    auth_method = models.CharField(
        max_length=30,
        choices=AuthMethod.choices,
        default=AuthMethod.PASSWORD,
    )

    country = models.ForeignKey(
        "base.Country",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="sso_sessions",
    )

    is_active = models.BooleanField(default=True, db_index=True)
    expires_at = models.DateTimeField()
    last_seen_at = models.DateTimeField(auto_now=True)
    revoked_at = models.DateTimeField(null=True, blank=True)
    revoke_reason = models.CharField(max_length=120, blank=True)

    requires_reauth = models.BooleanField(default=False)
    reauth_reason = models.CharField(max_length=120, blank=True)

    accessed_systems = models.ManyToManyField(
        "systems.System",
        through="SSOSessionSystemAccess",
        related_name="sso_sessions",
    )

    class Meta:
        db_table = "sso_session"
        indexes = [
            models.Index(fields=["user", "is_active"]),
            models.Index(fields=["expires_at"]),
        ]

    def is_expired(self) -> bool:
        return timezone.now() >= self.expires_at

    def extend(self, ttl_seconds: int) -> None:
        new_expiry = timezone.now() + timezone.timedelta(seconds=ttl_seconds)
        if new_expiry > self.expires_at:
            self.expires_at = new_expiry
            self.save(update_fields=["expires_at"])

    def revoke(self, reason: str = "logout") -> None:
        self.is_active = False
        self.revoked_at = timezone.now()
        self.revoke_reason = reason
        self.save(update_fields=["is_active", "revoked_at", "revoke_reason"])
        self.token_sets.filter(is_active=True).update(is_active=False)

    def __str__(self) -> str:
        return f"SSOSession {self.id} — {self.user}"


class SSOSessionSystemAccess(BaseModel):
    session = models.ForeignKey(
        SSOSession,
        on_delete=models.CASCADE,
        related_name="system_accesses"
    )
    system = models.ForeignKey("systems.System", on_delete=models.CASCADE)

    last_accessed_at = models.DateTimeField(auto_now=True)

    is_active  = models.BooleanField(default=True, db_index=True)
    revoked_at = models.DateTimeField(null=True, blank=True)

    last_token_refreshed_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text="Last time tokens were issued or refreshed for this system.",
    )

    last_mfa_verified_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text=(
            "Last time MFA was verified (or implicitly extended by a "
            "token refresh) for this system."
        ),
    )

    class Meta:
        db_table = "sso_session_system_access"
        unique_together = [("session", "system")]
        indexes = [
            models.Index(fields=["session", "is_active"]),
        ]

    def touch_token_refresh(self) -> None:
        now = timezone.now()
        self.last_token_refreshed_at = now
        self.last_mfa_verified_at = now
        self.save(update_fields=["last_token_refreshed_at", "last_mfa_verified_at"])

    def touch_mfa_verification(self) -> None:
        self.last_mfa_verified_at = timezone.now()
        self.save(update_fields=["last_mfa_verified_at"])

    def is_refresh_timed_out(self) -> bool:
        timeout_minutes = self.system.refresh_token_timeout_minutes
        if not timeout_minutes:
            return False
        if not self.last_token_refreshed_at:
            return True
        cutoff = timezone.now() - timezone.timedelta(minutes=timeout_minutes)
        return self.last_token_refreshed_at < cutoff

    def is_mfa_reauth_required(self) -> bool:
        window_minutes = getattr(self.system, "mfa_reauth_window_minutes", 0)
        if not window_minutes:
            return False
        if not self.last_mfa_verified_at:
            return True
        cutoff = timezone.now() - timezone.timedelta(minutes=window_minutes)
        return self.last_mfa_verified_at < cutoff


class SSOSessionMFAVerification(BaseModel):
    session = models.ForeignKey(
        SSOSession,
        on_delete=models.CASCADE,
        related_name="mfa_verifications"
    )
    method = models.CharField(max_length=20, choices=MFAMethod.choices)
    verified_at = models.DateTimeField(auto_now_add=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)

    system = models.ForeignKey(
        "systems.System",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="mfa_verifications",
    )

    class Meta:
        db_table = "sso_session_mfa_verification"
        indexes = [
            models.Index(fields=["session", "method"]),
            models.Index(fields=["session", "verified_at"]),
        ]


class PendingContextMFA(BaseModel):
    session = models.ForeignKey(
        SSOSession,
        on_delete=models.CASCADE,
        related_name="pending_context_mfas"
    )
    system_user = models.ForeignKey("accounts.SystemUser", on_delete=models.CASCADE)

    mfa_required_reason = models.CharField(max_length=255)
    mfa_allowed_methods = models.JSONField(default=list)
    mfa_reauth_window_minutes = models.PositiveSmallIntegerField(default=0)

    expires_at = models.DateTimeField()
    satisfied_at = models.DateTimeField(null=True, blank=True)

    client = models.ForeignKey("systems.SystemClient", on_delete=models.CASCADE)
    redirect_uri = models.URLField()
    scopes = models.JSONField(default=list)
    state = models.CharField(max_length=255, blank=True)
    nonce = models.CharField(max_length=255, blank=True)
    code_challenge = models.CharField(max_length=128, blank=True)
    code_challenge_method = models.CharField(max_length=10, default="S256")

    class Meta:
        db_table = "sso_pending_context_mfa"
        indexes = [
            models.Index(fields=["session", "satisfied_at"]),
        ]

    def is_expired(self) -> bool:
        return timezone.now() >= self.expires_at


class AuthorizationCode(BaseModel):
    code = models.CharField(max_length=128, unique=True, db_index=True)
    user = models.ForeignKey("accounts.User", on_delete=models.CASCADE)
    client = models.ForeignKey("systems.SystemClient", on_delete=models.CASCADE)
    sso_session = models.ForeignKey(
        SSOSession,
        null=True,
        blank=True,
        on_delete=models.SET_NULL
    )
    system_user = models.ForeignKey(
        "accounts.SystemUser",
        null=True,
        blank=True,
        on_delete=models.SET_NULL
    )

    code_challenge = models.CharField(max_length=128, blank=True)
    code_challenge_method = models.CharField(max_length=10, default="S256")

    redirect_uri = models.URLField()
    scopes = models.JSONField(default=list)
    state = models.CharField(max_length=255, blank=True)
    nonce = models.CharField(max_length=255, blank=True)

    expires_at = models.DateTimeField()
    used_at = models.DateTimeField(null=True, blank=True)
    is_used = models.BooleanField(default=False)

    class Meta:
        db_table = "sso_authorization_code"

    def is_expired(self) -> bool:
        return timezone.now() >= self.expires_at


class TokenSet(BaseModel):
    sso_session = models.ForeignKey(
        SSOSession,
        on_delete=models.CASCADE,
        related_name="token_sets"
    )
    user = models.ForeignKey("accounts.User", on_delete=models.CASCADE)
    client = models.ForeignKey("systems.SystemClient", on_delete=models.CASCADE)
    system_user = models.ForeignKey(
        "accounts.SystemUser",
        null=True,
        blank=True,
        on_delete=models.SET_NULL
    )

    scopes = models.JSONField(default=list)
    is_active = models.BooleanField(default=True, db_index=True)

    class Meta:
        db_table = "sso_token_set"
        indexes = [models.Index(fields=["user", "client", "is_active"])]


class AccessToken(BaseModel):
    token_set = models.ForeignKey(
        TokenSet,
        on_delete=models.CASCADE,
        related_name="access_tokens"
    )
    token_hash = models.CharField(max_length=128, unique=True, db_index=True)
    jti = models.UUIDField(unique=True, default=uuid.uuid4)

    expires_at = models.DateTimeField()
    revoked_at = models.DateTimeField(null=True, blank=True)
    is_revoked = models.BooleanField(default=False, db_index=True)

    role_snapshot = models.CharField(max_length=120, blank=True)
    permissions_snapshot = models.JSONField(default=list)

    class Meta:
        db_table = "sso_access_token"
        indexes  = [
            models.Index(fields=["jti"]),
            models.Index(fields=["expires_at", "is_revoked"]),
        ]

    def is_expired(self) -> bool:
        return timezone.now() >= self.expires_at


class RefreshToken(BaseModel):
    token_set = models.ForeignKey(
        TokenSet,
        on_delete=models.CASCADE,
        related_name="refresh_tokens"
    )
    token_hash = models.CharField(max_length=128, unique=True, db_index=True)
    jti = models.UUIDField(unique=True, default=uuid.uuid4)

    expires_at = models.DateTimeField()
    used_at = models.DateTimeField(null=True, blank=True)
    is_used = models.BooleanField(default=False, db_index=True)
    revoked_at = models.DateTimeField(null=True, blank=True)
    is_revoked = models.BooleanField(default=False, db_index=True)

    rotated_to = models.OneToOneField(
        "self",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="rotated_from",
    )

    class Meta:
        db_table = "sso_refresh_token"


class PasswordlessChallenge(BaseModel):
    class Purpose(models.TextChoices):
        LOGIN = "login", "Passwordless Login"
        MFA = "mfa", "MFA Second Factor"

    user = models.ForeignKey(
        "accounts.User",
        on_delete=models.CASCADE,
        related_name="passwordless_challenges",
    )
    client = models.ForeignKey(
        "systems.SystemClient",
        null=True,
        blank=True,
        on_delete=models.CASCADE,
    )
    sso_session = models.ForeignKey(
        SSOSession,
        null=True,
        blank=True,
        on_delete=models.CASCADE,
        related_name="passwordless_challenges",
    )

    purpose = models.CharField(max_length=10, choices=Purpose.choices)
    contact_type = models.CharField(max_length=20, blank=True)
    delivery_target = models.CharField(max_length=255, blank=True)
    code_hash = models.CharField(max_length=128)
    expires_at = models.DateTimeField()
    attempts = models.PositiveSmallIntegerField(default=0)
    is_used = models.BooleanField(default=False, db_index=True)
    used_at = models.DateTimeField(null=True, blank=True)

    ip_requested = models.GenericIPAddressField(null=True, blank=True)
    ip_verified = models.GenericIPAddressField(null=True, blank=True)

    class Meta:
        db_table = "accounts_passwordless_challenge"
        indexes  = [models.Index(fields=["is_used", "expires_at"])]

    def is_expired(self) -> bool:
        return timezone.now() >= self.expires_at


class MagicLink(BaseModel):
    user = models.ForeignKey(
        "accounts.User",
        on_delete=models.CASCADE,
        related_name="magic_links"
    )
    client = models.ForeignKey("systems.SystemClient", on_delete=models.CASCADE)

    contact_type = models.CharField(max_length=20, blank=True)
    delivery_target = models.CharField(max_length=255, blank=True)
    token_hash = models.CharField(max_length=128, unique=True, db_index=True)
    scopes = models.JSONField(default=list)
    expires_at = models.DateTimeField()
    is_used = models.BooleanField(default=False)
    used_at = models.DateTimeField(null=True, blank=True)

    ip_requested = models.GenericIPAddressField(null=True, blank=True)
    ip_used = models.GenericIPAddressField(null=True, blank=True)

    class Meta:
        db_table = "accounts_magic_link"
        indexes  = [models.Index(fields=["is_used", "expires_at"])]

    def is_expired(self) -> bool:
        return timezone.now() >= self.expires_at


class LoginContextSelection(BaseModel):
    sso_session = models.ForeignKey(
        SSOSession,
        on_delete=models.CASCADE,
        related_name="context_selections"
    )
    system_user  = models.ForeignKey("accounts.SystemUser", on_delete=models.CASCADE)
    organization = models.ForeignKey(
        "organizations.Organization",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
    )
    country = models.ForeignKey(
        "base.Country",
        null=True,
        blank=True,
        on_delete=models.SET_NULL
    )
    role = models.ForeignKey(
        "permissions.Role",
        null=True,
        blank=True,
        on_delete=models.SET_NULL
    )

    role_name_snapshot = models.CharField(max_length=120, blank=True)
    selected_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "sso_context_selection"