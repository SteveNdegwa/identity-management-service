from django.contrib.contenttypes.fields import GenericForeignKey
from django.contrib.contenttypes.models import ContentType
from django.core.serializers.json import DjangoJSONEncoder
from django.db import models

from apps.base.models import BaseModel


class AuditEventType(models.TextChoices):
    # Authorization
    LOGIN_SUCCESS = "auth.login.success"
    LOGIN_FAILED = "auth.login.failed"
    LOGIN_LOCKED = "auth.login.locked"
    LOGOUT = "auth.logout"
    LOGOUT_GLOBAL = "auth.logout.global"
    MFA_ENROLLMENT_INITIATED = "auth.mfa.enrollment_initiated"
    MFA_ENROLLED = "auth.mfa.enrolled"
    MFA_REMOVED = "auth.mfa.removed"
    MFA_VERIFIED = "auth.mfa.verified"
    MFA_FAILED = "auth.mfa.failed"
    MFA_REQUIRED = "auth.mfa.required"
    MFA_ENROLLMENT_REQUIRED = "auth.mfa.enrollment_required"
    MFA_ENROLLMENT_COMPLETE = "auth.mfa.enrollment_complete"
    MFA_METHOD_SUSPENDED = "auth.mfa.method_suspended"
    MFA_PRIMARY_CHANGED = "auth.mfa.primary_changed"
    BACKUP_CODES_GENERATED = "auth.mfa.backup_codes_generated"
    PASSWORD_CHANGED = "auth.password.changed"
    PASSWORD_RESET = "auth.password.reset"
    MAGIC_LINK_SENT = "auth.magic_link.sent"
    MAGIC_LINK_USED = "auth.magic_link.used"
    PASSWORDLESS_INITIATED = "auth.passwordless.initiated"
    PASSWORDLESS_VERIFIED = "auth.passwordless.verified"
    SESSION_CREATED = "auth.session.created"
    SESSION_REVOKED = "auth.session.revoked"
    SESSION_REAUTH_REQUIRED = "auth.session.reauth_required"
    TOKEN_ISSUED = "auth.token.issued"
    TOKEN_REFRESHED = "auth.token.refreshed"
    TOKEN_REVOKED = "auth.token.revoked"
    TOKEN_REFRESH_REUSE = "auth.token.refresh_reuse_detected"
    CONTEXT_SELECTED = "auth.context.selected"

    # Identifiers
    IDENTIFIER_ADDED = "identifier.added"
    IDENTIFIER_VERIFIED = "identifier.verified"
    IDENTIFIER_PROMOTED = "identifier.promoted"
    IDENTIFIER_DISASSOCIATED = "identifier.disassociated"
    IDENTIFIER_RECYCLED = "identifier.recycled"

    # Users
    USER_CREATED = "user.created"
    USER_UPDATED = "user.updated"
    USER_DELETED = "user.deleted"
    SYSTEM_USER_CREATED = "system_user.created"
    SYSTEM_USER_CLAIMED = "system_user.claimed"
    SYSTEM_USER_INVITED = "system_user.invited"
    USER_SUSPENDED = "user.suspended"
    USER_RESTORED = "user.restored"
    USER_LINKED_TO_SYSTEM = "user.linked_to_system"

    # Organization
    ORG_CREATED = "org.created"
    ORG_UPDATED = "org.updated"
    ORG_DEACTIVATED = "org.deactivated"
    ORG_REACTIVATED = "org.reactivated"

    ORG_SETTINGS_CHANGED = "org.settings.changed"
    ORG_SETTING_DELETED = "org.settings.deleted"

    ORG_COUNTRY_ADDED = "org.country.added"
    ORG_COUNTRY_UPDATED = "org.country.updated"
    ORG_COUNTRY_DEACTIVATED = "org.country.deactivated"

    MEMBER_ADDED = "org.member.added"
    MEMBER_REMOVED = "org.member.removed"
    MEMBER_SUSPENDED = "org.member.suspended"
    MEMBER_UNSUSPENDED = "org.member.unsuspended"
    MEMBER_ROLE_CHANGED = "org.member.role_changed"
    MEMBER_BRANCH_CHANGED = "org.member.branch_changed"

    BRANCH_CREATED = "org.branch.created"
    BRANCH_UPDATED = "org.branch.updated"
    BRANCH_DEACTIVATED = "org.branch.deactivated"
    BRANCH_REACTIVATED = "org.branch.reactivated"

    # Roles
    ROLE_CREATED = "role.created"
    ROLE_UPDATED = "role.updated"
    ROLE_DELETED = "role.deleted"
    PERMISSION_GRANTED = "permission.granted"
    PERMISSION_REVOKED = "permission.revoked"
    OVERRIDE_CREATED = "permission.override.created"
    OVERRIDE_REVOKED = "permission.override.revoked"

    # Systems
    SYSTEM_CREATED = "system.created"
    SYSTEM_SETTINGS_CHANGED = "system.settings.changed"
    WEBHOOK_TRIGGERED = "system.webhook.triggered"
    WEBHOOK_FAILED = "system.webhook.failed"

class AuditLog(BaseModel):
    class Outcome(models.TextChoices):
        SUCCESS = "success", "Success"
        FAILURE = "failure", "Failure"
        PARTIAL = "partial", "Partial"

    event_type = models.CharField(
        max_length=80,
        choices=AuditEventType.choices,
        db_index=True
    )

    actor_user_id = models.UUIDField(null=True, blank=True, db_index=True)
    actor_system_user_id = models.UUIDField(null=True, blank=True)
    actor_email = models.EmailField(blank=True)
    actor_ip = models.GenericIPAddressField(null=True, blank=True)
    actor_user_agent = models.TextField(blank=True)

    subject_type = models.CharField(max_length=60, blank=True)
    subject_id = models.CharField(max_length=80, blank=True, db_index=True)
    subject_label = models.CharField(max_length=255, blank=True)

    system_id = models.UUIDField(null=True, blank=True, db_index=True)
    system_name = models.CharField(max_length=120, blank=True)
    organization_id = models.UUIDField(null=True, blank=True, db_index=True)
    organization_name = models.CharField(max_length=255, blank=True)
    country_code = models.CharField(max_length=2,   blank=True)

    sso_session_id = models.UUIDField(null=True, blank=True)
    token_jti = models.UUIDField(null=True, blank=True)

    identifier_type = models.CharField(max_length=30, blank=True)

    payload = models.JSONField(default=dict)

    outcome = models.CharField(
        max_length=20,
        choices=Outcome.choices,
        default=Outcome.SUCCESS,
    )
    failure_reason = models.TextField(blank=True)

    class Meta:
        db_table = "audit_log"
        indexes = [
            models.Index(fields=["actor_user_id", "created_at"]),
            models.Index(fields=["event_type", "created_at"]),
            models.Index(fields=["system_id", "created_at"]),
            models.Index(fields=["organization_id", "created_at"]),
            models.Index(fields=["subject_id", "created_at"]),
            models.Index(fields=["identifier_type", "created_at"]),
        ]

    def __str__(self):
        return f"{self.event_type} at {self.created_at}"


class RequestLog(BaseModel):
    request_id = models.UUIDField(editable=False, db_index=True)
    user_id = models.UUIDField(null=True, blank=True, db_index=True)
    system_user_id = models.UUIDField(null=True, blank=True, db_index=True)
    sso_session_id = models.UUIDField(null=True, blank=True, db_index=True)
    token_jti = models.UUIDField(null=True, blank=True, db_index=True)
    is_authenticated = models.BooleanField(default=False)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(null=True, blank=True)
    session_key = models.CharField(max_length=40, null=True, blank=True)
    request_method = models.CharField(max_length=10)
    request_path = models.TextField()
    request_data = models.JSONField(null=True, blank=True)
    is_secure = models.BooleanField(default=False)
    view_name = models.CharField(max_length=255, null=True, blank=True)
    view_args = models.JSONField(null=True, blank=True)
    view_kwargs = models.JSONField(null=True, blank=True)
    exception_type = models.CharField(max_length=255, null=True, blank=True)
    exception_message = models.TextField(null=True, blank=True)
    exception_traceback = models.TextField(null=True, blank=True)
    started_at = models.DateTimeField(auto_now_add=True)
    ended_at = models.DateTimeField(null=True, blank=True)
    time_taken = models.FloatField(null=True, blank=True)
    response_status = models.PositiveSmallIntegerField(null=True, blank=True)
    response_data = models.JSONField(null=True, blank=True)

    def __str__(self) -> str:
        return f'RequestLog {self.request_id} - {self.request_method} {self.request_path}'


class ModelAuditEventType(models.TextChoices):
    CREATE = 'CREATE', 'Create'
    UPDATE = 'UPDATE', 'Update'
    DELETE = 'DELETE', 'Delete'


class ModelAuditSeverity(models.TextChoices):
    LOW = 'LOW', 'Low'
    MEDIUM = 'MEDIUM', 'Medium'
    HIGH = 'HIGH', 'High'
    CRITICAL = 'CRITICAL', 'Critical'


class ModelAuditLog(BaseModel):
    request_id = models.UUIDField(null=True, blank=True, db_index=True)
    user_id = models.UUIDField(null=True, blank=True, db_index=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(null=True, blank=True)

    event_type = models.CharField(
        max_length=20,
        choices=ModelAuditEventType.choices,
        db_index=True,
    )
    severity = models.CharField(
        max_length=10,
        choices=ModelAuditSeverity.choices,
        default=ModelAuditSeverity.MEDIUM,
        db_index=True,
    )

    content_type = models.ForeignKey(
        ContentType,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
    )
    object_id = models.CharField(max_length=255, null=True, blank=True, db_index=True)
    content_object = GenericForeignKey('content_type', 'object_id')

    object_repr = models.CharField(max_length=255, blank=True)
    changes = models.JSONField(
        null=True,
        blank=True,
        encoder=DjangoJSONEncoder,
    )
    metadata = models.JSONField(null=True, blank=True, encoder=DjangoJSONEncoder)

    class Meta:
        indexes = [
            models.Index(fields=['created_at', 'event_type']),
            models.Index(fields=['content_type', 'object_id']),
            models.Index(fields=['severity', 'created_at']),
            models.Index(fields=['user_id']),
            models.Index(fields=['request_id']),
        ]

    def __str__(self):
        return f"{self.event_type} {self.object_repr} at {self.created_at}"


class ModelAuditConfiguration(BaseModel):
    app_label = models.CharField(max_length=100)
    model_name = models.CharField(max_length=100)
    is_enabled = models.BooleanField(default=True)
    track_create = models.BooleanField(default=True)
    track_update = models.BooleanField(default=True)
    track_delete = models.BooleanField(default=True)
    excluded_fields = models.JSONField(default=list, blank=True)
    retention_days = models.PositiveIntegerField(default=365)

    class Meta:
        unique_together = ('app_label', 'model_name')

    def __str__(self):
        return f'{self.app_label}.{self.model_name}'

    def save(self, *args, **kwargs):
        self.app_label = self.app_label.lower()
        self.model_name = self.model_name.lower()
        super().save(*args, **kwargs)
