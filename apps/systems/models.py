import secrets
from django.core.exceptions import ValidationError
from django.db import models
from apps.base.models import BaseModel, Realm


class System(BaseModel):
    realm = models.ForeignKey(
        Realm,
        on_delete=models.PROTECT,
        related_name="systems",
        editable=False,
        help_text="Realm determines SSO boundary and identifier uniqueness"
    )

    class PasswordType(models.TextChoices):
        PASSWORD = "password", "Password"
        PIN = "pin", "PIN"

    name = models.CharField(max_length=120, unique=True)
    slug = models.SlugField(max_length=80, unique=True)
    description = models.TextField(blank=True)
    logo_url = models.URLField(blank=True)
    website = models.URLField(blank=True)

    available_countries = models.ManyToManyField(
        "base.Country",
        related_name="available_systems",
    )

    required_identifier_types = models.JSONField(default=list)
    allowed_login_identifier_types = models.JSONField(default=list)

    password_type = models.CharField(
        max_length=10,
        choices=PasswordType.choices,
        default=PasswordType.PASSWORD
    )
    allow_password_login = models.BooleanField(default=True)
    allow_passwordless_login = models.BooleanField(default=False)
    allow_magic_link_login = models.BooleanField(default=False)
    allow_social_login = models.BooleanField(default=False)
    passwordless_only = models.BooleanField(default=False)

    allowed_social_providers = models.JSONField(default=list)
    registration_open = models.BooleanField(default=True)
    requires_approval = models.BooleanField(default=False)

    mfa_required = models.BooleanField(default=False)
    mfa_required_enforced = models.BooleanField(default=False)
    allowed_mfa_methods = models.JSONField(
        default=list,
        help_text="Empty = all MFA methods permitted. Non-empty = restrict to listed methods.",
    )

    is_active = models.BooleanField(default=True)

    class Meta:
        db_table = "systems_system"
        ordering = ["name"]

    def __str__(self):
        return self.name

    def save(self, *args, **kwargs):
        if self.pk:
            old = System.objects.get(pk=self.pk)
            if old.realm_id != self.realm_id:
                raise ValidationError(
                    "System realm cannot be changed after creation."
                )
        super().save(*args, **kwargs)

    def get_effective_allowed_mfa_methods(self) -> list:
        return self.allowed_mfa_methods or []

    def is_login_flow_allowed(self, flow: str) -> bool:
        if flow == "password":
            return self.allow_password_login and not self.passwordless_only
        if flow == "passwordless":
            return self.allow_passwordless_login
        if flow == "magic_link":
            return self.allow_magic_link_login
        if flow == "social":
            return self.allow_social_login
        return False

    def is_identifier_type_allowed_for_login(self, identifier_type: str) -> bool:
        if not self.allowed_login_identifier_types:
            return True
        return identifier_type in self.allowed_login_identifier_types


class SystemClient(BaseModel):
    class ClientType(models.TextChoices):
        CONFIDENTIAL = "confidential", "Confidential (server-side)"
        PUBLIC = "public", "Public (SPA / mobile)"
        M2M = "m2m", "Machine-to-Machine"

    system = models.ForeignKey(
        System,
        on_delete=models.CASCADE,
        related_name="clients"
    )
    name = models.CharField(max_length=120)
    client_id = models.CharField(max_length=80, unique=True, default=secrets.token_urlsafe)
    client_secret_hash = models.CharField(max_length=255, blank=True)
    client_type = models.CharField(
        max_length=30,
        choices=ClientType.choices,
        default=ClientType.CONFIDENTIAL,
    )
    redirect_uris = models.JSONField(default=list)
    logout_uris = models.JSONField(default=list)
    allowed_scopes = models.JSONField(default=list)
    access_token_ttl = models.PositiveIntegerField(default=0)
    refresh_token_ttl = models.PositiveIntegerField(default=0)
    id_token_ttl = models.PositiveIntegerField(default=0)

    override_allowed_login_identifier_types = models.JSONField(null=True, blank=True)
    override_allow_passwordless_login = models.BooleanField(null=True, blank=True)
    override_allow_magic_link_login = models.BooleanField(null=True, blank=True)
    override_allow_social_login = models.BooleanField(null=True, blank=True)
    override_allowed_social_providers = models.JSONField(null=True, blank=True)

    is_active = models.BooleanField(default=True)

    class Meta:
        db_table = "systems_client"
        unique_together = [("system", "name")]

    def __str__(self):
        return f"{self.system.name}/{self.name} ({self.client_id[:10]}…)"

    def get_effective_config(self) -> dict:
        system = self.system

        def resolve(client_val, system_val):
            return client_val if client_val is not None else system_val

        return {
            "allowed_login_identifier_types": resolve(
                self.override_allowed_login_identifier_types,
                system.allowed_login_identifier_types,
            ),
            "allow_password_login": (
                    system.allow_password_login and not system.passwordless_only
            ),
            "allow_passwordless_login": resolve(
                self.override_allow_passwordless_login,
                system.allow_passwordless_login,
            ),
            "allow_magic_link_login": resolve(
                self.override_allow_magic_link_login,
                system.allow_magic_link_login,
            ),
            "allow_social_login": resolve(
                self.override_allow_social_login,
                system.allow_social_login,
            ),
            "allowed_social_providers": resolve(
                self.override_allowed_social_providers,
                system.allowed_social_providers,
            ),
            "passwordless_only": system.passwordless_only,
            "registration_open": system.registration_open,
            "requires_approval": system.requires_approval,
            "mfa_required": system.mfa_required,
            "allowed_mfa_methods": system.allowed_mfa_methods,
        }


class SystemSettings(BaseModel):
    class ValueType(models.TextChoices):
        STRING = "string", "String"
        INTEGER = "integer", "Integer"
        BOOLEAN = "boolean", "Boolean"
        JSON = "json", "JSON"

    system = models.ForeignKey(System, on_delete=models.CASCADE, related_name="settings")
    key = models.CharField(max_length=120)
    value = models.TextField()
    value_type = models.CharField(
        max_length=20,
        choices=ValueType.choices,
        default=ValueType.STRING,
    )
    description = models.TextField(blank=True)
    is_secret = models.BooleanField(default=False)

    class Meta:
        db_table = "systems_settings"
        unique_together = [("system", "key")]

    def __str__(self):
        return f"{self.system.name}.{self.key}"

    def typed_value(self):
        import json
        if self.value_type == self.ValueType.BOOLEAN:
            return self.value.lower() in ("true", "1", "yes")
        if self.value_type == self.ValueType.INTEGER:
            return int(self.value)
        if self.value_type == self.ValueType.JSON:
            return json.loads(self.value)
        return self.value


class SystemWebhook(BaseModel):
    system = models.ForeignKey(System, on_delete=models.CASCADE, related_name="webhooks")
    name = models.CharField(max_length=80)
    endpoint_url = models.URLField()
    secret_encrypted = models.TextField()
    event_types = models.JSONField(default=list)
    is_active = models.BooleanField(default=True)
    last_triggered_at = models.DateTimeField(null=True, blank=True)
    last_response_code = models.PositiveSmallIntegerField(null=True, blank=True)
    consecutive_failures = models.PositiveSmallIntegerField(default=0)

    class Meta:
        db_table = "systems_webhook"

    def __str__(self):
        return f"{self.system.name} → {self.endpoint_url}"