from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin, BaseUserManager
from django.db import models
from django.utils import timezone

from apps.base.models import BaseModel, SoftDeleteModel


class UserManager(BaseUserManager):
    def create_user(
        self,
        password=None,
        email=None,
        phone_number=None,
        username=None,
        primary_country=None,
        added_by_system=None,
        **extra_fields,
    ):
        if not any([email, phone_number, username]):
            raise ValueError("At least one identifier (email, phone, username) is required")

        user = self.model(primary_country=primary_country, **extra_fields)
        if password:
            user.set_password(password)
        else:
            user.set_unusable_password()
        user.save(using=self._db)

        from apps.accounts.identifier_utils import IdentifierNormaliser

        if email:
            UserIdentifier.objects.create(
                user=user,
                identifier_type=IdentifierType.EMAIL,
                value=email,
                value_normalised=IdentifierNormaliser.normalise(email, IdentifierType.EMAIL),
                is_primary=(not phone_number and not username),
                added_by_system=added_by_system,
            )
        if phone_number:
            UserIdentifier.objects.create(
                user=user,
                identifier_type=IdentifierType.PHONE,
                value=phone_number,
                value_normalised=IdentifierNormaliser.normalise(phone_number, IdentifierType.PHONE),
                is_primary=(not email and not username),
                added_by_system=added_by_system,
            )
        if username:
            UserIdentifier.objects.create(
                user=user,
                identifier_type=IdentifierType.USERNAME,
                value=username,
                value_normalised=username.lower().strip(),
                is_primary=(not email and not phone_number),
                added_by_system=added_by_system,
            )
        return user

    def create_superuser(self, email, password, **extra_fields):
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)
        return self.create_user(email=email, password=password, **extra_fields)

    @staticmethod
    def get_by_identifier(value: str, identifier_type: str = None) -> "User":
        from apps.accounts.identifier_utils import IdentifierNormaliser, detect_identifier_type
        detected = identifier_type or detect_identifier_type(value)
        normalised = IdentifierNormaliser.normalise(value, detected)

        qs = UserIdentifier.objects.filter(value_normalised=normalised)
        if identifier_type:
            qs = qs.filter(identifier_type=identifier_type)

        row = qs.select_related("user").first()
        if not row:
            raise User.DoesNotExist(f"No active identifier: {value}")
        return row.user


class User(AbstractBaseUser, PermissionsMixin, BaseModel, SoftDeleteModel):
    primary_country = models.ForeignKey(
        "core.Country",
        null=True, blank=True,
        on_delete=models.SET_NULL,
        related_name="primary_users",
    )

    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    date_joined = models.DateTimeField(default=timezone.now)

    failed_login_attempts = models.PositiveSmallIntegerField(default=0)
    locked_until = models.DateTimeField(null=True, blank=True)

    objects = UserManager()

    USERNAME_FIELD  = "id"
    REQUIRED_FIELDS = []

    class Meta:
        db_table = "accounts_user"

    def __str__(self):
        primary = self.identifiers.filter(is_primary=True).first()
        return primary.value if primary else str(self.id)

    def is_locked(self):
        return self.locked_until is not None and self.locked_until > timezone.now()

    def get_email(self) -> str | None:
        row = self.identifiers.filter(
            identifier_type=IdentifierType.EMAIL
        ).first()
        return row.value if row else None

    def get_phone(self) -> str | None:
        row = self.identifiers.filter(
            identifier_type=IdentifierType.PHONE
        ).first()
        return row.value if row else None

    def get_primary_identifier(self) -> "UserIdentifier | None":
        return self.identifiers.filter(is_primary=True).first()


class IdentifierType(models.TextChoices):
    EMAIL = "email", "Email Address"
    PHONE = "phone", "Phone Number"
    USERNAME = "username", "Username"
    NATIONAL_ID = "national_id", "National ID"


class ActiveIdentifierManager(models.Manager):
    def get_queryset(self):
        return super().get_queryset().filter(disassociated_at__isnull=True)


class UserIdentifier(BaseModel):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="identifiers")
    identifier_type = models.CharField(max_length=30, choices=IdentifierType.choices)
    value = models.CharField(max_length=255)
    value_normalised = models.CharField(max_length=255, db_index=True)

    is_primary  = models.BooleanField(default=False)
    is_verified = models.BooleanField(default=False)
    verified_at = models.DateTimeField(null=True, blank=True)

    added_by_system = models.ForeignKey(
        "systems.System",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="added_identifiers",
    )

    disassociated_at = models.DateTimeField(null=True, blank=True, db_index=True)
    disassociation_reason = models.CharField(
        max_length=30,
        choices=[
            ("user_removed", "User removed it"),
            ("carrier_recycle", "Carrier number recycled"),
            ("expired", "Identifier expired"),
            ("admin_removed", "Admin removed it"),
            ("superseded", "Replaced by newer identifier"),
        ],
        blank=True,
    )
    disassociated_by = models.ForeignKey(
        User,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="disassociated_identifiers",
    )

    objects = ActiveIdentifierManager()
    all_objects = models.Manager()

    class Meta:
        db_table = "accounts_user_identifier"
        constraints = [
            models.UniqueConstraint(
                fields=["identifier_type", "value_normalised"],
                condition=models.Q(disassociated_at__isnull=True),
                name="unique_active_identifier",
            )
        ]
        indexes = [
            models.Index(fields=["user", "identifier_type"]),
            models.Index(fields=["identifier_type", "value_normalised"]),
        ]

    def __str__(self):
        status = "active" if not self.disassociated_at else "disassociated"
        return f"{self.identifier_type}:{self.value} ({status})"

    @property
    def is_active(self):
        return self.disassociated_at is None

    def disassociate(self, reason: str, disassociated_by: User = None):
        self.disassociated_at = timezone.now()
        self.disassociation_reason = reason
        self.is_primary = False
        self.disassociated_by = disassociated_by
        self.save(update_fields=[
            "disassociated_at",
            "disassociation_reason",
            "disassociated_by",
            "is_primary",
        ])


class MFAMethod(models.TextChoices):
    TOTP = "totp", "Authenticator App (TOTP)"
    SMS = "sms", "SMS OTP"
    EMAIL = "email_otp", "Email OTP"
    WEBAUTHN = "webauthn", "Hardware Key / Passkey (WebAuthn)"
    BACKUP = "backup", "Backup Code"


class UserMFA(BaseModel, SoftDeleteModel):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="mfa_methods")
    method = models.CharField(max_length=20, choices=MFAMethod.choices)
    is_primary = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)

    # Encrypted secret (TOTP) or public key (WebAuthn)
    secret_encrypted = models.TextField(blank=True)

    # WebAuthn: identifies the credential / authenticator device
    credential_id = models.TextField(blank=True, db_index=True)

    # SMS/Email: explicit override for delivery destination
    # If blank, resolved at runtime from UserIdentifier
    delivery_target = models.CharField(max_length=120, blank=True)

    # Friendly name shown in "your enrolled devices" list
    device_name = models.CharField(max_length=120, blank=True)

    last_used_at = models.DateTimeField(null=True, blank=True)
    verified_at  = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = "accounts_user_mfa"
        unique_together = [("user", "method", "credential_id")]

    def __str__(self):
        return f"{self.user} – {self.method} ({'primary' if self.is_primary else 'secondary'})"


class BackupCode(BaseModel, SoftDeleteModel):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="backup_codes")
    code_hash = models.CharField(max_length=128)
    is_used = models.BooleanField(default=False, db_index=True)
    used_at = models.DateTimeField(null=True, blank=True)
    used_from_ip = models.GenericIPAddressField(null=True, blank=True)
    invalidated_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = "accounts_backup_code"


class PendingMFAEnrollment(BaseModel, SoftDeleteModel):
    session = models.OneToOneField(
        "sso.SSOSession",
        on_delete=models.CASCADE,
        related_name="pending_mfa_enrollment"
    )
    required_by = models.CharField(max_length=255)
    allowed_methods = models.JSONField(default=list)
    context_system_user_id  = models.UUIDField(null=True, blank=True)
    context_org_id = models.UUIDField(null=True, blank=True)
    context_country_code = models.CharField(max_length=2, blank=True)
    expires_at = models.DateTimeField()
    completed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = "accounts_pending_mfa_enrollment"

    def is_expired(self):
        return timezone.now() >= self.expires_at


class Gender(models.TextChoices):
    MALE = "male", "Male"
    FEMALE = "female", "Female"
    OTHER = "other", "Other"
    PREFER_NOT = "prefer_not", "Prefer not to say"


class SystemUserStatus(models.TextChoices):
    PENDING = "pending", "Pending — provisioned, awaiting claim"
    INVITED = "invited", "Invited — email/SMS sent"
    ACTIVE = "active", "Active — claimed and in use"
    SUSPENDED = "suspended", "Suspended"


class SystemUser(BaseModel, SoftDeleteModel):
    user = models.ForeignKey(
        User,
        null=True,
        blank=True,
        on_delete=models.CASCADE,
        related_name="system_users",
    )
    system  = models.ForeignKey(
        "systems.System",
        on_delete=models.CASCADE,
        related_name="system_users"
    )
    country = models.ForeignKey(
        "core.Country",
        on_delete=models.PROTECT,
        related_name="system_users"
    )

    status = models.CharField(
        max_length=20,
        choices=SystemUserStatus.choices,
        default=SystemUserStatus.PENDING,
        db_index=True,
    )

    # Invite flow
    provisioning_email = models.EmailField(blank=True, db_index=True)
    provisioning_phone = models.CharField(max_length=30, blank=True)
    claim_token_lookup_id = models.CharField(
        max_length=32,
        unique=True,
        db_index=True,
        editable=False,
    )
    claim_token_hash = models.CharField(max_length=255, blank=True)
    claim_token_expires_at = models.DateTimeField(null=True, blank=True)
    invited_at = models.DateTimeField(null=True, blank=True)
    claimed_at = models.DateTimeField(null=True, blank=True)

    # Per-system profile
    first_name = models.CharField(max_length=120, blank=True)
    last_name = models.CharField(max_length=120, blank=True)
    middle_name = models.CharField(max_length=120, blank=True)
    display_name = models.CharField(max_length=255, blank=True)
    date_of_birth = models.DateField(null=True, blank=True)
    gender = models.CharField(max_length=20, choices=Gender.choices, blank=True)
    profile_photo_url = models.URLField(blank=True)

    # System-specific reference
    external_ref = models.CharField(max_length=120, blank=True, db_index=True)

    # Suspension
    is_suspended = models.BooleanField(default=False, db_index=True)
    suspended_reason = models.TextField(blank=True)
    suspended_at = models.DateTimeField(null=True, blank=True)
    suspended_by = models.ForeignKey(
        User,
        null=True, blank=True,
        on_delete=models.SET_NULL,
        related_name="suspended_system_users",
    )

    # Activity
    registered_at = models.DateTimeField(auto_now_add=True)
    last_login_at = models.DateTimeField(null=True, blank=True)

    # Metadata for system-specific extras
    metadata = models.JSONField(default=dict, blank=True)

    class Meta:
        db_table = "accounts_system_user"
        constraints = [
            models.UniqueConstraint(
                fields=["user", "system"],
                condition=models.Q(user__isnull=False),
                name="unique_claimed_system_user",
            )
        ]
        indexes = [
            models.Index(fields=["system", "country"]),
            models.Index(fields=["system", "status"]),
            models.Index(fields=["system", "is_suspended"]),
        ]

    def __str__(self):
        identifier = self.user or self.provisioning_email or self.provisioning_phone or str(self.id)
        return f"{identifier} @ {self.system.name}"

    @property
    def is_claimable(self):
        return (
            self.status == SystemUserStatus.INVITED
            and self.claim_token_expires_at
            and self.claim_token_expires_at > timezone.now()
        )

    @property
    def full_name(self):
        parts = filter(None, [self.first_name, self.middle_name, self.last_name])
        return " ".join(parts) or self.display_name or ""


class SocialAccount(BaseModel, SoftDeleteModel):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="social_accounts")
    provider = models.CharField(max_length=50)
    uid = models.CharField(max_length=255)

    access_token  = models.TextField(blank=True)
    refresh_token = models.TextField(blank=True)
    token_expires_at = models.DateTimeField(null=True, blank=True)
    extra_data = models.JSONField(default=dict)

    class Meta:
        db_table = "accounts_social_account"
        unique_together = [("provider", "uid")]

    def __str__(self):
        return f"{self.provider}:{self.uid} → {self.user}"
