import secrets
from typing import Optional

import bcrypt
from django.contrib.auth.base_user import AbstractBaseUser, BaseUserManager
from django.contrib.auth.models import PermissionsMixin
from django.core.exceptions import ValidationError
from django.db import models
from django.utils import timezone

from base.models import BaseModel, SoftDeleteModel, Realm
from utils.social_providers import SocialProvider


def generate_claim_lookup_id() -> str:
    return secrets.token_urlsafe(16)


class Gender(models.TextChoices):
    MALE = "male", "Male"
    FEMALE = "female", "Female"
    OTHER = "other", "Other"
    PREFER_NOT = "prefer_not", "Prefer not to say"


class IdentifierType(models.TextChoices):
    EMAIL = "email", "Email Address"
    PHONE = "phone", "Phone Number"


class UserManager(BaseUserManager):
    use_in_migrations = True

    def _create_user(
            self,
            realm: Realm,
            email: str,
            phone_number: str,
            password: Optional[str],
            pin: Optional[str],
            **extra_fields,
    ):
        if not email:
            raise ValueError("Email is required.")
        if not phone_number:
            raise ValueError("Phone number is required.")

        user = self.model(
            realm=realm,
            email=self.normalize_email(email).strip().lower(),
            phone_number=phone_number.strip(),
            **extra_fields,
        )

        if password:
            user.set_password(password)
        else:
            user.set_unusable_password()

        if pin:
            user.set_pin(pin)

        user.save(using=self._db)
        return user

    def create_user(
            self,
            realm: Realm,
            email: str,
            phone_number: str,
            password: Optional[str] = None,
            pin: Optional[str] = None,
            **extra_fields,
    ):
        extra_fields.setdefault("is_staff", False)
        extra_fields.setdefault("is_superuser", False)
        extra_fields.setdefault("is_active", True)
        return self._create_user(realm, email, phone_number, password, pin, **extra_fields)

    def create_superuser(
            self,
            email: str,
            phone_number: str,
            password: str,
            **extra_fields,
    ):
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)
        extra_fields.setdefault("is_active", True)

        if extra_fields.get("is_staff") is not True:
            raise ValueError("Superuser must have is_staff=True.")
        if extra_fields.get("is_superuser") is not True:
            raise ValueError("Superuser must have is_superuser=True.")

        realm, _ = Realm.objects.get_or_create(name="Admin")

        return self._create_user(realm, email, phone_number, password, None, **extra_fields)

    def get_by_identifier(self, realm: Realm, value: str, identifier_type: IdentifierType) -> "User":
        from identifier_utils import IdentifierNormaliser
        if identifier_type not in IdentifierType.values:
            raise ValueError("Invalid identifier type.")

        normalised = IdentifierNormaliser.normalise(value, identifier_type)
        if not normalised:
            raise User.DoesNotExist("Identifier is required.")

        if identifier_type == IdentifierType.PHONE:
            return self.get(realm=realm, phone_number=normalised)
        return self.get(realm=realm, email=normalised)


class User(AbstractBaseUser, PermissionsMixin, BaseModel, SoftDeleteModel):
    realm = models.ForeignKey(
        Realm,
        on_delete=models.PROTECT,
        related_name="users",
    )
    primary_country = models.ForeignKey(
        "base.Country",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="primary_users",
    )

    email = models.EmailField()
    email_verified = models.BooleanField(default=False)
    email_verified_at = models.DateTimeField(null=True, blank=True)
    phone_number = models.CharField(max_length=30)
    phone_verified = models.BooleanField(default=False)
    phone_verified_at = models.DateTimeField(null=True, blank=True)

    first_name = models.CharField(max_length=120, blank=True)
    last_name = models.CharField(max_length=120, blank=True)
    middle_name = models.CharField(max_length=120, blank=True)
    display_name = models.CharField(max_length=255, blank=True)
    date_of_birth = models.DateField(null=True, blank=True)
    gender = models.CharField(max_length=20, choices=Gender.choices, blank=True)
    profile_photo_url = models.URLField(blank=True)

    pin = models.CharField(max_length=255, blank=True)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    date_joined = models.DateTimeField(default=timezone.now)
    failed_login_attempts = models.PositiveSmallIntegerField(default=0)
    locked_until = models.DateTimeField(null=True, blank=True)

    objects = UserManager()

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = ["phone_number"]

    class Meta:
        db_table = "accounts_user"
        constraints = [
            models.UniqueConstraint(
                fields=["realm", "email"],
                name="unique_user_email_per_realm",
            ),
            models.UniqueConstraint(
                fields=["realm", "phone_number"],
                name="unique_user_phone_per_realm",
            ),
        ]

    def __str__(self) -> str:
        return self.email

    def save(self, *args, **kwargs) -> None:
        self.email = self.email.strip().lower()
        self.phone_number = self.phone_number.strip()
        if not self._state.adding:
            old = User.all_objects.get(pk=self.pk)
            if old.realm_id and self.realm_id and old.realm_id != self.realm_id:
                raise ValidationError("Cannot change realm.")
        super().save(*args, **kwargs)

    def set_pin(self, raw_pin: str) -> None:
        self.pin = bcrypt.hashpw(raw_pin.encode(), bcrypt.gensalt()).decode()

    def check_pin(self, raw_pin: str) -> bool:
        if not self.pin:
            return False
        return bcrypt.checkpw(raw_pin.encode(), self.pin.encode())

    def is_locked(self) -> bool:
        return self.locked_until is not None and self.locked_until > timezone.now()

    def get_email(self) -> str:
        return self.email

    def get_phone(self) -> str:
        return self.phone_number

    @property
    def full_name(self) -> str:
        parts = [self.first_name, self.middle_name, self.last_name]
        return " ".join(part for part in parts if part).strip() or self.display_name or self.email


class SystemUserStatus(models.TextChoices):
    PENDING = "pending", "Pending"
    INVITED = "invited", "Invited"
    ACTIVE = "active", "Active"
    SUSPENDED = "suspended", "Suspended"
    REMOVED = "removed", "Removed"


class SystemUser(BaseModel, SoftDeleteModel):
    user = models.ForeignKey(
        User,
        null=True,
        blank=True,
        on_delete=models.CASCADE,
        related_name="system_users",
        db_index=True,
    )
    system = models.ForeignKey(
        "systems.System",
        on_delete=models.CASCADE,
        related_name="system_users",
        db_index=True,
    )
    organization = models.ForeignKey(
        "organizations.Organization",
        null=True,
        blank=True,
        on_delete=models.CASCADE,
        related_name="memberships",
        db_index=True,
    )
    country = models.ForeignKey(
        "base.Country",
        null=True,
        blank=True,
        on_delete=models.PROTECT,
        related_name="system_users",
    )
    role = models.ForeignKey(
        "permissions.Role",
        on_delete=models.PROTECT,
        related_name="org_memberships",
    )
    all_branches = models.BooleanField(default=True)
    branch_access = models.ManyToManyField(
        "organizations.Branch",
        blank=True,
        related_name="memberships",
    )
    status = models.CharField(
        max_length=20,
        choices=SystemUserStatus.choices,
        default=SystemUserStatus.PENDING,
        db_index=True,
    )
    provisioned_by = models.ForeignKey(
        "self",
        on_delete=models.SET_NULL,
        related_name="user_system_provisions",
        null=True,
        blank=True,
    )

    provisioning_email = models.EmailField(blank=True, db_index=True)
    claim_token_lookup_id = models.CharField(
        max_length=64,
        unique=True,
        db_index=True,
        default=generate_claim_lookup_id,
    )
    claim_token_hash = models.CharField(max_length=255, blank=True)
    claim_token_expires_at = models.DateTimeField(null=True, blank=True)
    invited_at = models.DateTimeField(null=True, blank=True)
    claimed_at = models.DateTimeField(null=True, blank=True)

    external_ref = models.CharField(max_length=120, blank=True, db_index=True)
    referral_code = models.CharField(max_length=32, null=True, blank=True, unique=True, db_index=True)

    suspended_reason = models.TextField(blank=True)
    suspended_at = models.DateTimeField(null=True, blank=True)
    suspended_by = models.ForeignKey(
        "self",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="suspended_system_users",
    )

    registered_at = models.DateTimeField(auto_now_add=True)
    last_login_at = models.DateTimeField(null=True, blank=True)
    metadata = models.JSONField(default=dict, blank=True)

    class Meta:
        db_table = "accounts_system_user"
        constraints = [
            models.UniqueConstraint(
                fields=["user", "system", "organization"],
                condition=models.Q(status=SystemUserStatus.ACTIVE),
                name="unique_user_per_system_org",
            )
        ]
        indexes = [
            models.Index(fields=["system", "country", "organization"]),
            models.Index(fields=["user", "system", "status"]),
        ]

    def __str__(self):
        identifier = self.user.email if self.user_id else self.provisioning_email or str(self.id)
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
        if self.user_id:
            return self.user.full_name
        return self.provisioning_email or ""


class Referral(BaseModel):
    referrer = models.ForeignKey(
        SystemUser,
        on_delete=models.CASCADE,
        related_name="referrals_made",
    )
    referred = models.ForeignKey(
        SystemUser,
        on_delete=models.CASCADE,
        related_name="referred_by",
    )
    system = models.ForeignKey(
        "systems.System",
        on_delete=models.CASCADE,
        related_name="referrals",
    )
    referral_code = models.CharField(max_length=32, db_index=True)
    is_verified = models.BooleanField(default=False)
    verified_at = models.DateTimeField(null=True, blank=True)
    is_rewarded = models.BooleanField(default=False)
    rewarded_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = "accounts_referral"
        constraints = [
            models.CheckConstraint(
                condition=~models.Q(referrer=models.F("referred")),
                name="accounts_referral_no_self_referral",
            )
        ]
        indexes = [
            models.Index(fields=["system", "is_verified", "is_rewarded"]),
            models.Index(fields=["referrer", "is_verified", "is_rewarded"]),
        ]

    def __str__(self):
        return f"{self.referrer_id} -> {self.referred_id}"


class SocialAccount(BaseModel, SoftDeleteModel):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="social_accounts")
    provider = models.CharField(max_length=50, choices=SocialProvider.choices)
    uid = models.CharField(max_length=255)
    access_token = models.TextField(blank=True)
    refresh_token = models.TextField(blank=True)
    token_expires_at = models.DateTimeField(null=True, blank=True)
    extra_data = models.JSONField(default=dict)

    class Meta:
        db_table = "accounts_social_account"
        constraints = [
            models.UniqueConstraint(fields=["provider", "uid"], name="unique_social_provider_uid")
        ]

    def __str__(self):
        return f"{self.provider}:{self.uid} → {self.user.email}"


class VerificationMethod(models.TextChoices):
    OTP = "otp", "OTP Code"
    LINK = "link", "Verification Link"


class ContactVerificationPurpose(models.TextChoices):
    REGISTRATION = "registration", "Registration"
    PROFILE_UPDATE = "profile_update", "Profile Update"


class ContactVerification(BaseModel):
    user = models.ForeignKey(
        User,
        null=True,
        blank=True,
        on_delete=models.CASCADE,
        related_name="contact_verifications",
    )
    contact_type = models.CharField(max_length=20, choices=IdentifierType.choices)
    value = models.CharField(max_length=255)
    value_normalized = models.CharField(max_length=255, db_index=True)
    method = models.CharField(max_length=20, choices=VerificationMethod.choices)
    purpose = models.CharField(max_length=30, choices=ContactVerificationPurpose.choices)

    code_hash = models.CharField(max_length=128, blank=True)
    token_hash = models.CharField(max_length=128, blank=True)
    expires_at = models.DateTimeField()
    attempts = models.PositiveSmallIntegerField(default=0)
    is_used = models.BooleanField(default=False, db_index=True)
    used_at = models.DateTimeField(null=True, blank=True)
    is_verified = models.BooleanField(default=False, db_index=True)
    verified_at = models.DateTimeField(null=True, blank=True)
    consumed_at = models.DateTimeField(null=True, blank=True)
    ip_requested = models.GenericIPAddressField(null=True, blank=True)
    ip_verified = models.GenericIPAddressField(null=True, blank=True)

    class Meta:
        db_table = "accounts_contact_verification"
        indexes = [
            models.Index(fields=["contact_type", "value_normalized", "created_at"]),
            models.Index(fields=["is_verified", "consumed_at", "expires_at"]),
        ]

    def is_expired(self):
        return timezone.now() >= self.expires_at
