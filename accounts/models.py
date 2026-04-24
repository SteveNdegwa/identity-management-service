from typing import Optional

import bcrypt

from django.contrib.auth.models import BaseUserManager
from django.core.exceptions import ValidationError
from django.db import models
from django.utils import timezone

from base.models import BaseModel, SoftDeleteModel, Realm


class UserManager(BaseUserManager):
    def create_user(
            self,
            realm=None,
            password=None,
            pin=None,
            email=None,
            phone_number=None,
            username=None,
            national_id=None,
            primary_country=None,
            added_by_system=None,
            **extra_fields,
    ):
        if not realm:
            raise ValueError("Realm is required when creating a user")
        if not any([email, phone_number, username]):
            raise ValueError("At least one identifier (email, phone, username) is required")

        user = self.model(
            realm=realm,
            primary_country=primary_country,
            **extra_fields
        )

        if password:
            user.set_password(password)

        if pin:
            user.set_pin(pin)

        user.save(using=self._db)

        # Create identifiers
        from accounts.identifier_utils import IdentifierNormaliser
        if email:
            UserIdentifier.objects.create(
                user=user,
                realm=realm,
                identifier_type=IdentifierType.EMAIL,
                value=email,
                value_normalised=IdentifierNormaliser.normalise(email, IdentifierType.EMAIL),
                is_primary=True,
                added_by_system=added_by_system,
            )
        if phone_number:
            UserIdentifier.objects.create(
                user=user,
                realm=realm,
                identifier_type=IdentifierType.PHONE,
                value=phone_number,
                value_normalised=IdentifierNormaliser.normalise(phone_number, IdentifierType.PHONE),
                is_primary=False,
                added_by_system=added_by_system,
            )
        if username:
            UserIdentifier.objects.create(
                user=user,
                realm=realm,
                identifier_type=IdentifierType.USERNAME,
                value=username,
                value_normalised=IdentifierNormaliser.normalise(username, IdentifierType.USERNAME),
                is_primary=False,
                added_by_system=added_by_system,
            )

        if national_id:
            UserIdentifier.objects.create(
                user=user,
                realm=realm,
                identifier_type=IdentifierType.NATIONAL_ID,
                value=national_id,
                value_normalised=IdentifierNormaliser.normalise(national_id, IdentifierType.NATIONAL_ID),
                is_primary=False,
                added_by_system=added_by_system,
            )
        return user

    @staticmethod
    def get_by_identifier(realm: Realm, value: str, identifier_type: str = None) -> "User":
        from accounts.identifier_utils import detect_identifier_type, IdentifierNormaliser
        detected = identifier_type or detect_identifier_type(value)
        normalised = IdentifierNormaliser.normalise(value, detected)

        qs = UserIdentifier.objects.filter(
            realm=realm,
            value_normalised=normalised,
            identifier_type=detected
        )

        row = qs.select_related("user").first()
        if not row:
            raise User.DoesNotExist(f"No active identifier: {value}")
        return row.user


class User(BaseModel, SoftDeleteModel):
    realm = models.ForeignKey(
        Realm,
        on_delete=models.PROTECT,
        related_name="users"
    )
    primary_country = models.ForeignKey(
        "base.Country",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="primary_users",
    )
    password = models.CharField(max_length=128, blank=True)
    pin = models.CharField(max_length=255, blank=True)
    last_login = models.DateTimeField(blank=True, null=True)
    is_active = models.BooleanField(default=True)
    date_joined = models.DateTimeField(default=timezone.now)
    failed_login_attempts = models.PositiveSmallIntegerField(default=0)
    locked_until = models.DateTimeField(null=True, blank=True)

    objects = UserManager()

    class Meta:
        db_table = "accounts_user"

    def __str__(self) -> str:
        primary = self.identifiers.filter(is_primary=True).first()
        return primary.value if primary else str(self.id)

    def save(self, *args, **kwargs) -> None:
        if self.pk:  # Existing user
            old = User.objects.get(pk=self.pk)
            if old.realm_id != self.realm_id:
                raise ValidationError("Cannot change realm.")
        super().save(*args, **kwargs)

    def set_password(self, raw_password: str) -> None:
        self.password = bcrypt.hashpw(raw_password.encode(), bcrypt.gensalt()).decode()

    def check_password(self, raw_password: str) -> bool:
        if not self.password:
            return False
        return bcrypt.checkpw(raw_password.encode(), self.pin.encode())

    def set_pin(self, raw_pin: str) -> None:
        self.pin = bcrypt.hashpw(raw_pin.encode(), bcrypt.gensalt()).decode()

    def check_pin(self, raw_pin: str) -> bool:
        if not self.pin:
            return False
        return bcrypt.checkpw(raw_pin.encode(), self.pin.encode())

    def is_locked(self) -> bool:
        return self.locked_until is not None and self.locked_until > timezone.now()

    def get_email(self) -> Optional[str]:
        row = self.identifiers.filter(identifier_type=IdentifierType.EMAIL).first()
        return row.value if row else None

    def get_phone(self) -> Optional[str]:
        row = self.identifiers.filter(identifier_type=IdentifierType.PHONE).first()
        return row.value if row else None

    def get_national_id(self) -> Optional[str]:
        row = self.identifiers.filter(identifier_type=IdentifierType.NATIONAL_ID).first()
        return row.value if row else None

    def get_primary_identifier(self) -> Optional["UserIdentifier"]:
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
    realm = models.ForeignKey(Realm, on_delete=models.PROTECT, related_name="identifiers")

    identifier_type = models.CharField(max_length=30, choices=IdentifierType.choices)
    value = models.CharField(max_length=255)
    value_normalised = models.CharField(max_length=255, db_index=True)
    is_primary = models.BooleanField(default=False)
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
                fields=["realm", "identifier_type", "value_normalised"],
                condition=models.Q(disassociated_at__isnull=True),
                name="unique_active_identifier_per_realm",
            )
        ]
        indexes = [
            models.Index(fields=["realm", "identifier_type", "value_normalised"]),
            models.Index(fields=["user", "identifier_type"]),
        ]

    def save(self, *args, **kwargs):
        if self.pk:  # Existing identifier
            old = UserIdentifier.objects.get(pk=self.pk)
            if old.realm_id != self.realm_id:
                raise ValidationError("Cannot change realm of an existing identifier")
        else:
            # New identifier - auto set realm from user
            if self.user_id and not self.realm_id:
                self.realm = self.user.realm
        super().save(*args, **kwargs)

    def __str__(self):
        status = "active" if not self.disassociated_at else "disassociated"
        return f"{self.identifier_type}:{self.value} ({status}) @ {self.realm.name}"

    @property
    def is_active(self):
        return self.disassociated_at is None

    def disassociate(self, reason: str, disassociated_by: User = None):
        self.disassociated_at = timezone.now()
        self.disassociation_reason = reason
        self.is_primary = False
        self.disassociated_by = disassociated_by
        self.save(update_fields=[
            "disassociated_at", "disassociation_reason", "disassociated_by", "is_primary"
        ])


class Gender(models.TextChoices):
    MALE = "male", "Male"
    FEMALE = "female", "Female"
    OTHER = "other", "Other"
    PREFER_NOT = "prefer_not", "Prefer not to say"


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
        db_index=True
    )
    system = models.ForeignKey(
        "systems.System",
        on_delete=models.CASCADE,
        related_name="system_users",
        db_index=True
    )
    organization = models.ForeignKey(
        "organizations.Organization",
        on_delete=models.CASCADE,
        related_name="memberships",
        db_index=True
    )
    country = models.ForeignKey(
        "base.Country",
        on_delete=models.PROTECT,
        related_name="system_users"
    )
    role = models.ForeignKey(
        "permissions.Role",
        on_delete=models.PROTECT,
        related_name="org_memberships"
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
        blank=True
    )
    # Invite flow
    provisioning_email = models.EmailField(blank=True, db_index=True)
    provisioning_phone = models.CharField(max_length=30, blank=True, db_index=True)
    provisioning_national_id = models.CharField(max_length=20, blank=True, db_index=True)
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
                name="unique_user_per_system_org"
            )
        ]
        indexes = [
            models.Index(fields=["system", "country", "organization"]),
            models.Index(fields=["user", "system", "status"]),
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


class Referral(BaseModel):
    referrer = models.ForeignKey(
        SystemUser,
        on_delete=models.CASCADE,
        related_name="referrals_made",
    )
    referred = models.OneToOneField(
        SystemUser,
        on_delete=models.CASCADE,
        related_name="referral_record",
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
    provider = models.CharField(max_length=50)
    uid = models.CharField(max_length=255)
    access_token = models.TextField(blank=True)
    refresh_token = models.TextField(blank=True)
    token_expires_at = models.DateTimeField(null=True, blank=True)
    extra_data = models.JSONField(default=dict)

    class Meta:
        db_table = "accounts_social_account"
        # unique_together = [("provider", "uid")]

    def __str__(self):
        return f"{self.provider}:{self.uid} → {self.user}"
