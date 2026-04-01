from django.db import models

from apps.base.models import BaseModel


class PermissionCategory(BaseModel):
    system = models.ForeignKey(
        "systems.System",
        on_delete=models.CASCADE,
        related_name="permission_categories"
    )
    name = models.CharField(max_length=80)
    slug = models.SlugField(max_length=60)
    description = models.TextField(blank=True)

    class Meta:
        db_table = "permissions_category"
        unique_together = [("system", "slug")]

    def __str__(self):
        return f"{self.system.slug}:{self.slug}"


class Permission(BaseModel):
    system = models.ForeignKey(
        "systems.System",
        on_delete=models.CASCADE,
        related_name="permissions"
    )
    category = models.ForeignKey(
        PermissionCategory,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="permissions",
    )
    codename = models.CharField(max_length=120)
    name = models.CharField(max_length=255)
    description = models.TextField(blank=True)

    is_read_only = models.BooleanField(default=False)
    is_sensitive = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)

    class Meta:
        db_table = "permissions_permission"
        unique_together = [("system", "codename")]

    def __str__(self):
        return f"{self.system.slug}:{self.codename}"


class Role(BaseModel):
    system = models.ForeignKey(
        "systems.System",
        on_delete=models.CASCADE,
        related_name="roles"
    )
    country = models.ForeignKey(
        "base.Country",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="roles",
    )

    name = models.CharField(max_length=120)
    slug = models.SlugField(max_length=100)
    description = models.TextField(blank=True)

    permissions = models.ManyToManyField(
        Permission,
        through="RolePermission",
        related_name="roles",
    )

    parent_role = models.ForeignKey(
        "self",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="child_roles",
    )

    mfa_required = models.BooleanField(default=False)
    mfa_allowed_methods = models.JSONField(default=list, blank=True)

    is_system_defined = models.BooleanField(default=False)
    created_by_org = models.ForeignKey(
        "organizations.Organization",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="custom_roles",
    )

    is_active = models.BooleanField(default=True)

    class Meta:
        db_table = "permissions_role"
        unique_together = [("system", "country", "slug")]
        indexes = [
            models.Index(fields=["system", "is_active"]),
            models.Index(fields=["system", "country"]),
        ]

    def __str__(self):
        country_str = f"/{self.country.code}" if self.country_id else ""
        return f"{self.system.slug}{country_str}:{self.name}"

    def get_all_permission_ids(self, _visited: set = None) -> set:
        if _visited is None:
            _visited = set()
        if self.id in _visited:
            return set()
        _visited.add(self.id)

        ids = set(
            self.role_permissions
                .filter(is_active=True)
                .values_list("permission_id", flat=True)
        )
        if self.parent_role_id:
            ids |= self.parent_role.get_all_permission_ids(_visited)
        return ids


class RolePermission(BaseModel):
    role = models.ForeignKey(
        Role,
        on_delete=models.CASCADE,
        related_name="role_permissions"
    )
    permission = models.ForeignKey(
        Permission,
        on_delete=models.CASCADE,
        related_name="role_permissions"
    )
    conditions = models.JSONField(default=dict, blank=True)
    is_active = models.BooleanField(default=True)
    granted_at = models.DateTimeField(auto_now_add=True)
    granted_by = models.ForeignKey(
        "accounts.User",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="granted_role_permissions",
    )

    class Meta:
        db_table = "permissions_role_permission"
        unique_together = [("role", "permission")]


class UserPermissionOverride(BaseModel):
    class Effect(models.TextChoices):
        GRANT = "grant", "Grant"
        DENY = "deny", "Deny"

    system_user = models.ForeignKey(
        "accounts.SystemUser",
        on_delete=models.CASCADE,
        related_name="permission_overrides"
    )
    organization = models.ForeignKey("organizations.Organization", on_delete=models.CASCADE)
    country = models.ForeignKey("base.Country", on_delete=models.PROTECT)
    permission = models.ForeignKey(Permission, on_delete=models.CASCADE)

    effect = models.CharField(max_length=10, choices=Effect.choices)

    reason = models.TextField(blank=True)
    expires_at = models.DateTimeField(null=True, blank=True)
    is_active = models.BooleanField(default=True)
    granted_by = models.ForeignKey(
        "accounts.SystemUser",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="issued_overrides"
    )

    class Meta:
        db_table = "permissions_user_override"
        unique_together = [("system_user", "organization", "country", "permission")]

    def __str__(self):
        return (
            f"{self.effect.upper()} {self.permission.codename} "
            f"→ {self.system_user} in {self.organization}/{self.country.code}"
        )