from django.db import models

from apps.base.models import BaseModel


class Organization(BaseModel):
    system = models.ForeignKey(
        "systems.System",
        on_delete=models.CASCADE,
        related_name="organizations"
    )
    name = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    slug = models.SlugField(max_length=120)
    logo_url = models.URLField(blank=True)
    website = models.URLField(blank=True)

    countries = models.ManyToManyField(
        "base.Country",
        through="OrganizationCountry",
        related_name="organizations",
    )

    is_active = models.BooleanField(default=True)
    verified = models.BooleanField(default=False)
    verified_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = "organizations_organization"
        unique_together = [("system", "slug")]

    def __str__(self):
        return f"{self.name} ({self.system})"


class OrganizationCountry(BaseModel):
    organization = models.ForeignKey(
        Organization,
        on_delete=models.CASCADE,
        related_name="organization_countries",
    )
    country = models.ForeignKey(
        "base.Country",
        on_delete=models.CASCADE,
        related_name="organization_countries",
    )

    registration_number = models.CharField(max_length=120, blank=True)
    tax_id = models.CharField(max_length=120, blank=True)

    is_active = models.BooleanField(default=True)
    activated_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "organizations_organization_country"
        unique_together = [("organization", "country")]

    def __str__(self):
        return f"{self.organization.name} - {self.country.code}"


class Branch(BaseModel):
    organization = models.ForeignKey(
        Organization,
        on_delete=models.CASCADE,
        related_name="branches"
    )
    country = models.ForeignKey(
        "base.Country",
        on_delete=models.PROTECT,
        related_name="branches"
    )
    name = models.CharField(max_length=255)
    code = models.CharField(max_length=40, blank=True)

    parent = models.ForeignKey(
        "self",
        null=True, blank=True,
        on_delete=models.SET_NULL,
        related_name="children",
    )

    is_active = models.BooleanField(default=True)
    metadata = models.JSONField(default=dict, blank=True)

    class Meta:
        db_table = "organizations_branch"
        unique_together = [("organization", "country", "code")]

    def __str__(self):
        return f"{self.name} ({self.organization.name}, {self.country.code})"


class OrganizationSettings(BaseModel):
    class ValueType(models.TextChoices):
        STRING  = "string",  "String"
        INTEGER = "integer", "Integer"
        BOOLEAN = "boolean", "Boolean"
        JSON = "json", "JSON"
        URL = "url", "URL"

    organization = models.ForeignKey(
        Organization,
        on_delete=models.CASCADE,
        related_name="settings"
    )
    key = models.CharField(max_length=120)
    value = models.TextField()
    value_type = models.CharField(
        max_length=20,
        choices=ValueType.choices,
        default=ValueType.STRING,
    )
    description = models.TextField(blank=True)
    is_secret = models.BooleanField(default=False)
    updated_by = models.ForeignKey(
        "accounts.SystemUser",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
    )

    class Meta:
        db_table = "organizations_settings"
        unique_together = [("organization", "key")]

    def __str__(self):
        return f"{self.organization.name}.{self.key}"

    def typed_value(self):
        import json
        if self.value_type == self.ValueType.BOOLEAN:
            return self.value.lower() in ("true", "1", "yes")
        if self.value_type == self.ValueType.INTEGER:
            return int(self.value)
        if self.value_type == self.ValueType.JSON:
            return json.loads(self.value)
        return self.value
