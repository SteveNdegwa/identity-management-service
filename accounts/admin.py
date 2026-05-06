from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as DjangoUserAdmin
from django.contrib.auth.forms import ReadOnlyPasswordHashField
from django import forms

from accounts.models import (
    ContactVerification,
    Referral,
    SocialAccount,
    SystemUser,
    User,
)


class UserCreationForm(forms.ModelForm):
    password1 = forms.CharField(widget=forms.PasswordInput)
    password2 = forms.CharField(widget=forms.PasswordInput)

    class Meta:
        model = User
        fields = ("email", "phone_number", "realm")

    def clean(self):
        cleaned = super().clean()
        if cleaned.get("password1") != cleaned.get("password2"):
            raise forms.ValidationError("Passwords do not match.")
        return cleaned

    def save(self, commit=True):
        user = super().save(commit=False)
        user.set_password(self.cleaned_data["password1"])
        if commit:
            user.save()
        return user


class UserChangeForm(forms.ModelForm):
    password = ReadOnlyPasswordHashField()

    class Meta:
        model = User
        fields = "__all__"


@admin.register(User)
class UserAdmin(DjangoUserAdmin):
    form = UserChangeForm
    add_form = UserCreationForm
    model = User
    list_display = ("email", "phone_number", "realm", "primary_country", "is_active", "is_staff", "email_verified", "phone_verified")
    list_filter = ("is_active", "is_staff", "email_verified", "phone_verified", "realm")
    autocomplete_fields = ("realm", "primary_country")
    ordering = ("email",)
    search_fields = ("email", "phone_number", "first_name", "last_name")
    fieldsets = (
        (None, {"fields": ("email", "phone_number", "password", "pin", "realm", "primary_country")}),
        ("Profile", {"fields": ("first_name", "last_name", "middle_name", "display_name", "date_of_birth", "gender", "profile_photo_url")}),
        ("Verification", {"fields": ("email_verified", "email_verified_at", "phone_verified", "phone_verified_at")}),
        ("Permissions", {"fields": ("is_active", "is_staff", "is_superuser", "groups", "user_permissions")}),
        ("Security", {"fields": ("failed_login_attempts", "locked_until", "last_login", "date_joined")}),
    )
    add_fieldsets = (
        (None, {
            "classes": ("wide",),
            "fields": ("email", "phone_number", "realm", "password1", "password2"),
        }),
    )


@admin.register(SystemUser)
class SystemUserAdmin(admin.ModelAdmin):
    list_display = ("system", "user", "organization", "country", "role", "status", "provisioning_email", "registered_at")
    list_filter = ("system", "status", "organization", "country", "all_branches")
    search_fields = ("provisioning_email", "user__email", "user__phone_number", "external_ref", "referral_code")
    autocomplete_fields = (
        "user",
        "system",
        "organization",
        "country",
        "role",
        "provisioned_by",
        "suspended_by",
    )
    filter_horizontal = ("branch_access",)
    readonly_fields = ("claim_token_lookup_id", "registered_at", "created_at", "updated_at")

    fieldsets = (
        ("Membership", {
            "fields": ("user", "system", "organization", "country", "role", "status")
        }),
        ("Access", {
            "fields": ("all_branches", "branch_access")
        }),
        ("Provisioning", {
            "fields": (
                "provisioned_by",
                "provisioning_email",
                "claim_token_lookup_id",
                "claim_token_hash",
                "claim_token_expires_at",
                "invited_at",
                "claimed_at",
            )
        }),
        ("Referrals", {
            "fields": ("referral_code",)
        }),
        ("Suspension", {
            "fields": ("suspended_reason", "suspended_at", "suspended_by")
        }),
        ("Metadata", {
            "fields": ("external_ref", "metadata", "registered_at", "last_login_at")
        }),
        ("Audit", {
            "fields": ("created_at", "updated_at")
        }),
    )


@admin.register(SocialAccount)
class SocialAccountAdmin(admin.ModelAdmin):
    list_display = ("provider", "uid", "user", "token_expires_at")
    list_filter = ("provider",)
    search_fields = ("uid", "user__email")
    autocomplete_fields = ("user",)
    readonly_fields = ("created_at", "updated_at")


@admin.register(ContactVerification)
class ContactVerificationAdmin(admin.ModelAdmin):
    list_display = ("contact_type", "value", "method", "purpose", "is_verified", "is_used", "expires_at", "user")
    list_filter = ("contact_type", "method", "purpose", "is_verified", "is_used")
    search_fields = ("value", "value_normalized", "user__email", "user__phone_number")
    autocomplete_fields = ("user",)
    readonly_fields = ("created_at", "updated_at")

    fieldsets = (
        ("Contact", {
            "fields": ("user", "contact_type", "value", "value_normalized", "method", "purpose")
        }),
        ("Challenge", {
            "fields": ("code_hash", "token_hash", "expires_at", "attempts")
        }),
        ("Lifecycle", {
            "fields": ("is_used", "used_at", "is_verified", "verified_at", "consumed_at")
        }),
        ("Request", {
            "fields": ("ip_requested", "ip_verified")
        }),
        ("Audit", {
            "fields": ("created_at", "updated_at")
        }),
    )


@admin.register(Referral)
class ReferralAdmin(admin.ModelAdmin):
    list_display = ("system", "referrer", "referred", "is_verified", "is_rewarded", "created_at")
    list_filter = ("system", "is_verified", "is_rewarded")
    search_fields = ("referral_code", "referrer__user__email", "referred__user__email")
    autocomplete_fields = ("referrer", "referred", "system")
    readonly_fields = ("created_at", "updated_at")
