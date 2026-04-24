from django import forms
from django.contrib import admin, messages
from django.contrib.admin.options import IS_POPUP_VAR
from django.contrib.admin.utils import unquote
from django.contrib.auth.forms import ReadOnlyPasswordHashField
from django.contrib.auth.hashers import UNUSABLE_PASSWORD_PREFIX
from django.core.exceptions import PermissionDenied
from django.db.models import Prefetch
from django.http import Http404, HttpResponseRedirect
from django.template.response import TemplateResponse
from django.urls import path, reverse
from django.utils.html import format_html
from django.utils.translation import gettext_lazy as _

from .models import (
    User,
    UserIdentifier,
    SystemUser,
    SocialAccount,
    SystemUserStatus,
)


class ReadOnlySecretHashWidget(forms.Widget):
    def __init__(self, button_label, *args, **kwargs):
        self.button_label = button_label
        super().__init__(*args, **kwargs)

    def render(self, name, value, attrs=None, renderer=None):
        has_value = bool(value) and not str(value).startswith(UNUSABLE_PASSWORD_PREFIX)
        summary = _("Configured") if has_value else _("Not set")
        return format_html(
            "<div>{}</div><div style=\"margin-top:4px;color:#666;\">{}</div>",
            summary,
            self.button_label,
        )

    def id_for_label(self, id_):
        return None


class ReadOnlySecretHashField(forms.Field):
    def __init__(self, *, label, button_label, **kwargs):
        kwargs.setdefault("required", False)
        kwargs.setdefault("disabled", True)
        super().__init__(
            label=label,
            widget=ReadOnlySecretHashWidget(button_label=button_label),
            **kwargs,
        )


class UserCreationAdminForm(forms.ModelForm):
    password1 = forms.CharField(
        label=_("Password"),
        strip=False,
        widget=forms.PasswordInput(attrs={"autocomplete": "new-password"}),
    )
    password2 = forms.CharField(
        label=_("Password confirmation"),
        strip=False,
        widget=forms.PasswordInput(attrs={"autocomplete": "new-password"}),
        help_text=_("Enter the same password as before, for verification."),
    )
    pin1 = forms.CharField(
        label=_("PIN"),
        required=False,
        strip=False,
        widget=forms.PasswordInput(attrs={"autocomplete": "off"}),
    )
    pin2 = forms.CharField(
        label=_("PIN confirmation"),
        required=False,
        strip=False,
        widget=forms.PasswordInput(attrs={"autocomplete": "off"}),
        help_text=_("Enter the same PIN as before, for verification."),
    )

    class Meta:
        model = User
        fields = ("realm", "primary_country", "is_active")

    def clean(self):
        cleaned_data = super().clean()
        password1 = cleaned_data.get("password1")
        password2 = cleaned_data.get("password2")
        if password1 and password2 and password1 != password2:
            self.add_error("password2", _("The two password fields didn't match."))
        pin1 = cleaned_data.get("pin1")
        pin2 = cleaned_data.get("pin2")
        if pin1 or pin2:
            if not pin1:
                self.add_error("pin1", _("This field is required when setting a PIN."))
            if not pin2:
                self.add_error("pin2", _("This field is required when setting a PIN."))
            if pin1 and pin2 and pin1 != pin2:
                self.add_error("pin2", _("The two PIN fields didn't match."))
        return cleaned_data

    def save(self, commit=True):
        user = super().save(commit=False)
        user.set_password(self.cleaned_data["password1"])
        if self.cleaned_data.get("pin1"):
            user.set_pin(self.cleaned_data["pin1"])
        if commit:
            user.save()
            self.save_m2m()
        return user


class UserChangeAdminForm(forms.ModelForm):
    password = ReadOnlyPasswordHashField(label=_("Password"), required=False)
    pin = ReadOnlySecretHashField(
        label=_("PIN"),
        button_label=_("Change PIN using the linked form."),
    )

    class Meta:
        model = User
        fields = "__all__"

    def clean_password(self):
        return self.initial.get("password")

    def clean_pin(self):
        return self.initial.get("pin")


class UserAdminPasswordChangeForm(forms.Form):
    password1 = forms.CharField(
        label=_("New password"),
        strip=False,
        widget=forms.PasswordInput(attrs={"autocomplete": "new-password"}),
    )
    password2 = forms.CharField(
        label=_("New password confirmation"),
        strip=False,
        widget=forms.PasswordInput(attrs={"autocomplete": "new-password"}),
    )

    def __init__(self, user, *args, **kwargs):
        self.user = user
        super().__init__(*args, **kwargs)

    def clean(self):
        cleaned_data = super().clean()
        password1 = cleaned_data.get("password1")
        password2 = cleaned_data.get("password2")
        if password1 and password2 and password1 != password2:
            self.add_error("password2", _("The two password fields didn't match."))
        return cleaned_data

    def save(self, commit=True):
        self.user.set_password(self.cleaned_data["password1"])
        if commit:
            self.user.save(update_fields=["password"])
        return self.user


class UserAdminPinChangeForm(forms.Form):
    pin1 = forms.CharField(
        label=_("New PIN"),
        strip=False,
        widget=forms.PasswordInput(attrs={"autocomplete": "off"}),
    )
    pin2 = forms.CharField(
        label=_("New PIN confirmation"),
        strip=False,
        widget=forms.PasswordInput(attrs={"autocomplete": "off"}),
    )

    def __init__(self, user, *args, **kwargs):
        self.user = user
        super().__init__(*args, **kwargs)

    def clean(self):
        cleaned_data = super().clean()
        pin1 = cleaned_data.get("pin1")
        pin2 = cleaned_data.get("pin2")
        if pin1 and pin2 and pin1 != pin2:
            self.add_error("pin2", _("The two PIN fields didn't match."))
        return cleaned_data

    def save(self, commit=True):
        self.user.set_pin(self.cleaned_data["pin1"])
        if commit:
            self.user.save(update_fields=["pin"])
        return self.user


class UserIdentifierInline(admin.TabularInline):
    model = UserIdentifier
    fk_name = "user"
    extra = 0

    autocomplete_fields = ["added_by_system", "disassociated_by"]

    readonly_fields = (
        "value_normalised",
        "verified_at",
        "is_active_display",
        "created_at",
        "updated_at",
    )

    fields = (
        "identifier_type",
        "value",
        "value_normalised",
        "is_primary",
        "is_verified",
        "verified_at",
        "disassociated_at",
        "disassociation_reason",
        "added_by_system",
        "is_active_display",
    )

    def is_active_display(self, obj):
        return obj.disassociated_at is None

    is_active_display.short_description = "Active"

    def has_add_permission(self, request, obj=None):
        return False


class SystemUserInline(admin.TabularInline):
    model = SystemUser
    extra = 0
    fk_name = "user"

    autocomplete_fields = [
        "system",
        "organization",
        "country",
        "role",
        "provisioned_by",
        "suspended_by",
    ]

    readonly_fields = (
        "registered_at",
        "last_login_at",
        "status_badge",
    )

    fields = (
        "system",
        "organization",
        "country",
        "role",
        "status",
        "status_badge",
        "all_branches",
        "registered_at",
        "last_login_at",
    )

    def status_badge(self, obj):
        color_map = {
            SystemUserStatus.ACTIVE: "green",
            SystemUserStatus.PENDING: "orange",
            SystemUserStatus.INVITED: "blue",
            SystemUserStatus.SUSPENDED: "red",
            SystemUserStatus.REMOVED: "gray",
        }

        color = color_map.get(obj.status, "black")

        return format_html(
            '<b style="color:{}">{}</b>',
            color,
            obj.get_status_display(),
        )

    status_badge.short_description = "Status"

    def has_add_permission(self, request, obj=None):
        return False


class SocialAccountInline(admin.TabularInline):
    model = SocialAccount
    extra = 0
    readonly_fields = ("created_at", "updated_at")

    fields = (
        "provider",
        "uid",
        "access_token",
        "refresh_token",
        "token_expires_at",
        "created_at",
    )


@admin.register(User)
class UserAdmin(admin.ModelAdmin):
    form = UserChangeAdminForm
    add_form = UserCreationAdminForm
    change_password_form = UserAdminPasswordChangeForm
    change_pin_form = UserAdminPinChangeForm

    list_display = (
        "id",
        "realm",
        "primary_country",
        "email_display",
        "phone_display",
        "is_active",
        "is_locked_display",
        "created_at",
    )

    list_filter = (
        "is_active",
        "realm",
        "primary_country",
        "created_at",
    )

    search_fields = (
        "identifiers__value",
        "identifiers__value_normalised",
        "id",
    )

    inlines = (
        UserIdentifierInline,
        SystemUserInline,
        SocialAccountInline,
    )

    readonly_fields = (
        "id",
        "created_at",
        "updated_at",
        "last_login",
        "failed_login_attempts",
        "locked_until",
        "is_locked_display",
    )

    raw_id_fields = ("realm", "primary_country")
    list_select_related = ("realm", "primary_country")

    fieldsets = (
        ("Identity", {
            "fields": (
                "id",
                "realm",
                "primary_country",
            )
        }),
        ("Credentials", {
            "fields": ("password", "pin")
        }),
        ("Status", {
            "fields": (
                "is_active",
                "last_login",
                "failed_login_attempts",
                "locked_until",
                "is_locked_display",
            )
        }),
        ("Audit", {
            "fields": (
                "created_at",
                "updated_at",
            )
        }),
    )

    add_fieldsets = (
        ("Identity", {
            "fields": (
                "realm",
                "primary_country",
            )
        }),
        ("Credentials", {
            "fields": (
                "password1",
                "password2",
                "pin1",
                "pin2",
            )
        }),
        ("Status", {
            "fields": ("is_active",)
        }),
    )

    def get_fieldsets(self, request, obj=None):
        if obj is None:
            return self.add_fieldsets
        return super().get_fieldsets(request, obj)

    def get_form(self, request, obj=None, **kwargs):
        defaults = {"form": self.add_form if obj is None else self.form}
        defaults.update(kwargs)
        form = super().get_form(request, obj, **defaults)
        if obj is not None and "password" in form.base_fields:
            password_url = reverse(
                f"{self.admin_site.name}:{obj._meta.app_label}_{obj._meta.model_name}_password_change",
                args=[obj.pk],
            )
            form.base_fields["password"].help_text = format_html(
                'Raw passwords are not stored. You can change the password using <a href="{}">this form</a>.',
                password_url,
            )
        if obj is not None and "pin" in form.base_fields:
            pin_url = reverse(
                f"{self.admin_site.name}:{obj._meta.app_label}_{obj._meta.model_name}_pin_change",
                args=[obj.pk],
            )
            form.base_fields["pin"].help_text = format_html(
                'Raw PINs are not stored. You can change the PIN using <a href="{}">this form</a>.',
                pin_url,
            )
        return form

    def get_urls(self):
        return [
            path(
                "<id>/password/",
                self.admin_site.admin_view(self.user_change_password),
                name="accounts_user_password_change",
            ),
            path(
                "<id>/pin/",
                self.admin_site.admin_view(self.user_change_pin),
                name="accounts_user_pin_change",
            ),
            *super().get_urls(),
        ]

    def get_queryset(self, request):
        return super().get_queryset(request).select_related(
            "realm",
            "primary_country",
        ).prefetch_related(
            Prefetch(
                "identifiers",
                queryset=UserIdentifier.all_objects.all()
            )
        )

    def email_display(self, obj):
        return obj.get_email()

    email_display.short_description = "Email"

    def phone_display(self, obj):
        return obj.get_phone()

    phone_display.short_description = "Phone"

    def is_locked_display(self, obj):
        return obj.is_locked()

    is_locked_display.boolean = True
    is_locked_display.short_description = "Locked"

    def user_change_password(self, request, id, form_url=""):
        return self._change_secret(
            request=request,
            id=id,
            form_url=form_url,
            form_class=self.change_password_form,
            success_message=_("Password changed successfully."),
            title_template=_("Change password: %s"),
        )

    def user_change_pin(self, request, id, form_url=""):
        return self._change_secret(
            request=request,
            id=id,
            form_url=form_url,
            form_class=self.change_pin_form,
            success_message=_("PIN changed successfully."),
            title_template=_("Change PIN: %s"),
        )

    def _change_secret(self, request, id, form_url, form_class, success_message, title_template):
        user = self.get_object(request, unquote(id))
        if not self.has_change_permission(request, user):
            raise PermissionDenied
        if user is None:
            raise Http404(
                _("%(name)s object with primary key %(key)r does not exist.")
                % {
                    "name": self.opts.verbose_name,
                    "key": id,
                }
            )

        if request.method == "POST":
            form = form_class(user, request.POST)
            if form.is_valid():
                user = form.save()
                change_message = self.construct_change_message(request, form, None)
                self.log_change(request, user, change_message)
                messages.success(request, success_message)
                return HttpResponseRedirect(
                    reverse(
                        f"{self.admin_site.name}:{user._meta.app_label}_{user._meta.model_name}_change",
                        args=(user.pk,),
                    )
                )
        else:
            form = form_class(user)

        fieldsets = ((None, {"fields": list(form.base_fields)}),)
        admin_form = admin.helpers.AdminForm(form, fieldsets, {})
        context = {
            "title": title_template % user,
            "adminForm": admin_form,
            "form_url": form_url,
            "form": form,
            "is_popup": (IS_POPUP_VAR in request.POST or IS_POPUP_VAR in request.GET),
            "is_popup_var": IS_POPUP_VAR,
            "add": False,
            "change": True,
            "has_delete_permission": False,
            "has_change_permission": True,
            "has_absolute_url": False,
            "opts": self.opts,
            "original": user,
            "save_as": False,
            "show_save": True,
            **self.admin_site.each_context(request),
        }
        request.current_app = self.admin_site.name
        return TemplateResponse(
            request,
            "admin/auth/user/change_password.html",
            context,
        )


@admin.register(UserIdentifier)
class UserIdentifierAdmin(admin.ModelAdmin):
    list_display = (
        "id",
        "user",
        "realm",
        "identifier_type",
        "value",
        "is_primary",
        "is_verified",
        "status_display",
        "created_at",
    )

    list_filter = (
        "identifier_type",
        "is_primary",
        "is_verified",
        "realm",
    )

    search_fields = (
        "value",
        "value_normalised",
        "user__id",
    )

    raw_id_fields = (
        "user",
        "realm",
        "added_by_system",
        "disassociated_by",
    )

    list_select_related = (
        "user",
        "realm",
    )

    readonly_fields = (
        "value_normalised",
        "created_at",
        "updated_at",
    )

    fieldsets = (
        ("Identifier", {
            "fields": (
                "user",
                "realm",
                "identifier_type",
                "value",
                "value_normalised",
            )
        }),
        ("Verification", {
            "fields": (
                "is_primary",
                "is_verified",
                "verified_at",
            )
        }),
        ("Lifecycle", {
            "fields": (
                "disassociated_at",
                "disassociation_reason",
                "added_by_system",
            )
        }),
        ("Audit", {
            "fields": (
                "created_at",
                "updated_at",
            )
        }),
    )

    def get_queryset(self, request):
        return super().get_queryset(request).select_related("user", "realm")

    def status_display(self, obj):
        if obj.disassociated_at:
            return format_html('<span style="color:red">DISASSOCIATED</span>')
        return format_html('<span style="color:green">ACTIVE</span>')


@admin.register(SystemUser)
class SystemUserAdmin(admin.ModelAdmin):
    list_display = (
        "id",
        "user",
        "system",
        "organization",
        "country",
        "role",
        "status_badge",
        "created_at",
    )

    list_filter = (
        "status",
        "system",
        "organization",
        "country",
        "role",
    )

    search_fields = (
        "first_name",
        "last_name",
        "display_name",
        "provisioning_email",
        "external_ref",
    )

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

    readonly_fields = (
        "id",
        "registered_at",
        "last_login_at",
        "claim_token_hash",
        "claim_token_lookup_id",
        "created_at",
        "updated_at",
        "status_badge",
    )

    list_select_related = (
        "user",
        "system",
        "organization",
        "country",
        "role",
    )

    fieldsets = (
        ("Identity", {
            "fields": (
                "user",
                "system",
                "organization",
                "country",
                "role",
            )
        }),
        ("Status", {
            "fields": (
                "status",
                "registered_at",
                "last_login_at",
            )
        }),
        ("Security", {
            "fields": (
                "claim_token_hash",
                "claim_token_lookup_id",
            )
        }),
        ("Audit", {
            "fields": (
                "created_at",
                "updated_at",
            )
        }),
    )

    def get_queryset(self, request):
        return super().get_queryset(request).select_related(
            "user",
            "system",
            "organization",
            "country",
            "role",
        )

    def status_badge(self, obj):
        color_map = {
            SystemUserStatus.ACTIVE: "green",
            SystemUserStatus.PENDING: "orange",
            SystemUserStatus.INVITED: "blue",
            SystemUserStatus.SUSPENDED: "red",
            SystemUserStatus.REMOVED: "gray",
        }

        color = color_map.get(obj.status, "black")

        return format_html(
            '<span style="padding:2px 6px;border-radius:4px;background:{};color:white;">{}</span>',
            color,
            obj.get_status_display(),
        )

    status_badge.short_description = "Status"


@admin.register(SocialAccount)
class SocialAccountAdmin(admin.ModelAdmin):
    list_display = (
        "id",
        "user",
        "provider",
        "uid",
        "token_status",
        "created_at",
    )

    list_filter = ("provider",)

    search_fields = ("uid", "user__id")

    raw_id_fields = ("user",)

    list_select_related = ("user",)

    readonly_fields = ("created_at", "updated_at")

    fieldsets = (
        ("Account", {
            "fields": (
                "user",
                "provider",
                "uid",
            )
        }),
        ("Tokens", {
            "fields": (
                "access_token",
                "refresh_token",
                "token_expires_at",
            )
        }),
        ("Audit", {
            "fields": (
                "created_at",
                "updated_at",
            )
        }),
    )

    def get_queryset(self, request):
        return super().get_queryset(request).select_related("user")

    def token_status(self, obj):
        if obj.token_expires_at and obj.token_expires_at < obj.updated_at:
            return format_html('<span style="color:red">Expired</span>')
        return format_html('<span style="color:green">Active</span>')

    token_status.short_description = "Token"
