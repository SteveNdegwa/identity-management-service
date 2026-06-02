from django import forms
from django.contrib import admin, messages
from django.http import HttpResponseRedirect
from django.urls import reverse
from django.utils.html import format_html

from utils.social_providers import SocialProvider

from .models import System, SystemClient, SystemSettings, SystemWebhook
from .services.system_admin_service import SystemAdminService, SystemAdminServiceError


class SystemAdminForm(forms.ModelForm):
    allowed_social_providers = forms.MultipleChoiceField(
        choices=SocialProvider.choices,
        required=False,
        help_text='Supported providers are fixed for consistency.',
    )

    class Meta:
        model = System
        fields = (
            'realm',
            'name',
            'slug',
            'parent_system',
            'description',
            'logo_url',
            'favicon_url',
            'website',
            'subdomain',
            'primary_color',
            'secondary_color',
            'accent_colors',
            'tagline',
            'available_countries',
            'password_type',
            'allow_password_login',
            'allow_passwordless_login',
            'allow_magic_link_login',
            'allow_social_login',
            'passwordless_only',
            'allowed_social_providers',
            'registration_open',
            'auto_login_after_registration',
            'requires_approval',
            'allows_referrals',
            'referral_reward_amount',
            'auto_verify_referrals',
            'mfa_required',
            'mfa_required_enforced',
            'allowed_mfa_methods',
            'refresh_token_timeout_minutes',
            'mfa_reauth_window_minutes',
            'default_role',
            'is_active',
        )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['allowed_social_providers'].initial = (
            self.instance.allowed_social_providers or []
        )

    def clean_allowed_social_providers(self):
        return self.cleaned_data['allowed_social_providers']


class SystemClientInline(admin.TabularInline):
    model = SystemClient
    extra = 0
    show_change_link = True
    fields = (
        'name',
        'client_id',
        'client_type',
        'is_active',
    )
    readonly_fields = ('client_id',)


class SystemSettingsInline(admin.TabularInline):
    model = SystemSettings
    extra = 0
    show_change_link = True
    fields = (
        'key',
        'value_type',
        'is_secret',
    )


class SystemWebhookInline(admin.TabularInline):
    model = SystemWebhook
    extra = 0
    show_change_link = True
    fields = (
        'name',
        'endpoint_url',
        'is_active',
        'last_response_code',
        'consecutive_failures',
    )
    readonly_fields = (
        'last_response_code',
        'consecutive_failures',
    )


@admin.register(System)
class SystemAdmin(admin.ModelAdmin):
    form = SystemAdminForm
    list_display = (
        'name',
        'slug',
        'realm',
        'parent_system',
        'subdomain',
        'password_type',
        'is_active_colored',
        'registration_open',
        'allows_referrals',
        'mfa_required',
    )
    list_filter = (
        'is_active',
        'registration_open',
        'requires_approval',
        'allows_referrals',
        'auto_verify_referrals',
        'mfa_required',
        'mfa_required_enforced',
        'password_type',
        'parent_system',
    )
    search_fields = (
        'name',
        'slug',
        'description',
    )
    ordering = ('name',)
    filter_horizontal = ('available_countries',)
    inlines = (
        SystemClientInline,
        SystemSettingsInline,
        SystemWebhookInline,
    )

    readonly_fields = (
        'created_at',
        'updated_at',
    )

    fieldsets = (
        (
            'Core',
            {
                'fields': (
                    'realm',
                    'parent_system',
                    'name',
                    'slug',
                    'description',
                    'logo_url',
                    'favicon_url',
                    'website',
                    'subdomain',
                    'available_countries',
                    'default_role',
                    'is_active',
                )
            },
        ),
        (
            'Branding',
            {
                'fields': (
                    'primary_color',
                    'secondary_color',
                    'accent_colors',
                    'tagline',
                )
            },
        ),
        (
            'Authentication',
            {
                'fields': (
                    'password_type',
                    'allow_password_login',
                    'allow_passwordless_login',
                    'allow_magic_link_login',
                    'allow_social_login',
                    'allowed_social_providers',
                    'passwordless_only',
                )
            },
        ),
        (
            'MFA',
            {
                'fields': (
                    'mfa_required',
                    'mfa_required_enforced',
                    'allowed_mfa_methods',
                    'mfa_reauth_window_minutes',
                )
            },
        ),
        ('Token Refresh', {'fields': ('refresh_token_timeout_minutes',)}),
        (
            'Rules',
            {
                'fields': (
                    'registration_open',
                    'auto_login_after_registration',
                    'requires_approval',
                    'allows_referrals',
                    'referral_reward_amount',
                    'auto_verify_referrals',
                )
            },
        ),
        (
            'Audit',
            {
                'fields': (
                    'created_at',
                    'updated_at',
                )
            },
        ),
    )

    def get_queryset(self, request):
        qs = super().get_queryset(request)
        return qs.select_related('realm').prefetch_related(
            'clients',
            'settings',
            'webhooks',
            'available_countries',
        )

    def is_active_colored(self, obj):
        color = 'green' if obj.is_active else 'red'
        text = 'Active' if obj.is_active else 'Inactive'

        return format_html(
            '<span style="color:{};font-weight:600">{}</span>',
            color,
            text,
        )

    is_active_colored.short_description = 'Status'


@admin.register(SystemClient)
class SystemClientAdmin(admin.ModelAdmin):
    change_form_template = 'admin/systems/systemclient/change_form.html'

    list_display = (
        'name',
        'system',
        'client_id_short',
        'client_type',
        'is_active',
    )
    list_filter = (
        'client_type',
        'is_active',
        'system',
    )
    search_fields = (
        'name',
        'client_id',
    )
    ordering = ('system', 'name')

    readonly_fields = (
        'client_id',
        'client_secret_hash',
        'created_at',
        'updated_at',
    )

    fieldsets = (
        (
            'Core',
            {
                'fields': (
                    'system',
                    'name',
                    'client_id',
                    'client_type',
                    'is_active',
                )
            },
        ),
        ('Security', {'fields': ('client_secret_hash',)}),
        (
            'OAuth',
            {
                'fields': (
                    'redirect_uris',
                    'logout_uris',
                    'allowed_scopes',
                )
            },
        ),
        (
            'Token TTL',
            {
                'fields': (
                    'access_token_ttl',
                    'refresh_token_ttl',
                    'id_token_ttl',
                )
            },
        ),
        (
            'Overrides',
            {
                'fields': (
                    'override_allow_passwordless_login',
                    'override_allow_magic_link_login',
                    'override_allow_social_login',
                    'override_allowed_social_providers',
                )
            },
        ),
        (
            'Audit',
            {
                'fields': (
                    'created_at',
                    'updated_at',
                )
            },
        ),
    )

    def save_model(self, request, obj, form, change):
        if not change and obj.client_type != SystemClient.ClientType.PUBLIC:
            raw_secret = SystemAdminService.generate_client_secret()
            obj.client_secret_hash = SystemAdminService.hash_client_secret(raw_secret)
            request._raw_client_secret = raw_secret
        super().save_model(request, obj, form, change)

    def response_add(self, request, obj, post_url_continue=None):
        raw_secret = getattr(request, '_raw_client_secret', '')
        if raw_secret:
            self._stash_raw_client_secret(request, obj, raw_secret)
            return HttpResponseRedirect(self._change_url(obj))
        return super().response_add(request, obj, post_url_continue)

    def response_change(self, request, obj):
        if '_regenerate_client_secret' in request.POST:
            try:
                _, raw_secret = SystemAdminService().regenerate_client_secret(client=obj)
            except SystemAdminServiceError as exc:
                self.message_user(request, str(exc), level=messages.ERROR)
            else:
                self._stash_raw_client_secret(request, obj, raw_secret)
            return HttpResponseRedirect('.')
        return super().response_change(request, obj)

    def change_view(self, request, object_id, form_url='', extra_context=None):
        extra_context = extra_context or {}
        raw_secret_key = self._raw_secret_session_key(object_id)
        raw_secret = request.session.pop(raw_secret_key, '')
        if raw_secret:
            request.session.modified = True
            extra_context['raw_client_secret'] = raw_secret
        return super().change_view(request, object_id, form_url, extra_context)

    def _change_url(self, obj):
        return reverse('admin:systems_systemclient_change', args=[obj.pk])

    def _stash_raw_client_secret(self, request, obj, raw_secret: str) -> None:
        request.session[self._raw_secret_session_key(obj.pk)] = raw_secret

    @staticmethod
    def _raw_secret_session_key(client_id) -> str:
        return f'systems.raw_client_secret.{client_id}'

    def get_queryset(self, request):
        return super().get_queryset(request).select_related('system')

    def client_id_short(self, obj):
        return obj.client_id[:10]

    client_id_short.short_description = 'Client ID'


@admin.register(SystemSettings)
class SystemSettingsAdmin(admin.ModelAdmin):
    list_display = (
        'system',
        'key',
        'value_type',
        'is_secret',
    )
    list_filter = (
        'system',
        'value_type',
        'is_secret',
    )
    search_fields = (
        'key',
        'value',
    )
    ordering = ('system', 'key')

    readonly_fields = (
        'created_at',
        'updated_at',
    )

    fieldsets = (
        (
            'Core',
            {
                'fields': (
                    'system',
                    'key',
                    'value',
                    'value_type',
                )
            },
        ),
        (
            'Meta',
            {
                'fields': (
                    'description',
                    'is_secret',
                )
            },
        ),
        (
            'Audit',
            {
                'fields': (
                    'created_at',
                    'updated_at',
                )
            },
        ),
    )

    def get_queryset(self, request):
        return super().get_queryset(request).select_related('system')


@admin.register(SystemWebhook)
class SystemWebhookAdmin(admin.ModelAdmin):
    list_display = (
        'name',
        'system',
        'endpoint_url',
        'is_active',
        'last_response_code',
        'consecutive_failures',
    )
    list_filter = (
        'system',
        'is_active',
    )
    search_fields = (
        'name',
        'endpoint_url',
    )
    ordering = ('system', 'name')

    readonly_fields = (
        'last_triggered_at',
        'last_response_code',
        'consecutive_failures',
        'created_at',
        'updated_at',
    )

    fieldsets = (
        (
            'Core',
            {
                'fields': (
                    'system',
                    'name',
                    'endpoint_url',
                    'is_active',
                )
            },
        ),
        ('Security', {'fields': ('secret_encrypted',)}),
        ('Events', {'fields': ('event_types',)}),
        (
            'Health',
            {
                'fields': (
                    'last_triggered_at',
                    'last_response_code',
                    'consecutive_failures',
                )
            },
        ),
        (
            'Audit',
            {
                'fields': (
                    'created_at',
                    'updated_at',
                )
            },
        ),
    )

    def get_queryset(self, request):
        return super().get_queryset(request).select_related('system')
