from decimal import Decimal

from django.test import TestCase, override_settings

from base.models import Country, Realm
from organizations.models import OnboardingServiceProduct, OnboardingVerificationCheck
from systems.models import System, SystemSettings
from systems.services.system_admin_service import SystemAdminService


@override_settings(
    IDENTITY_PUBLIC_SCHEME='https',
    IDENTITY_PUBLIC_ROOT_DOMAIN='identity.example.com',
    IDENTITY_DEFAULT_REDIRECT_PATHS=['/auth/callback'],
    IDENTITY_DEFAULT_LOGOUT_PATHS=['/auth/logout'],
)
class SystemResellerProvisioningTests(TestCase):
    def setUp(self):
        self.realm = Realm.objects.create(name='Main Realm')
        self.country = Country.objects.create(code='KE', code3='KEN', name='Kenya')
        self.parent_system = System.objects.create(
            realm=self.realm,
            name='Radicrunch',
            slug='radicrunch',
            subdomain='radicrunch',
            logo_url='https://assets.example.com/radicrunch.png',
            favicon_url='https://assets.example.com/favicon.ico',
            primary_color='#102030',
            secondary_color='#405060',
            accent_colors=['#708090'],
            tagline='Main system',
            allow_passwordless_login=True,
            allow_magic_link_login=True,
            allow_social_login=True,
            allowed_social_providers=['google'],
            registration_open=True,
        )
        self.parent_system.available_countries.add(self.country)
        SystemSettings.objects.create(
            system=self.parent_system,
            key='payments.provider',
            value='stripe',
        )
        OnboardingServiceProduct.objects.create(
            system=self.parent_system,
            code='kyb',
            name='KYB',
            amount=Decimal('100.00'),
        )
        OnboardingVerificationCheck.objects.create(
            system=self.parent_system,
            code='business-registry',
            name='Business Registry',
            integration_code='registry',
        )

    def test_create_reseller_inherits_config_and_creates_default_client(self):
        reseller, client, raw_secret = SystemAdminService().create_reseller(
            parent_system=self.parent_system,
            name='Whitelisted Partner',
            subdomain='partner',
            tagline='Partner identity',
        )

        self.assertEqual(reseller.parent_system, self.parent_system)
        self.assertEqual(reseller.realm, self.parent_system.realm)
        self.assertTrue(reseller.allow_passwordless_login)
        self.assertTrue(reseller.allow_magic_link_login)
        self.assertEqual(reseller.allowed_social_providers, ['google'])
        self.assertEqual(reseller.tagline, 'Partner identity')
        self.assertEqual(reseller.logo_url, self.parent_system.logo_url)
        self.assertEqual(reseller.favicon_url, self.parent_system.favicon_url)
        self.assertEqual(list(reseller.available_countries.all()), [self.country])
        self.assertEqual(
            client.redirect_uris, ['https://partner.identity.example.com/auth/callback']
        )
        self.assertEqual(client.logout_uris, ['https://partner.identity.example.com/auth/logout'])
        self.assertEqual(client.allowed_scopes, ['openid', 'profile', 'email'])
        self.assertTrue(raw_secret)

    def test_create_reseller_clones_operational_configuration(self):
        reseller, _, _ = SystemAdminService().create_reseller(
            parent_system=self.parent_system,
            name='Config Partner',
            subdomain='config-partner',
        )

        self.assertTrue(reseller.settings.filter(key='payments.provider', value='stripe').exists())
        self.assertTrue(reseller.onboarding_service_products.filter(code='kyb').exists())
        self.assertTrue(
            reseller.onboarding_verification_checks.filter(code='business-registry').exists()
        )
