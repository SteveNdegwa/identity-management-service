import hashlib
from datetime import date

from django.test import TestCase

from accounts.services.account_service import AccountService
from accounts.services.identifier_verification_service import IdentifierVerificationService
from base.models import Country, Realm
from organizations.models import Organization
from permissions.models import Role
from sso.models import SSOSession
from sso.services.sso_service import SSOService, AuthenticationError
from systems.models import System, SystemClient


class SocialLoginTests(TestCase):
    def setUp(self):
        self.realm = Realm.objects.create(name="SSO Realm")
        self.country = Country.objects.create(code="KE", code3="KEN", name="Kenya", phone_code="+254")
        self.system = System.objects.create(
            realm=self.realm,
            name="SSO System",
            slug="sso-system",
            registration_open=True,
            allow_social_login=True,
            allowed_social_providers=["google"],
        )
        self.system.available_countries.add(self.country)
        self.organization = Organization.objects.create(system=self.system, name="SSO Org", slug="sso-org")
        self.role = Role.objects.create(system=self.system, country=self.country, name="Member", slug="member")
        self.client = SystemClient.objects.create(
            system=self.system,
            name="Web",
            client_type=SystemClient.ClientType.PUBLIC,
            client_id="test-client-id",
            redirect_uris=["http://localhost:3000/callback"],
            override_allow_social_login=True,
            override_allowed_social_providers=["google"],
        )
        self.account_service = AccountService()
        self.verification_service = IdentifierVerificationService()
        self.sso_service = SSOService()

        email_verification = self.verification_service.initiate_registration_verification("email", "ada@example.com")
        phone_verification = self.verification_service.initiate_registration_verification("phone", "+254715013269")
        email_verification.code_hash = hashlib.sha256("123456".encode()).hexdigest()
        phone_verification.code_hash = hashlib.sha256("123456".encode()).hexdigest()
        email_verification.save(update_fields=["code_hash"])
        phone_verification.save(update_fields=["code_hash"])
        email_verification = self.verification_service.verify_registration_verification(str(email_verification.id), code="123456")
        phone_verification = self.verification_service.verify_registration_verification(str(phone_verification.id), code="123456")

        self.user, _ = self.account_service.self_registration_social(
            system=self.system,
            role=self.role,
            provider="google",
            uid="google-subject-1",
            first_name="Ada",
            last_name="Lovelace",
            date_of_birth=date(1990, 1, 1),
            gender="female",
            email="ada@example.com",
            phone_number="+254715013269",
            email_verification_id=str(email_verification.id),
            phone_verification_id=str(phone_verification.id),
            primary_country=self.country,
            organization=self.organization,
        )

    def test_authenticate_social_creates_social_session(self):
        session = self.sso_service.authenticate_social(
            client=self.client,
            provider="google",
            uid="google-subject-1",
            ip_address="127.0.0.1",
            user_agent="pytest",
            device_id="device-1",
            device_name="Chrome",
        )

        self.assertEqual(session.user, self.user)
        self.assertEqual(session.auth_method, SSOSession.AuthMethod.SOCIAL)
        self.assertEqual(session.initiating_system, self.system)

    def test_authenticate_social_rejects_provider_not_allowed_by_client(self):
        with self.assertRaises(AuthenticationError):
            self.sso_service.authenticate_social(
                client=self.client,
                provider="github",
                uid="github-subject-1",
            )
