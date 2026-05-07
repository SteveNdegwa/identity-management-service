import hashlib
from datetime import date

from django.test import TestCase

from accounts.models import SocialAccount, SystemUser, User
from accounts.services.account_service import (
    AccountService,
    ClaimLinkConfirmationRequired,
    SelfRegistrationError,
)
from accounts.services.identifier_verification_service import IdentifierVerificationService
from base.models import Country, Realm
from organizations.models import Organization
from permissions.models import Role
from systems.models import System


class AccountFlowTests(TestCase):
    def setUp(self):
        self.realm = Realm.objects.create(name="Test Realm")
        self.country = Country.objects.create(code="KE", code3="KEN", name="Kenya", phone_code="+254")
        self.system = System.objects.create(
            realm=self.realm,
            name="Test System",
            slug="test-system",
            registration_open=True,
            allow_social_login=True,
            allowed_social_providers=["google"],
        )
        self.system.available_countries.add(self.country)
        self.organization = Organization.objects.create(system=self.system, name="Test Org", slug="test-org")
        self.role = Role.objects.create(system=self.system, country=self.country, name="Member", slug="member")
        self.account_service = AccountService()
        self.verification_service = IdentifierVerificationService()

    def test_direct_registration_requires_verified_email_and_phone(self):
        email_verification = self.verification_service.initiate_registration_verification("email", "ada@example.com")
        phone_verification = self.verification_service.initiate_registration_verification("phone", "+254715013269")

        email_verification.code_hash = hashlib.sha256("123456".encode()).hexdigest()
        email_verification.save(update_fields=["code_hash"])
        phone_verification.code_hash = hashlib.sha256("123456".encode()).hexdigest()
        phone_verification.save(update_fields=["code_hash"])

        email_verification = self.verification_service.verify_registration_verification(
            verification_id=str(email_verification.id),
            code="123456",
        )
        phone_verification = self.verification_service.verify_registration_verification(
            verification_id=str(phone_verification.id),
            code="123456",
        )

        user, system_user = self.account_service.self_registration(
            system=self.system,
            role=self.role,
            first_name="Ada",
            last_name="Lovelace",
            date_of_birth=date(1990, 1, 1),
            gender="female",
            email="ada@example.com",
            phone_number="+254715013269",
            password="Secret123!",
            email_verification_id=str(email_verification.id),
            phone_verification_id=str(phone_verification.id),
            primary_country=self.country,
        )

        self.assertTrue(user.email_verified)
        self.assertTrue(user.phone_verified)
        self.assertEqual(system_user.user, user)

    def test_social_registration_requires_phone(self):
        email_verification = self.verification_service.initiate_registration_verification("email", "ada@example.com")
        email_verification.code_hash = hashlib.sha256("123456".encode()).hexdigest()
        email_verification.save(update_fields=["code_hash"])
        email_verification = self.verification_service.verify_registration_verification(
            verification_id=str(email_verification.id),
            code="123456",
        )

        with self.assertRaises(SelfRegistrationError):
            self.account_service.self_registration_social(
                system=self.system,
                role=self.role,
                provider="google",
                uid="google-subject-1",
                first_name="Ada",
                last_name="Lovelace",
                date_of_birth=date(1990, 1, 1),
                gender="female",
                email="ada@example.com",
                email_verification_id=str(email_verification.id),
                primary_country=self.country,
            )

    def test_social_registration_creates_social_account(self):
        email_verification = self.verification_service.initiate_registration_verification("email", "ada@example.com")
        phone_verification = self.verification_service.initiate_registration_verification("phone", "+254715013269")
        email_verification.code_hash = hashlib.sha256("123456".encode()).hexdigest()
        phone_verification.code_hash = hashlib.sha256("123456".encode()).hexdigest()
        email_verification.save(update_fields=["code_hash"])
        phone_verification.save(update_fields=["code_hash"])
        email_verification = self.verification_service.verify_registration_verification(str(email_verification.id), code="123456")
        phone_verification = self.verification_service.verify_registration_verification(str(phone_verification.id), code="123456")

        user, _ = self.account_service.self_registration_social(
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
        )

        self.assertTrue(SocialAccount.objects.filter(user=user, provider="google", uid="google-subject-1").exists())

    def test_claim_new_marks_invited_email_verified_without_email_verification(self):
        inviter = User.objects.create_user(
            realm=self.realm,
            email="inviter@example.com",
            phone_number="+254700000001",
            password="Secret123!",
        )
        inviter_system_user = SystemUser.objects.create(
            user=inviter,
            system=self.system,
            organization=self.organization,
            country=self.country,
            role=self.role,
            status="active",
            provisioning_email=inviter.email,
        )

        invited_system_user = SystemUser.objects.create(
            system=self.system,
            organization=self.organization,
            country=self.country,
            role=self.role,
            provisioned_by=inviter_system_user,
            provisioning_email="invitee@example.com",
            status="pending",
        )
        lookup_id, token = self.account_service.invite(
            system_user=invited_system_user,
            invited_by=inviter_system_user,
        )

        phone_verification = self.verification_service.initiate_registration_verification("phone", "+254715013270")
        phone_verification.code_hash = hashlib.sha256("123456".encode()).hexdigest()
        phone_verification.save(update_fields=["code_hash"])
        phone_verification = self.verification_service.verify_registration_verification(
            verification_id=str(phone_verification.id),
            code="123456",
        )

        claimed_system_user = self.account_service.claim_user(
            lookup_id=lookup_id,
            token=token,
            claim_action="new",
            password="Secret123!",
            phone_number="+254715013270",
            first_name="Grace",
            last_name="Hopper",
            date_of_birth=date(1990, 1, 1),
            gender="female",
            country=self.country,
            phone_verification_id=str(phone_verification.id),
        )

        claimed_system_user.refresh_from_db()
        claimed_user = claimed_system_user.user
        self.assertTrue(claimed_user.email_verified)
        self.assertIsNotNone(claimed_user.email_verified_at)
        self.assertTrue(claimed_user.phone_verified)

    def test_claim_link_marks_existing_email_verified(self):
        inviter = User.objects.create_user(
            realm=self.realm,
            email="inviter@example.com",
            phone_number="+254700000001",
            password="Secret123!",
        )
        inviter_system_user = SystemUser.objects.create(
            user=inviter,
            system=self.system,
            organization=self.organization,
            country=self.country,
            role=self.role,
            status="active",
            provisioning_email=inviter.email,
        )
        existing_user = User.objects.create_user(
            realm=self.realm,
            email="invitee@example.com",
            phone_number="+254715013271",
            password="Secret123!",
        )

        invited_system_user = SystemUser.objects.create(
            system=self.system,
            organization=self.organization,
            country=self.country,
            role=self.role,
            provisioned_by=inviter_system_user,
            provisioning_email=existing_user.email,
            status="pending",
        )
        lookup_id, token = self.account_service.invite(
            system_user=invited_system_user,
            invited_by=inviter_system_user,
        )

        claimed_system_user = self.account_service.claim_user(
            lookup_id=lookup_id,
            token=token,
            claim_action="link",
        )

        existing_user.refresh_from_db()
        self.assertEqual(claimed_system_user.user, existing_user)
        self.assertTrue(existing_user.email_verified)
        self.assertIsNotNone(existing_user.email_verified_at)

    def test_claim_new_links_existing_phone_without_updating_email(self):
        inviter = User.objects.create_user(
            realm=self.realm,
            email="inviter@example.com",
            phone_number="+254700000001",
            password="Secret123!",
        )
        inviter_system_user = SystemUser.objects.create(
            user=inviter,
            system=self.system,
            organization=self.organization,
            country=self.country,
            role=self.role,
            status="active",
            provisioning_email=inviter.email,
        )
        existing_user = User.objects.create_user(
            realm=self.realm,
            email="old-org@example.com",
            phone_number="+254715013272",
            password="Secret123!",
        )
        invited_system_user = SystemUser.objects.create(
            system=self.system,
            organization=self.organization,
            country=self.country,
            role=self.role,
            provisioned_by=inviter_system_user,
            provisioning_email="new-org@example.com",
            status="pending",
        )
        lookup_id, token = self.account_service.invite(
            system_user=invited_system_user,
            invited_by=inviter_system_user,
        )

        phone_verification = self.verification_service.initiate_registration_verification("phone", "+254715013272")
        phone_verification.code_hash = hashlib.sha256("123456".encode()).hexdigest()
        phone_verification.save(update_fields=["code_hash"])
        phone_verification = self.verification_service.verify_registration_verification(
            verification_id=str(phone_verification.id),
            code="123456",
        )

        with self.assertRaises(ClaimLinkConfirmationRequired):
            self.account_service.claim_user(
                lookup_id=lookup_id,
                token=token,
                claim_action="new",
                phone_number="+254715013272",
                first_name="Grace",
                last_name="Hopper",
                date_of_birth=date(1990, 1, 1),
                gender="female",
                country=self.country,
                phone_verification_id=str(phone_verification.id),
            )

        claimed_system_user = self.account_service.claim_user(
            lookup_id=lookup_id,
            token=token,
            claim_action="new",
            phone_number="+254715013272",
            first_name="Grace",
            last_name="Hopper",
            date_of_birth=date(1990, 1, 1),
            gender="female",
            country=self.country,
            phone_verification_id=str(phone_verification.id),
            confirm_link_existing_user=True,
        )

        existing_user.refresh_from_db()
        self.assertEqual(claimed_system_user.user, existing_user)
        self.assertEqual(existing_user.email, "old-org@example.com")
        self.assertTrue(existing_user.phone_verified)
        self.assertFalse(User.objects.filter(email="new-org@example.com").exists())

    def test_claim_new_links_existing_phone_and_updates_email_when_requested(self):
        inviter = User.objects.create_user(
            realm=self.realm,
            email="inviter@example.com",
            phone_number="+254700000001",
            password="Secret123!",
        )
        inviter_system_user = SystemUser.objects.create(
            user=inviter,
            system=self.system,
            organization=self.organization,
            country=self.country,
            role=self.role,
            status="active",
            provisioning_email=inviter.email,
        )
        existing_user = User.objects.create_user(
            realm=self.realm,
            email="old-org@example.com",
            phone_number="+254715013273",
            password="Secret123!",
        )
        invited_system_user = SystemUser.objects.create(
            system=self.system,
            organization=self.organization,
            country=self.country,
            role=self.role,
            provisioned_by=inviter_system_user,
            provisioning_email="new-org@example.com",
            status="pending",
        )
        lookup_id, token = self.account_service.invite(
            system_user=invited_system_user,
            invited_by=inviter_system_user,
        )

        phone_verification = self.verification_service.initiate_registration_verification("phone", "+254715013273")
        phone_verification.code_hash = hashlib.sha256("123456".encode()).hexdigest()
        phone_verification.save(update_fields=["code_hash"])
        phone_verification = self.verification_service.verify_registration_verification(
            verification_id=str(phone_verification.id),
            code="123456",
        )

        claimed_system_user = self.account_service.claim_user(
            lookup_id=lookup_id,
            token=token,
            claim_action="new",
            phone_number="+254715013273",
            first_name="Grace",
            last_name="Hopper",
            date_of_birth=date(1990, 1, 1),
            gender="female",
            country=self.country,
            phone_verification_id=str(phone_verification.id),
            confirm_link_existing_user=True,
            update_email=True,
        )

        existing_user.refresh_from_db()
        self.assertEqual(claimed_system_user.user, existing_user)
        self.assertEqual(existing_user.email, "new-org@example.com")
        self.assertTrue(existing_user.email_verified)
        self.assertTrue(existing_user.phone_verified)
