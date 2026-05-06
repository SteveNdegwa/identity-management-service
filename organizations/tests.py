from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase

from accounts.models import SystemUser, User
from base.models import Country, Realm
from organizations.models import (
    DocumentStatus,
    DocumentType,
    OnboardingStatus,
    OrganizationCountry,
    OrganizationOnboarding,
    OrganizationOnboardingCountry,
)
from organizations.services.onboarding_service import OnboardingError, OnboardingService
from permissions.models import Role
from systems.models import System


class OnboardingServiceTests(TestCase):
    def setUp(self):
        self.realm = Realm.objects.create(name="Test Realm")
        self.country_ke = Country.objects.create(code="KE", code3="KEN", name="Kenya", phone_code="+254")
        self.country_ug = Country.objects.create(code="UG", code3="UGA", name="Uganda", phone_code="+256")
        self.country_tz = Country.objects.create(code="TZ", code3="TZA", name="Tanzania", phone_code="+255")
        self.system = System.objects.create(
            realm=self.realm,
            name="Test System",
            slug="test-system",
        )
        self.system.available_countries.add(self.country_ke, self.country_ug, self.country_tz)
        self.role = Role.objects.create(system=self.system, country=self.country_ke, name="Owner", slug="owner")
        self.user = User.objects.create_user(
            realm=self.realm,
            email="owner@example.com",
            phone_number="+254700000001",
            password="Secret123!",
        )
        self.system_user = SystemUser.objects.create(
            user=self.user,
            system=self.system,
            country=self.country_ke,
            role=self.role,
            status="active",
            provisioning_email=self.user.email,
        )
        self.service = OnboardingService()

    @staticmethod
    def _documents():
        return {
            "business_registration": SimpleUploadedFile("business.pdf", b"business", content_type="application/pdf"),
            "kra_pin": SimpleUploadedFile("kra.pdf", b"kra", content_type="application/pdf"),
        }

    def _approve_documents(self, onboarding):
        for document in onboarding.documents.all():
            document.status = DocumentStatus.APPROVED
            document.save(update_fields=["status"])

    def test_create_application_supports_multiple_countries(self):
        onboarding = self.service.create_application(
            system=self.system,
            contact_system_user=self.system_user,
            countries=[
                {"country": self.country_ke, "registration_number": "KE-1", "tax_id": "KRA-1"},
                {"country": self.country_ug, "registration_number": "UG-1", "tax_id": "URA-1"},
            ],
            legal_name="Acme Holdings Ltd",
            trading_name="Acme",
            organization_type="microfinance_bank",
            products_needed=["statement_analysis", "kyc_kyb_checks"],
            monthly_transaction_volume="10001_to_30000",
            staff_size="21_to_50",
            pain_points=["manual_analysis", "manual_verifications"],
            documents=self._documents(),
        )

        self.assertEqual(OrganizationOnboarding.objects.count(), 1)
        self.assertEqual(
            set(onboarding.country_requests.values_list("country_id", flat=True)),
            {self.country_ke.id, self.country_ug.id},
        )
        self.assertEqual(onboarding.organization_type, "microfinance_bank")
        self.assertEqual(onboarding.products_needed, ["statement_analysis", "kyc_kyb_checks"])
        self.assertEqual(onboarding.pain_points, ["manual_analysis", "manual_verifications"])

    def test_editable_onboarding_country_details_can_be_updated(self):
        onboarding = self.service.create_application(
            system=self.system,
            contact_system_user=self.system_user,
            countries=[{"country": self.country_ke, "registration_number": "KE-1", "tax_id": "KRA-1"}],
            legal_name="Acme Holdings Ltd",
            documents=self._documents(),
        )
        country_request = onboarding.country_requests.get(country=self.country_ke)

        with self.assertRaises(OnboardingError):
            self.service.update_application(
                onboarding=onboarding,
                performed_by=self.system_user,
                country=self.country_ug,
            )
        updated_country = self.service.update_country(
            country_request=country_request,
            performed_by=self.system_user,
            country=self.country_ug,
            registration_number="UG-1",
            tax_id="URA-1",
        )

        self.assertEqual(updated_country.country, self.country_ug)
        self.assertEqual(updated_country.registration_number, "UG-1")
        self.assertEqual(updated_country.tax_id, "URA-1")

    def test_editable_onboarding_country_can_be_removed_when_another_country_remains(self):
        onboarding = self.service.create_application(
            system=self.system,
            contact_system_user=self.system_user,
            countries=[
                {"country": self.country_ke, "registration_number": "KE-1", "tax_id": "KRA-1"},
                {"country": self.country_ug, "registration_number": "UG-1", "tax_id": "URA-1"},
            ],
            legal_name="Acme Holdings Ltd",
            documents=self._documents(),
        )
        uganda = onboarding.country_requests.get(country=self.country_ug)

        self.service.remove_country(uganda, self.system_user)

        self.assertTrue(OrganizationOnboarding.objects.filter(id=onboarding.id).exists())
        self.assertFalse(OrganizationOnboardingCountry.objects.filter(id=uganda.id).exists())
        self.assertEqual(onboarding.country_requests.count(), 1)

    def test_editable_onboarding_country_cannot_remove_last_country(self):
        onboarding = self.service.create_application(
            system=self.system,
            contact_system_user=self.system_user,
            countries=[{"country": self.country_ke, "registration_number": "KE-1", "tax_id": "KRA-1"}],
            legal_name="Acme Holdings Ltd",
            documents=self._documents(),
        )
        kenya = onboarding.country_requests.get(country=self.country_ke)

        with self.assertRaises(OnboardingError):
            self.service.remove_country(kenya, self.system_user)

        self.assertTrue(OrganizationOnboardingCountry.objects.filter(id=kenya.id).exists())

    def test_add_country_adds_country_row_to_existing_editable_onboarding(self):
        onboarding = self.service.create_application(
            system=self.system,
            contact_system_user=self.system_user,
            countries=[{"country": self.country_ke, "registration_number": "KE-1", "tax_id": "KRA-1"}],
            legal_name="Acme Holdings Ltd",
            documents=self._documents(),
        )

        added = self.service.add_country(
            onboarding=onboarding,
            performed_by=self.system_user,
            country=self.country_tz,
            registration_number="TZ-1",
            tax_id="TRA-1",
        )

        self.assertEqual(added.onboarding, onboarding)
        self.assertEqual(added.country, self.country_tz)
        self.assertEqual(onboarding.country_requests.count(), 2)

    def test_non_mandatory_document_can_be_removed_but_mandatory_document_cannot(self):
        onboarding = self.service.create_application(
            system=self.system,
            contact_system_user=self.system_user,
            countries=[{"country": self.country_ke, "registration_number": "KE-1", "tax_id": "KRA-1"}],
            legal_name="Acme Holdings Ltd",
            documents=self._documents(),
        )
        other = self.service.upload_document(
            onboarding=onboarding,
            uploaded_by=self.system_user,
            document_type=DocumentType.OTHER,
            file=SimpleUploadedFile("other.pdf", b"other", content_type="application/pdf"),
        )
        mandatory = onboarding.documents.get(document_type=DocumentType.BUSINESS_REGISTRATION)

        self.service.remove_document(other, self.system_user)
        with self.assertRaises(OnboardingError):
            self.service.remove_document(mandatory, self.system_user)

        self.assertFalse(onboarding.documents.filter(id=other.id).exists())
        self.assertTrue(onboarding.documents.filter(id=mandatory.id).exists())

    def test_non_editable_onboarding_cannot_change_country_or_be_removed(self):
        onboarding = self.service.create_application(
            system=self.system,
            contact_system_user=self.system_user,
            countries=[{"country": self.country_ke, "registration_number": "KE-1", "tax_id": "KRA-1"}],
            legal_name="Acme Holdings Ltd",
            documents=self._documents(),
        )
        self.service.submit(onboarding, self.system_user)

        with self.assertRaises(OnboardingError):
            self.service.update_country(
                country_request=onboarding.country_requests.get(country=self.country_ke),
                performed_by=self.system_user,
                country=self.country_ug,
            )
        with self.assertRaises(OnboardingError):
            self.service.remove_country(onboarding.country_requests.get(country=self.country_ke), self.system_user)

    def test_complete_onboarding_creates_org_and_marks_country_approved(self):
        onboarding = self.service.create_application(
            system=self.system,
            contact_system_user=self.system_user,
            countries=[{"country": self.country_ke, "registration_number": "KE-1", "tax_id": "KRA-1"}],
            legal_name="Acme Holdings Ltd",
            documents=self._documents(),
        )
        self._approve_documents(onboarding)

        self.service.submit(onboarding, self.system_user)
        self.service.start_review(onboarding, self.system_user)
        self.service.approve(onboarding, self.system_user)
        organization = self.service.complete_onboarding(onboarding, self.system_user)

        onboarding.refresh_from_db()
        org_country = OrganizationCountry.objects.get(organization=organization, country=self.country_ke)
        self.assertEqual(onboarding.status, OnboardingStatus.ONBOARDED)
        self.assertEqual(onboarding.organization, organization)
        self.assertTrue(organization.verified)
        self.assertEqual(org_country.approval_status, OrganizationCountry.ApprovalStatus.APPROVED)
        self.assertEqual(org_country.source_onboarding, onboarding)

    def test_complete_onboarding_can_add_later_country_to_existing_org(self):
        first_onboarding = self.service.create_application(
            system=self.system,
            contact_system_user=self.system_user,
            countries=[{"country": self.country_ke, "registration_number": "KE-1", "tax_id": "KRA-1"}],
            legal_name="Acme Holdings Ltd",
            documents=self._documents(),
        )
        self._approve_documents(first_onboarding)
        self.service.submit(first_onboarding, self.system_user)
        self.service.start_review(first_onboarding, self.system_user)
        self.service.approve(first_onboarding, self.system_user)
        organization = self.service.complete_onboarding(first_onboarding, self.system_user)

        second_onboarding = self.service.create_country_application_for_onboarded_organization(
            organization=organization,
            contact_system_user=self.system_user,
            country=self.country_ug,
            registration_number="UG-1",
            tax_id="URA-1",
            documents=self._documents(),
        )
        self._approve_documents(second_onboarding)
        self.service.submit(second_onboarding, self.system_user)
        self.service.start_review(second_onboarding, self.system_user)
        self.service.approve(second_onboarding, self.system_user)
        returned_organization = self.service.complete_onboarding(second_onboarding, self.system_user)

        self.assertEqual(returned_organization, organization)
        self.assertEqual(organization.organization_countries.count(), 2)
        uganda = OrganizationCountry.objects.get(organization=organization, country=self.country_ug)
        self.assertEqual(uganda.approval_status, OrganizationCountry.ApprovalStatus.APPROVED)
        self.assertEqual(uganda.source_onboarding, second_onboarding)
