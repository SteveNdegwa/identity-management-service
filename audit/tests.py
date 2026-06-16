import uuid

from django.test import TestCase

from accounts.models import SystemUser, User
from audit.models import ModelAuditConfiguration, ModelAuditEventType, ModelAuditLog
from audit.services.request_context import RequestContext
from base.models import Country, Realm
from organizations.models import Organization
from permissions.models import Role
from systems.models import System


class AuditableMixinTests(TestCase):
    def tearDown(self):
        RequestContext.clear()

    def test_save_creates_model_audit_log_with_request_metadata(self):
        ModelAuditConfiguration.objects.create(app_label='base', model_name='realm')
        request_id = uuid.uuid4()
        user_id = uuid.uuid4()
        RequestContext.update(
            request_id=request_id,
            user_id=user_id,
            ip_address='127.0.0.1',
            user_agent='test-agent',
            request_method='POST',
            request_path='/api/accounts/register/',
        )

        realm = Realm.objects.create(name='Registration Realm')

        audit_log = ModelAuditLog.objects.get(object_id=str(realm.id))
        self.assertEqual(audit_log.request_id, request_id)
        self.assertEqual(audit_log.user_id, user_id)
        self.assertEqual(audit_log.request_method, 'POST')
        self.assertEqual(audit_log.request_path, '/api/accounts/register/')

    def test_delete_audit_log_serializes_foreign_key_values(self):
        ModelAuditConfiguration.objects.create(app_label='accounts', model_name='user')
        realm = Realm.objects.create(name='Delete Realm')
        user = User.objects.create_user(
            realm=realm,
            email='delete@example.com',
            phone_number='+254700000001',
        )

        user.delete()

        audit_log = ModelAuditLog.objects.get(
            object_id=str(user.id),
            event_type=ModelAuditEventType.DELETE,
        )
        deleted_data = audit_log.metadata['deleted_object_data']
        self.assertEqual(deleted_data['realm'], str(realm.id))

    def test_update_audit_log_serializes_foreign_key_changes(self):
        ModelAuditConfiguration.objects.create(app_label='accounts', model_name='systemuser')
        realm = Realm.objects.create(name='System User Audit Realm')
        country = Country.objects.create(code='KE', code3='KEN', name='Kenya', phone_code='+254')
        system = System.objects.create(realm=realm, name='Audit System', slug='audit-system')
        role = Role.objects.create(system=system, country=country, name='Owner', slug='owner')
        user = User.objects.create_user(
            realm=realm,
            email='member@example.com',
            phone_number='+254700000002',
        )
        system_user = SystemUser.objects.create(
            user=user,
            system=system,
            country=country,
            role=role,
            provisioning_email=user.email,
        )
        organization = Organization.objects.create(
            system=system,
            name='Audit Organization',
            slug='audit-organization',
        )
        ModelAuditLog.objects.all().delete()

        system_user.organization = organization
        system_user.save()

        audit_log = ModelAuditLog.objects.get(
            object_id=str(system_user.id),
            event_type=ModelAuditEventType.UPDATE,
        )
        self.assertEqual(audit_log.changes['organization']['new_value'], str(organization.id))
