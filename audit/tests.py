import uuid

from django.test import TestCase

from accounts.models import User
from audit.models import ModelAuditConfiguration, ModelAuditEventType, ModelAuditLog
from audit.services.request_context import RequestContext
from base.models import Realm


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
        deleted_user_id = user.id

        user.delete()

        audit_log = ModelAuditLog.objects.get(
            object_id=str(deleted_user_id),
            event_type=ModelAuditEventType.DELETE,
        )
        deleted_data = audit_log.metadata['deleted_object_data']
        self.assertEqual(deleted_data['realm'], str(realm.id))
