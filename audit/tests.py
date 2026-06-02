import uuid

from django.test import TestCase

from audit.models import ModelAuditConfiguration, ModelAuditLog
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
