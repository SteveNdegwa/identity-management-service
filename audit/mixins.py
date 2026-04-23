from django.contrib.contenttypes.models import ContentType

from audit.services.request_context import RequestContext


class AuditableMixin:

    def _is_tracking_enabled(self, action: str) -> bool:
        from audit.models import ModelAuditConfiguration, ModelAuditEventType

        try:
            config = ModelAuditConfiguration.objects.get(
                app_label=self._meta.app_label,
                model_name=self._meta.model_name,
                is_enabled=True,
            )
        except ModelAuditConfiguration.DoesNotExist:
            return False

        if action == ModelAuditEventType.CREATE:
            return config.track_create
        if action == ModelAuditEventType.UPDATE:
            return config.track_update
        if action == ModelAuditEventType.DELETE:
            return config.track_delete

        return False

    def save(self, *args, **kwargs):
        from audit.models import ModelAuditEventType, ModelAuditSeverity, ModelAuditLog

        is_new = self.pk is None

        original_values = {}
        if not is_new:
            try:
                original = self.__class__.objects.get(pk=self.pk)
                for field in self._meta.fields:
                    original_values[field.name] = getattr(original, field.name, None)
            except self.__class__.DoesNotExist:
                is_new = True

        result = super().save(*args, **kwargs)

        event_type = ModelAuditEventType.CREATE if is_new else ModelAuditEventType.UPDATE
        if not self._is_tracking_enabled(event_type):
            return result

        context = RequestContext.get()

        changes = {}
        if not is_new and original_values:
            for field in self._meta.fields:
                if field.name in self._excluded_audit_fields():
                    continue
                old_value = original_values.get(field.name)
                new_value = getattr(self, field.name, None)
                if old_value != new_value:
                    changes[field.name] = {
                        'old_value': old_value,
                        'new_value': new_value,
                    }

        ModelAuditLog.objects.create(
            request_id=context.get('request_id'),
            user_id=context.get('user_id'),
            ip_address=context.get('ip_address'),
            user_agent=context.get('user_agent'),
            request_method=context.get('request_method'),
            request_path=context.get('request_path'),
            event_type=event_type,
            severity=ModelAuditSeverity.LOW if is_new else ModelAuditSeverity.MEDIUM,
            content_type=ContentType.objects.get_for_model(self.__class__),
            object_id=str(self.pk),
            object_repr=str(self),
            changes=changes or None,
        )

        return result

    def delete(self, *args, **kwargs):
        from audit.models import ModelAuditEventType, ModelAuditSeverity, ModelAuditLog

        if not self._is_tracking_enabled(ModelAuditEventType.DELETE):
            return super().delete(*args, **kwargs)

        context = RequestContext.get()

        # Snapshot before delete
        deleted_data = {
            field.name: getattr(self, field.name, None)
            for field in self._meta.fields
            if field.name not in self._excluded_audit_fields()
        }

        ModelAuditLog.objects.create(
            request_id=context.get('request_id'),
            api_client=context.get('api_client'),
            user=context.get('user'),
            ip_address=context.get('ip_address'),
            user_agent=context.get('user_agent'),
            request_method=context.get('request_method'),
            request_path=context.get('request_path'),
            activity_name=context.get('activity_name'),
            event_type=ModelAuditEventType.DELETE,
            severity=ModelAuditSeverity.MEDIUM,
            content_type=ContentType.objects.get_for_model(self.__class__),
            object_id=str(self.pk),
            object_repr=str(self),
            changes=None,
            metadata={'deleted_object_data': deleted_data},
        )

        return super().delete(*args, **kwargs)

    def _excluded_audit_fields(self):
        from audit.models import ModelAuditConfiguration

        config = ModelAuditConfiguration.objects.get(
            app_label=self._meta.app_label,
            model_name=self._meta.model_name,
            is_enabled=True,
        )

        if config is None:
            return []

        return config.excluded_fields or []
