import datetime

import requests
from django.conf import settings

from accounts.models import IdentifierType
from systems.models import System


class NotificationService:
    @classmethod
    def deliver_otp(
        cls,
        identifier_type: str,
        value: str,
        raw_code: str,
        system: System,
    ) -> None:
        context = {
            'code': raw_code,
            'system_name': system.name,
            'year': datetime.datetime.now().year,
            'expiry_minutes': 5,
        }

        if identifier_type == IdentifierType.PHONE:
            notification_type = 'sms'
            template = 'phone_verification'
        elif identifier_type == IdentifierType.EMAIL:
            notification_type = 'email'
            template = 'email_verification'
        else:
            raise ValueError(f'Unsupported identifier type: {identifier_type}')

        cls.send_notification(
            recipients=[value],
            notification_type=notification_type,
            template=template,
            context=context,
        )

    @classmethod
    def deliver_verification_link(
        cls,
        identifier_type: str,
        value: str,
        raw_token: str,
        system: System,
    ) -> None:
        context = {
            'action_url': raw_token,  # TODO: APPEND BASE URL
            'system_name': system.name,
            'year': datetime.datetime.now().year,
        }

        if identifier_type == IdentifierType.PHONE:
            notification_type = 'sms'
            template = 'phone_verification'
        elif identifier_type == IdentifierType.EMAIL:
            notification_type = 'email'
            template = 'email_verification'
        else:
            raise ValueError(f'Unsupported identifier type: {identifier_type}')

        cls.send_notification(
            recipients=[value],
            notification_type=notification_type,
            template=template,
            context=context,
        )

    @classmethod
    def deliver_magic_link(
        cls,
        identifier_type: str,
        value: str,
        raw_token: str,
        system: System,
    ) -> None:
        context = {
            'action_url': raw_token,  # TODO: APPEND BASE URL
            'system_name': system.name,
            'year': datetime.datetime.now().year,
        }

        if identifier_type == IdentifierType.PHONE:
            notification_type = 'sms'
            template = 'sms_magic_link'
        elif identifier_type == IdentifierType.EMAIL:
            notification_type = 'email'
            template = 'email_magic_link'
        else:
            raise ValueError(f'Unsupported identifier type: {identifier_type}')

        cls.send_notification(
            recipients=[value],
            notification_type=notification_type,
            template=template,
            context=context,
        )

    @classmethod
    def _make_request(cls, notification_data: dict):
        response = requests.post(
            f'{settings.NOTIFY_BASE_URL}/api/core/send-notification/',
            headers={'X-API-KEY': settings.NOTIFY_API_KEY},
            json=notification_data,
        )
        response.raise_for_status()

    @classmethod
    def send_notification(
        cls, recipients: list, notification_type: str, template: str, context: dict
    ) -> None:
        notification_data = {
            'unique_identifier': None,
            'system': 'IDMS',
            'recipients': list(set(recipients)),
            'notification_type': notification_type,
            'template': template,
            'context': context,
        }
        cls._make_request(notification_data)
