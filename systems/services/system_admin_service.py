import secrets

import bcrypt
from django.db import transaction

from audit.models import AuditEventType, AuditLog
from base.models import Country
from systems.models import System, SystemClient, SystemSettings


class SystemAdminService:

    @transaction.atomic
    def register_system(
        self,
        name: str,
        slug: str,
        countries: list[Country],
        system_type: str = "saas",
        **kwargs,
    ) -> System:
        system = System.objects.create(
            name=name,
            slug=slug,
            system_type=system_type,
            **kwargs
        )

        system.available_countries.set(countries)

        self._audit(
            AuditEventType.SYSTEM_CREATED,
            payload={"name": name, "countries": [c.code for c in countries]},
        )
        return system

    @staticmethod
    def add_country(system: System, country: Country, **kwargs):
        system.available_countries.add(country)
        return country

    @transaction.atomic
    def create_client(
        self,
        system: System,
        name: str,
        client_type: str = "confidential",
        redirect_uris: list = None,
        **kwargs,
    ) -> tuple:
        raw_secret  = secrets.token_urlsafe(48)
        secret_hash = bcrypt.hashpw(
            raw_secret.encode(), bcrypt.gensalt()
        ).decode()
        client = SystemClient.objects.create(
            system=system,
            name=name,
            client_type=client_type,
            redirect_uris=redirect_uris or [],
            client_secret_hash=secret_hash,
            **kwargs,
        )
        return client, raw_secret

    def set_system_setting(
        self,
        system: System,
        key: str,
        value: str,
        value_type: str = "string",
        **kwargs,
    ) -> SystemSettings:
        setting, _ = SystemSettings.objects.update_or_create(
            system=system,
            key=key,
            defaults={"value": value, "value_type": value_type, **kwargs},
        )
        self._audit(
            AuditEventType.SYSTEM_SETTINGS_CHANGED,
            payload={"system": system.name, "key": key},
        )
        return setting

    @staticmethod
    def _audit(event_type, actor=None, payload=None):
        AuditLog.objects.create(
            event_type=event_type,
            actor_user_id=actor.id if actor else None,
            payload=payload or {},
        )