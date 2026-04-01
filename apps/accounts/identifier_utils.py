import re

import phonenumbers

from apps.accounts.models import IdentifierType


def detect_identifier_type(value: str) -> str:
    value = value.strip()

    # Email
    if "@" in value:
        return IdentifierType.EMAIL

    # Phone number
    digits_only = re.sub(r"[\s\-\+\(\)]", "", value)
    if digits_only.isdigit() and 7 <= len(digits_only) <= 15:
        return IdentifierType.PHONE

    # National ID
    if re.match(r"^[A-Za-z0-9]{6,20}$", value):
        return IdentifierType.NATIONAL_ID

    # Username
    return IdentifierType.USERNAME


class IdentifierNormaliser:
    @classmethod
    def normalise(cls, value: str, identifier_type: str) -> str:
        value = value.strip()

        if identifier_type == IdentifierType.EMAIL:
            return cls._normalise_email(value)

        if identifier_type == IdentifierType.PHONE:
            return cls._normalise_phone(value)

        if identifier_type == IdentifierType.USERNAME:
            return value.lower()

        if identifier_type == IdentifierType.NATIONAL_ID:
            return cls._normalise_national_id(value)

        return value.lower()


    @classmethod
    def _normalise_email(cls, value: str) -> str:
        value = value.lower()
        local, _, domain = value.partition("@")
        local = local.split("+")[0]

        return f"{local}@{domain}"

    @classmethod
    def _normalise_phone(cls, value: str, default_region: str = "KE") -> str:
        # noinspection PyBroadException
        try:
            parsed = phonenumbers.parse(value, default_region)
            if phonenumbers.is_valid_number(parsed):
                return phonenumbers.format_number(
                    parsed,
                    phonenumbers.PhoneNumberFormat.E164,
                )
        except Exception:
            pass

        return re.sub(r"[^\d\+]", "", value)

    @classmethod
    def _normalise_national_id(cls, value: str) -> str:
        return re.sub(r"[\s\-]", "", value).upper()