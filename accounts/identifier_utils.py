import re

from accounts.models import IdentifierType


EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def detect_identifier_type(value: str) -> str:
    value = (value or "").strip()
    if EMAIL_RE.match(value):
        return IdentifierType.EMAIL
    return IdentifierType.PHONE


class IdentifierNormaliser:
    @classmethod
    def normalise(cls, value: str, identifier_type: str) -> str:
        value = (value or "").strip()
        if identifier_type == IdentifierType.EMAIL:
            return value.lower()
        if identifier_type == IdentifierType.PHONE:
            digits = re.sub(r"\D", "", value)
            return digits
        raise ValueError(f"Unsupported identifier type: {identifier_type}")
