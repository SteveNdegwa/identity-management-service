from typing import Optional

from accounts.models import IdentifierType
from systems.models import System


class NotificationService:
    @classmethod
    def deliver_otp_to_value(
            cls,
            identifier_type: str,
            value: str,
            raw_code: str,
            system: Optional[System] = None,
    ) -> None:
        # TODO: DELIVER OTP LOGIC
        if identifier_type == IdentifierType.PHONE:
            ...
        elif identifier_type == IdentifierType.EMAIL:
            ...
        else:
            raise ValueError(f"Unsupported identifier type: {identifier_type}")

    @classmethod
    def deliver_otp(
            cls,
            identifier_type: str,
            value: str,
            raw_code: str,
            system: Optional[System] = None,
            delivery_target: Optional[str] = None,
    ) -> None:
        target = delivery_target or value
        cls.deliver_otp_to_value(
            identifier_type=identifier_type,
            value=target,
            raw_code=raw_code,
            system=system,
        )

    @classmethod
    def deliver_verification_link(
            cls,
            identifier_type: str,
            value: str,
            raw_token: str,
            system: Optional[System] = None,
    ) -> None:
        # TODO: DELIVER VERIFICATION LINK LOGIC
        if identifier_type not in (IdentifierType.PHONE, IdentifierType.EMAIL):
            raise ValueError(f"Unsupported identifier type: {identifier_type}")

    @classmethod
    def deliver_magic_link(
        cls,
        identifier_type: str,
        value: str,
        raw_token: str,
        system: System,
    ) -> None:
        # TODO: DELIVER MAGIC LINK EMAIL
        ...
