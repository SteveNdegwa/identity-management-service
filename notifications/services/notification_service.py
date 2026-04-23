from typing import Optional

from accounts.models import UserIdentifier, IdentifierType
from systems.models import System


class NotificationService:

    @classmethod
    def deliver_otp(
            cls,
            identifier: UserIdentifier,
            raw_code: str,
            system: Optional[System] = None,
            delivery_target: Optional[str] = None,
    ) -> None:
        target = delivery_target or identifier.value

        # TODO: DELIVER OTP LOGIC

        if identifier.identifier_type == IdentifierType.PHONE:
            ...

        elif identifier.identifier_type == IdentifierType.EMAIL:
            ...

        else:
            raise ValueError(f"Unsupported identifier type: {identifier.identifier_type}")

    @classmethod
    def deliver_magic_link(
            cls,
            identifier: UserIdentifier,
            raw_token: str,
            system: System,
    ) -> None:
        # TODO: DELIVER MAGIC LINK EMAIL
        ...