import hashlib
import hmac
import secrets
from datetime import timedelta
from typing import Optional

from django.db import transaction
from django.utils import timezone

from accounts.identifier_utils import IdentifierNormaliser
from accounts.models import (
    ContactVerification,
    ContactVerificationPurpose,
    IdentifierType,
    User,
    VerificationMethod,
)
from notifications.services.notification_service import NotificationService
from systems.models import System
from utils.common import generate_otp, mask

VERIFY_TTL = 300
MAX_VERIFY_ATTEMPTS = 3


class IdentifierVerificationError(Exception):
    pass


class IdentifierVerificationService:
    def __init__(self):
        self._normaliser = IdentifierNormaliser()

    @staticmethod
    def _validate_identifier_type(identifier_type: str) -> str:
        if identifier_type not in (IdentifierType.EMAIL, IdentifierType.PHONE):
            raise IdentifierVerificationError("Only email and phone can be verified.")
        return identifier_type

    @staticmethod
    def _validate_method(method: str) -> str:
        if method not in VerificationMethod.values:
            raise IdentifierVerificationError("Verification method must be 'otp' or 'link'.")
        return method

    @transaction.atomic
    def initiate_registration_verification(
            self,
            identifier_type: str,
            value: str,
            method: str = VerificationMethod.OTP,
            ip_address: str = "",
            system: Optional[System] = None,
    ) -> ContactVerification:
        return self._initiate_verification(
            user=None,
            identifier_type=identifier_type,
            value=value,
            method=method,
            purpose=ContactVerificationPurpose.REGISTRATION,
            ip_address=ip_address,
            system=system,
        )

    @transaction.atomic
    def initiate_user_contact_verification(
            self,
            user: User,
            identifier_type: str,
            method: str = VerificationMethod.OTP,
            ip_address: str = "",
            system: Optional[System] = None,
    ) -> ContactVerification:
        value = user.email if identifier_type == IdentifierType.EMAIL else user.phone_number
        return self._initiate_verification(
            user=user,
            identifier_type=identifier_type,
            value=value,
            method=method,
            purpose=ContactVerificationPurpose.PROFILE_UPDATE,
            ip_address=ip_address,
            system=system,
        )

    def _initiate_verification(
            self,
            user: Optional[User],
            identifier_type: str,
            value: str,
            method: str,
            purpose: str,
            ip_address: str,
            system: Optional[System],
    ) -> ContactVerification:
        identifier_type = self._validate_identifier_type(identifier_type)
        method = self._validate_method(method)
        value = (value or "").strip()
        if not value:
            raise IdentifierVerificationError(f"{identifier_type} value is required.")

        normalised = self._normaliser.normalise(value, identifier_type)
        self._rate_limit(identifier_type, normalised, ip_address)

        verification = ContactVerification(
            user=user,
            contact_type=identifier_type,
            value=value,
            value_normalized=normalised,
            method=method,
            purpose=purpose,
            expires_at=timezone.now() + timedelta(seconds=VERIFY_TTL),
            ip_requested=ip_address or None,
        )

        if method == VerificationMethod.OTP:
            raw_code = generate_otp()
            verification.code_hash = hashlib.sha256(raw_code.encode()).hexdigest()
            verification.save()
            NotificationService.deliver_otp_to_value(
                identifier_type=identifier_type,
                value=value,
                raw_code=raw_code,
                system=system,
            )
        else:
            raw_token = secrets.token_urlsafe(32)
            verification.token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
            verification.save()
            NotificationService.deliver_verification_link(
                identifier_type=identifier_type,
                value=value,
                raw_token=raw_token,
                system=system,
            )

        return verification

    @transaction.atomic
    def verify_registration_verification(
            self,
            verification_id: str,
            code: str = "",
            token: str = "",
            ip_address: str = "",
    ) -> ContactVerification:
        verification = self._verify_contact_verification(
            verification_id=verification_id,
            code=code,
            token=token,
            ip_address=ip_address,
        )
        return verification

    @transaction.atomic
    def verify_user_contact(
            self,
            user: User,
            identifier_type: str,
            verification_id: str,
            code: str = "",
            token: str = "",
            ip_address: str = "",
    ) -> User:
        verification = self._verify_contact_verification(
            verification_id=verification_id,
            code=code,
            token=token,
            ip_address=ip_address,
        )
        if verification.user_id and verification.user_id != user.id:
            raise IdentifierVerificationError("This verification does not belong to the current user.")
        if verification.contact_type != identifier_type:
            raise IdentifierVerificationError("Verification contact type does not match.")
        self._mark_user_contact_verified(user, identifier_type)
        return user

    @staticmethod
    def _verify_contact_verification(
            verification_id: str,
            code: str,
            token: str,
            ip_address: str,
    ) -> ContactVerification:
        try:
            verification = ContactVerification.objects.get(id=verification_id, is_used=False)
        except ContactVerification.DoesNotExist:
            raise IdentifierVerificationError("Invalid or expired verification.")

        if verification.is_expired():
            raise IdentifierVerificationError("Verification has expired.")

        if verification.method == VerificationMethod.OTP:
            submitted_hash = hashlib.sha256((code or "").encode()).hexdigest()
            expected_hash = verification.code_hash
        else:
            submitted_hash = hashlib.sha256((token or "").encode()).hexdigest()
            expected_hash = verification.token_hash

        if not submitted_hash or not hmac.compare_digest(submitted_hash, expected_hash):
            verification.attempts += 1
            if verification.attempts >= MAX_VERIFY_ATTEMPTS:
                verification.is_used = True
            verification.save(update_fields=["attempts", "is_used"])
            remaining = max(0, MAX_VERIFY_ATTEMPTS - verification.attempts)
            if remaining == 0:
                raise IdentifierVerificationError(
                    "Too many incorrect attempts. Please request a new verification."
                )
            raise IdentifierVerificationError(
                f"Incorrect verification. {remaining} attempt(s) remaining."
            )

        verification.is_used = True
        verification.is_verified = True
        verification.used_at = timezone.now()
        verification.verified_at = timezone.now()
        verification.ip_verified = ip_address or None
        verification.save(update_fields=[
            "is_used", "is_verified", "used_at", "verified_at", "ip_verified"
        ])
        return verification

    def assert_verified_identifier(
            self,
            identifier_type: str,
            value: str,
            verification_id: Optional[str],
    ) -> Optional[ContactVerification]:
        if not verification_id:
            return None

        identifier_type = self._validate_identifier_type(identifier_type)
        normalised = self._normaliser.normalise(value, identifier_type)

        try:
            verification = ContactVerification.objects.get(
                id=verification_id,
                purpose=ContactVerificationPurpose.REGISTRATION,
                contact_type=identifier_type,
                value_normalized=normalised,
                is_verified=True,
                consumed_at__isnull=True,
            )
        except ContactVerification.DoesNotExist:
            raise IdentifierVerificationError(
                f"No verified {identifier_type} proof was found for '{value}'."
            )
        if verification.is_expired():
            raise IdentifierVerificationError(
                f"The verified {identifier_type} proof for '{value}' has expired."
            )
        return verification

    @staticmethod
    def consume_registration_verification(verification: ContactVerification) -> None:
        verification.consumed_at = timezone.now()
        verification.save(update_fields=["consumed_at"])

    @staticmethod
    def _mark_user_contact_verified(user: User, identifier_type: str) -> None:
        now = timezone.now()
        if identifier_type == IdentifierType.EMAIL:
            user.email_verified = True
            user.email_verified_at = now
            user.save(update_fields=["email_verified", "email_verified_at"])
            return
        user.phone_verified = True
        user.phone_verified_at = now
        user.save(update_fields=["phone_verified", "phone_verified_at"])

    @staticmethod
    def masked_value(value: str) -> str:
        return mask(value)

    @staticmethod
    def _rate_limit(identifier_type: str, normalised: str, ip_address: str) -> None:
        window = timezone.now() - timedelta(minutes=10)
        if ContactVerification.objects.filter(
            contact_type=identifier_type,
            value_normalized=normalised,
            created_at__gte=window,
        ).count() >= 5:
            raise IdentifierVerificationError(
                "Too many verifications requested. Please wait a few minutes."
            )

        if ip_address and ContactVerification.objects.filter(
            ip_requested=ip_address,
            created_at__gte=timezone.now() - timedelta(hours=1),
        ).count() >= 10:
            raise IdentifierVerificationError(
                "Too many requests from this device. Please try again later."
            )
