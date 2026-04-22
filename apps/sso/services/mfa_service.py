import hmac
import secrets

from dataclasses import dataclass
from datetime import timedelta
from typing import Optional, List

import bcrypt
import pyotp
from django.conf import settings

from django.db import transaction
from django.utils import timezone

from accounts.identifier_utils import detect_identifier_type
from apps.accounts.models import User, IdentifierType
from apps.accounts.identifier_utils import IdentifierNormaliser
from apps.audit.models import AuditLog, AuditEventType
from apps.notifications.services.notification_service import NotificationService
from apps.sso.models import (
    PasswordlessChallenge,
    PendingMFAEnrollment,
    MFAMethod,
    UserMFA,
    BackupCode,
    SSOSessionMFAVerification,
    SSOSession,
)
from apps.systems.models import SystemClient
from systems.models import System
from utils.common import generate_otp, hash_value, mask

PASSWORDLESS_TTL = 300
MAX_OTP_ATTEMPTS = 3


class MFAError(Exception):
    pass

class InvalidMFAOperationError(MFAError):
    pass

class MFARateLimitExceededError(MFAError):
    pass


@dataclass
class MFAEnrollmentResult:
    mfa: UserMFA
    backup_codes: Optional[List[str]] = None


class MFAService:
    def __init__(self):
        self._normaliser = IdentifierNormaliser()

    @transaction.atomic
    def initiate_enrollment(
            self,
            user: User,
            method: str,
            device_name: str = "",
            delivery_target: Optional[str] = None,
            client: Optional[SystemClient] = None,
            ip_address: str = "",
            pending_enrollment_id: Optional[str] = None,
    ) -> dict:
        if method not in MFAMethod.values:
            raise InvalidMFAOperationError(f"Invalid MFA method: {method}")
        if UserMFA.objects.filter(user=user, method=method, is_active=True).exists():
            raise InvalidMFAOperationError(f"{method} is already enrolled and active.")

        if method == MFAMethod.TOTP:
            return self._initiate_totp_enrollment(user, device_name, pending_enrollment_id)
        if method in (MFAMethod.SMS, MFAMethod.EMAIL):
            return self._initiate_otp_enrollment(
                user, method, delivery_target, client, ip_address, pending_enrollment_id
            )
        if method == MFAMethod.BACKUP:
            return self._initiate_backup_enrollment(user, pending_enrollment_id)
        if method == MFAMethod.WEBAUTHN:
            raise NotImplementedError("WebAuthn enrollment not implemented yet.")
        raise NotImplementedError(f"Enrollment for method '{method}' is not supported.")

    @transaction.atomic
    def verify_enrollment(
            self,
            user: User,
            method: str,
            verification_data: dict,
            ip_address: str = "",
            pending_enrollment_id: Optional[str] = None,
    ) -> MFAEnrollmentResult:
        if method == MFAMethod.TOTP:
            return self._verify_totp_enrollment(user, verification_data, ip_address, pending_enrollment_id)
        if method in (MFAMethod.SMS, MFAMethod.EMAIL):
            return self._verify_otp_enrollment(user, method, verification_data, ip_address, pending_enrollment_id)
        if method == MFAMethod.BACKUP:
            mfa = self._mark_backup_enrolled(user, ip_address, pending_enrollment_id)
            return MFAEnrollmentResult(mfa=mfa)
        raise InvalidMFAOperationError(f"Verification not supported for method {method}")

    @staticmethod
    def list_enrolled(user: User) -> List[UserMFA]:
        return list(
            UserMFA.objects.
            filter(user=user, is_active=True)
            .order_by("-is_primary", "method")
        )

    @staticmethod
    def get_primary(user: User) -> Optional[UserMFA]:
        return UserMFA.objects.filter(user=user, is_active=True, is_primary=True).first()

    @transaction.atomic
    def set_primary(self, user: User, mfa_id: str) -> UserMFA:
        mfa = UserMFA.objects.get(id=mfa_id, user=user, is_active=True)
        UserMFA.objects.filter(user=user, is_primary=True).update(is_primary=False)
        mfa.is_primary = True
        mfa.save(update_fields=["is_primary"])
        self._audit(user, AuditEventType.MFA_PRIMARY_CHANGED, {"method": mfa.method})
        return mfa

    @transaction.atomic
    def remove_mfa(self, user: User, mfa_id: str, ip_address: str = "") -> None:
        mfa = UserMFA.objects.get(id=mfa_id, user=user)
        if mfa.is_primary:
            raise InvalidMFAOperationError("Cannot remove the primary MFA method.")
        mfa.is_active = False
        mfa.save(update_fields=["is_active"])
        self._audit(user, AuditEventType.MFA_REMOVED, {"method": mfa.method}, ip_address)

    @transaction.atomic
    def generate_backup_codes(self, user: User, count: int = 10) -> List[str]:
        BackupCode.objects.filter(
            user=user,
            is_used=False,
            invalidated_at__isnull=True
        ).update(invalidated_at=timezone.now())
        codes = []
        for _ in range(count):
            raw_code = secrets.token_urlsafe(16)[:12].upper().replace("I", "X").replace("O", "Y")
            code_hash = bcrypt.hashpw(raw_code.encode(), bcrypt.gensalt()).decode()
            BackupCode.objects.create(user=user, code_hash=code_hash)
            codes.append(raw_code)
        self._audit(user, AuditEventType.BACKUP_CODES_GENERATED, {"count": count})
        return codes

    def verify_mfa_code(
            self,
            user: User,
            method: str,
            code: str,
            ip_address: str = "",
            sso_session: Optional[SSOSession] = None,
            system: Optional[System] = None,
    ) -> bool:
        mfa_entry = user.mfa_methods.filter(method=method, is_active=True).first()
        if not mfa_entry:
            raise InvalidMFAOperationError(f"MFA method '{method}' is not enrolled.")

        verified = self._validate_mfa_code(mfa_entry, code, method)

        if verified:
            if sso_session:
                SSOSessionMFAVerification.objects.create(
                    session=sso_session,
                    method=method,
                    ip_address=ip_address or None,
                    system=system,
                )
            mfa_entry.last_used_at = timezone.now()
            mfa_entry.save(update_fields=["last_used_at"])
            self._audit(user, AuditEventType.MFA_VERIFIED, {"method": method}, ip_address)
        else:
            self._audit(user, AuditEventType.MFA_FAILED, {"method": method}, ip_address, outcome="failure")

        return verified

    @transaction.atomic
    def initiate_mfa_otp(
        self,
        sso_session: SSOSession,
        method: str,
        client: SystemClient,
        ip_address: str = "",
    ) -> dict:
        if method not in (MFAMethod.SMS, MFAMethod.EMAIL):
            raise InvalidMFAOperationError("Only SMS and Email OTP methods are supported for this flow.")

        user = sso_session.user
        mfa_entry = user.mfa_methods.filter(method=method, is_active=True).first()
        if not mfa_entry:
            raise InvalidMFAOperationError(f"{method} MFA method is not enrolled.")

        id_type = IdentifierType.PHONE if method == MFAMethod.SMS else IdentifierType.EMAIL
        identifier = user.identifiers.filter(identifier_type=id_type, disassociated_at__isnull=True).first()
        if not identifier:
            raise InvalidMFAOperationError(f"No active {id_type} identifier found for MFA delivery.")

        send_to = mfa_entry.delivery_target or identifier.value
        self._rate_limit_otp(send_to, ip_address)

        raw_code  = generate_otp()
        code_hash = hash_value(raw_code)

        challenge = PasswordlessChallenge.objects.create(
            user=user,
            identifier=identifier,
            client=client,
            sso_session=sso_session,
            user_mfa=mfa_entry,
            purpose=PasswordlessChallenge.Purpose.MFA,
            code_hash=code_hash,
            expires_at=timezone.now() + timedelta(seconds=PASSWORDLESS_TTL),
            ip_requested=ip_address or None,
        )

        NotificationService.deliver_otp(
            identifier=identifier,
            raw_code=raw_code,
            system=client.system,
            delivery_target=mfa_entry.delivery_target
        )

        self._audit(
            user,
            AuditEventType.PASSWORDLESS_INITIATED,
            {"method": method, "purpose": "mfa"},
            ip_address
        )

        return {
            "challenge_id": str(challenge.id),
            "masked_destination": mask(send_to),
            "expires_in": PASSWORDLESS_TTL
        }

    @transaction.atomic
    def verify_mfa_otp(
        self,
        sso_session: SSOSession,
        client: SystemClient,
        challenge_id: str,
        code: str,
        ip_address: str = "",
    ) -> None:
        user = sso_session.user
        try:
            challenge = (
                PasswordlessChallenge.objects
                .select_related("identifier", "client")
                .get(
                    id=challenge_id,
                    user=user,
                    purpose=PasswordlessChallenge.Purpose.MFA,
                    is_used=False,
                )
            )
        except PasswordlessChallenge.DoesNotExist:
            raise InvalidMFAOperationError("Invalid or expired code.")

        if challenge.client != client:
            raise InvalidMFAOperationError("Invalid client for this verification request.")
        if challenge.is_expired():
            raise InvalidMFAOperationError("Code has expired. Please request a new one.")

        submitted_hash = hash_value(code)
        if not hmac.compare_digest(submitted_hash, challenge.code_hash):
            challenge.attempts += 1
            if challenge.attempts >= MAX_OTP_ATTEMPTS:
                challenge.is_used = True
            challenge.save(update_fields=["attempts", "is_used"])
            remaining = max(0, MAX_OTP_ATTEMPTS - challenge.attempts)
            if remaining == 0:
                raise InvalidMFAOperationError("Too many incorrect attempts. Please request a new code.")
            raise InvalidMFAOperationError(f"Incorrect code. {remaining} attempt(s) remaining.")

        challenge.is_used = True
        challenge.used_at = timezone.now()
        challenge.ip_verified = ip_address or None
        challenge.save(update_fields=["is_used", "used_at", "ip_verified"])

        mfa_method_str = (
            MFAMethod.SMS
            if challenge.identifier.identifier_type == IdentifierType.PHONE
            else MFAMethod.EMAIL
        )

        SSOSessionMFAVerification.objects.create(
            session=sso_session,
            method=mfa_method_str,
            ip_address=challenge.ip_verified,
            system=client.system,
        )

        if challenge.user_mfa:
            challenge.user_mfa.last_used_at = timezone.now()
            challenge.user_mfa.save(update_fields=["last_used_at"])

        self._audit(
            user,
            AuditEventType.MFA_VERIFIED,
            {"method": mfa_method_str, "system_id": str(client.system.id)},
            ip_address
        )

    @staticmethod
    def _initiate_totp_enrollment(user: User, device_name: str, pending_enrollment_id: Optional[str]) -> dict:
        secret = pyotp.random_base32()
        temp_mfa = UserMFA.objects.create(
            user=user,
            method=MFAMethod.TOTP,
            is_active=False,
            secret=secret,
            device_name=device_name or "Authenticator App",
        )
        provisioning_uri = pyotp.TOTP(secret).provisioning_uri(
            name=user.get_email() or str(user.id),
            issuer_name=getattr(settings, "MFA_ISSUER_NAME", "Authenticator App"),
        )
        return {
            "method": MFAMethod.TOTP,
            "temp_mfa_id": str(temp_mfa.id),
            "secret": secret,
            "provisioning_uri": provisioning_uri,
            "expires_in": 900,
            "pending_enrollment_id": pending_enrollment_id,
        }

    def _initiate_otp_enrollment(
            self,
            user: User,
            method: str,
            delivery_target: str,
            client: Optional[SystemClient],
            ip_address: str,
            pending_enrollment_id: Optional[str],
    ) -> dict:
        id_type = IdentifierType.PHONE if method == MFAMethod.SMS else IdentifierType.EMAIL
        identifier = user.identifiers.filter(identifier_type=id_type, disassociated_at__isnull=True).first()
        if not identifier:
            raise InvalidMFAOperationError(f"No active {id_type} identifier found for enrollment.")

        send_to = delivery_target or identifier.value
        self._rate_limit_otp(send_to, ip_address)

        raw_code  = generate_otp()
        code_hash = hash_value(raw_code)

        challenge = PasswordlessChallenge.objects.create(
            user=user,
            identifier=identifier,
            client=client,
            purpose=PasswordlessChallenge.Purpose.VERIFY,
            code_hash=code_hash,
            expires_at=timezone.now() + timedelta(seconds=PASSWORDLESS_TTL),
            ip_requested=ip_address or None,
        )

        NotificationService.deliver_otp(
            identifier=identifier,
            raw_code=raw_code,
            system=client.system if client else None,
            delivery_target=delivery_target
        )

        self._audit(
            user,
            AuditEventType.MFA_ENROLLMENT_INITIATED,
            {"method": method, "type": id_type}
        )

        return {
            "challenge_id": str(challenge.id),
            "masked_destination": mask(send_to),
            "expires_in": PASSWORDLESS_TTL,
            "method": method,
            "pending_enrollment_id": pending_enrollment_id,
        }

    def _initiate_backup_enrollment(self, user: User, pending_enrollment_id: Optional[str]) -> dict:
        codes = self.generate_backup_codes(user, count=10)
        return {
            "method": MFAMethod.BACKUP,
            "backup_codes": codes,
            "pending_enrollment_id": pending_enrollment_id
        }

    def _verify_totp_enrollment(self, user, data, ip_address, pending_enrollment_id) -> MFAEnrollmentResult:
        try:
            temp_mfa = UserMFA.objects.get(
                id=data.get("temp_mfa_id"),
                user=user,
                method=MFAMethod.TOTP,
                is_active=False
            )
        except UserMFA.DoesNotExist:
            raise InvalidMFAOperationError("TOTP enrollment session expired or invalid.")

        if not pyotp.TOTP(temp_mfa.secret).verify(data.get("code", ""), valid_window=1):
            raise InvalidMFAOperationError("Invalid TOTP code.")

        temp_mfa.is_active = True
        temp_mfa.verified_at = timezone.now()
        temp_mfa.last_used_at = timezone.now()
        temp_mfa.save(update_fields=["is_active", "verified_at", "last_used_at"])

        self._complete_pending_enrollment(user, pending_enrollment_id)
        self._audit(user, AuditEventType.MFA_ENROLLED, {"method": MFAMethod.TOTP}, ip_address)
        return MFAEnrollmentResult(mfa=temp_mfa)

    def _verify_otp_enrollment(self, user, method, data, ip_address, pending_enrollment_id) -> MFAEnrollmentResult:
        try:
            challenge = PasswordlessChallenge.objects.select_related("identifier").get(
                id=data.get("challenge_id"),
                user=user,
                purpose=PasswordlessChallenge.Purpose.VERIFY,
                is_used=False,
            )
        except PasswordlessChallenge.DoesNotExist:
            raise InvalidMFAOperationError("Invalid or expired verification code.")

        if challenge.is_expired():
            raise InvalidMFAOperationError("Verification code has expired.")

        submitted_hash = hash_value(data.get("code", ""))
        if not hmac.compare_digest(submitted_hash, challenge.code_hash):
            challenge.attempts += 1
            if challenge.attempts >= MAX_OTP_ATTEMPTS:
                challenge.is_used = True
            challenge.save(update_fields=["attempts", "is_used"])
            remaining = max(0, MAX_OTP_ATTEMPTS - challenge.attempts)
            if remaining == 0:
                raise InvalidMFAOperationError("Too many incorrect attempts.")
            raise InvalidMFAOperationError(f"Incorrect code. {remaining} attempt(s) remaining.")

        challenge.is_used = True
        challenge.used_at = timezone.now()
        challenge.ip_verified = ip_address or None
        challenge.save(update_fields=["is_used", "used_at", "ip_verified"])

        mfa = UserMFA.objects.create(
            user=user,
            method=method,
            is_active=True,
            verified_at=timezone.now(),
            last_used_at=timezone.now(),
            delivery_target=challenge.identifier.value,
            device_name=data.get("device_name", "") or f"{method.upper()} MFA",
        )

        self._complete_pending_enrollment(user, pending_enrollment_id)
        self._audit(user, AuditEventType.MFA_ENROLLED, {"method": method}, ip_address)
        return MFAEnrollmentResult(mfa=mfa)

    def _mark_backup_enrolled(self, user, ip_address, pending_enrollment_id) -> UserMFA:
        if not BackupCode.objects.filter(user=user, is_used=False, invalidated_at__isnull=True).exists():
            raise InvalidMFAOperationError("No backup codes generated yet.")

        mfa = UserMFA.objects.create(
            user=user,
            method=MFAMethod.BACKUP,
            is_active=True,
            verified_at=timezone.now(),
            last_used_at=timezone.now(),
            device_name="Backup Codes",
        )

        self._complete_pending_enrollment(user, pending_enrollment_id)
        self._audit(user, AuditEventType.MFA_ENROLLED, {"method": MFAMethod.BACKUP}, ip_address)
        return mfa

    @staticmethod
    def _complete_pending_enrollment(user: User, pending_id: Optional[str]):
        if not pending_id:
            return
        try:
            pending = PendingMFAEnrollment.objects.get(
                id=pending_id,
                session__user=user,
                completed_at__isnull=True
            )
            pending.completed_at = timezone.now()
            pending.save(update_fields=["completed_at"])
        except PendingMFAEnrollment.DoesNotExist:
            pass

    def _rate_limit_otp(self, destination: str, ip_address: str):
        detected_type = detect_identifier_type(destination)
        normalised = self._normaliser.normalise(destination,detected_type)

        window = timezone.now() - timedelta(minutes=10)
        count = PasswordlessChallenge.objects.filter(
            identifier__value_normalised=normalised,
            created_at__gte=window,
            purpose=PasswordlessChallenge.Purpose.VERIFY,
        ).count()
        if count >= 5:
            raise MFARateLimitExceededError(
                "Too many verification codes requested. Please wait a few minutes."
            )

        if ip_address:
            ip_count = PasswordlessChallenge.objects.filter(
                ip_requested=ip_address,
                created_at__gte=timezone.now() - timedelta(hours=1),
            ).count()
            if ip_count >= 10:
                raise MFARateLimitExceededError(
                    "Too many requests from this IP. Try again later."
                )

    def _validate_mfa_code(self, mfa_entry: UserMFA, code: str, method: str) -> bool:
        if method == MFAMethod.TOTP:
            return pyotp.TOTP(mfa_entry.secret).verify(code, valid_window=1)
        if method == MFAMethod.BACKUP:
            return self._verify_backup_code(mfa_entry.user, code)
        raise NotImplementedError(f"Method '{method}' must be verified via its OTP challenge flow.")

    @staticmethod
    def _verify_backup_code(user: User, raw_code: str) -> bool:
        for bc in BackupCode.objects.filter(user=user, is_used=False, invalidated_at__isnull=True):
            if bcrypt.checkpw(raw_code.encode(), bc.code_hash.encode()):
                bc.is_used = True
                bc.used_at = timezone.now()
                bc.save(update_fields=["is_used", "used_at"])
                return True
        return False

    @staticmethod
    def _audit(
            user: User,
            action: str,
            payload: Optional[dict] = None,
            ip_address: str = "",
            outcome: str = "success"
    ):
        AuditLog.objects.create(
            event_type=action,
            actor_user_id=user.id,
            actor_email=user.get_email() or "",
            actor_ip=ip_address or None,
            payload=payload or {},
            outcome=outcome,
        )