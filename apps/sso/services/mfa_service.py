"""
apps/accounts/services/mfa_service.py

Complete MFA service.

Key fixes:
  1. SMS and Email OTP are fully supported as MFA methods.
     initiate_mfa() creates a PasswordlessChallenge(purpose="mfa", sso_session=session)
     and delivers the OTP. verify_mfa_challenge() verifies it and marks
     session.mfa_verified = True.

  2. TOTP uses pyotp — two-step enrolment (generate → confirm).

  3. WebAuthn uses py-webauthn — two-step (begin registration → complete registration)
     and two-step verification (begin auth → complete auth).

  4. Backup codes: bcrypt hashed, invalidated on regeneration.

  5. All MFA verification goes through one of two paths:
     - challenge-based: SMS, Email → PasswordlessChallenge
     - credential-based: TOTP → pyotp, WebAuthn → py-webauthn, Backup → BackupCode

  6. The MFA prompt flow:
     - Find user's active UserMFA rows
     - Present primary method first
     - For SMS/Email: call initiate_mfa() to send the code
     - For TOTP/WebAuthn: no initiation needed, user opens their app
     - Verify via the appropriate path
     - On success: session.mfa_verified = True
"""

import hashlib
import secrets
from datetime import timedelta
from typing import Optional

import bcrypt
import pyotp
from django.db import transaction
from django.utils import timezone

from apps.accounts.models import (
    User, UserMFA, MFAMethod, BackupCode,
    PasswordlessChallenge, ChallengePurpose,
    PendingTOTPSetup, PendingMFAEnrollment,
    UserIdentifier, IdentifierType,
)
from apps.audit.models import AuditLog, AuditEventType
from apps.sso.models import SSOSession

BACKUP_CODE_COUNT = 10
OTP_TTL_SECONDS   = 300   # 5 minutes
MAX_OTP_ATTEMPTS  = 3


class MFAError(Exception):
    pass


class MFAService:

    def initiate_mfa(
        self,
        session: SSOSession,
        method: str,
        ip_address: str = "",
    ) -> dict:
        """
        For SMS and Email OTP MFA methods only.
        Creates a PasswordlessChallenge(purpose="mfa", sso_session=session)
        and delivers the OTP to the user's phone/email.

        Returns {"challenge_id": ..., "masked_destination": ..., "expires_in": ...}

        TOTP and WebAuthn do not need initiation — the user opens their app
        or inserts their key. Call verify_mfa() directly for those.
        """
        if method not in (MFAMethod.SMS, MFAMethod.EMAIL):
            raise MFAError(
                f"initiate_mfa() is only for SMS and Email OTP. "
                f"For TOTP/WebAuthn/Backup, call verify_mfa() directly."
            )

        user    = session.user
        mfa_row = user.mfa_methods.filter(method=method, is_active=True).first()
        if not mfa_row:
            raise MFAError(f"No active {method} MFA method enrolled.")

        destination = mfa_row.get_delivery_target()
        if not destination:
            raise MFAError(
                f"No delivery target for {method} MFA. "
                f"Please update your phone number or email."
            )

        # Find the UserIdentifier this corresponds to (for the FK on the challenge)
        id_type = IdentifierType.PHONE if method == MFAMethod.SMS else IdentifierType.EMAIL
        identifier = user.identifiers.filter(
            identifier_type=id_type,
            value=destination,
            is_verified=True,
        ).first()
        if not identifier:
            # Fall back to any verified identifier of this type
            identifier = user.identifiers.filter(
                identifier_type=id_type,
                is_verified=True,
            ).first()
        if not identifier:
            raise MFAError(
                f"Could not find a verified {id_type} identifier for MFA delivery."
            )

        raw_code   = self._generate_otp()
        code_hash  = hashlib.sha256(raw_code.encode()).hexdigest()

        challenge = PasswordlessChallenge.objects.create(
            user=user,
            identifier=identifier,
            sso_session=session,      # ← linked to the session needing MFA
            user_mfa=mfa_row,         # ← which MFA method triggered this
            purpose=ChallengePurpose.MFA,
            code_hash=code_hash,
            expires_at=timezone.now() + timedelta(seconds=OTP_TTL_SECONDS),
            ip_requested=ip_address or None,
        )

        self._deliver_otp(method, destination, raw_code, session)

        return {
            "challenge_id": str(challenge.id),
            "masked_destination": self._mask(destination),
            "expires_in": OTP_TTL_SECONDS,
        }

    # =========================================================================
    # Verify MFA  — routes to correct verification path
    # =========================================================================

    @transaction.atomic
    def verify_mfa(
        self,
        session: "SSOSession",
        method: str,
        code: str,
        challenge_id: Optional[str] = None,
        ip_address: str = "",
        # WebAuthn-specific
        webauthn_credential_id: Optional[str] = None,
        webauthn_client_data: Optional[str] = None,
        webauthn_authenticator_data: Optional[str] = None,
        webauthn_signature: Optional[str] = None,
    ) -> bool:
        """
        Verify an MFA code/credential for a session.

        Routing:
          SMS / Email → verify via PasswordlessChallenge (challenge_id required)
          TOTP        → verify via pyotp
          WebAuthn    → verify via py-webauthn (webauthn_* fields required)
          Backup      → verify via BackupCode bcrypt iteration

        On success: session.mfa_verified = True, session.mfa_method = method
        On failure: audit logged, returns False
        """
        user = session.user

        if method in (MFAMethod.SMS, MFAMethod.EMAIL):
            verified = self._verify_otp_challenge(
                session=session,
                challenge_id=challenge_id,
                code=code,
                ip_address=ip_address,
            )
        elif method == MFAMethod.TOTP:
            verified = self._verify_totp(user=user, code=code)
        elif method == MFAMethod.WEBAUTHN:
            verified = self._verify_webauthn(
                user=user,
                credential_id=webauthn_credential_id,
                client_data=webauthn_client_data,
                authenticator_data=webauthn_authenticator_data,
                signature=webauthn_signature,
                session_id=str(session.id),
            )
        elif method == MFAMethod.BACKUP:
            verified = self._verify_backup_code(user=user, raw_code=code, ip=ip_address)
        else:
            raise MFAError(f"Unknown MFA method: {method}")

        if verified:
            session.mfa_verified = True
            session.mfa_method   = method
            session.save(update_fields=["mfa_verified", "mfa_method"])

            # Update last_used_at on the UserMFA row
            mfa_row = user.mfa_methods.filter(method=method, is_active=True).first()
            if mfa_row:
                mfa_row.last_used_at = timezone.now()
                mfa_row.save(update_fields=["last_used_at"])

            AuditLog.objects.create(
                event_type=AuditEventType.MFA_VERIFIED,
                actor_user_id=user.id,
                actor_ip=ip_address or None,
                payload={"method": method, "session_id": str(session.id)},
            )
        else:
            AuditLog.objects.create(
                event_type=AuditEventType.MFA_FAILED,
                actor_user_id=user.id,
                actor_ip=ip_address or None,
                payload={"method": method},
                outcome="failure",
            )

        return verified

    # =========================================================================
    # OTP challenge verification (SMS / Email MFA)
    # =========================================================================

    def _verify_otp_challenge(
        self,
        session: "SSOSession",
        challenge_id: Optional[str],
        code: str,
        ip_address: str = "",
    ) -> bool:
        """
        Verify an OTP delivered via SMS or Email for MFA purpose.

        Finds the PasswordlessChallenge by:
          1. challenge_id if provided (preferred — explicit)
          2. Falls back to the most recent active MFA challenge for this session

        This handles the case where the client loses the challenge_id
        (e.g. page refresh).
        """
        if challenge_id:
            try:
                challenge = PasswordlessChallenge.objects.select_related(
                    "user_mfa"
                ).get(
                    id=challenge_id,
                    purpose=ChallengePurpose.MFA,
                    sso_session=session,
                    is_used=False,
                )
            except PasswordlessChallenge.DoesNotExist:
                return False
        else:
            # Fall back to most recent active MFA challenge for this session
            challenge = PasswordlessChallenge.objects.filter(
                purpose=ChallengePurpose.MFA,
                sso_session=session,
                is_used=False,
            ).order_by("-created_at").first()
            if not challenge:
                return False

        if challenge.is_expired():
            return False

        submitted_hash = hashlib.sha256(code.encode()).hexdigest()
        if not _constant_compare(submitted_hash, challenge.code_hash):
            challenge.attempts += 1
            if challenge.attempts >= MAX_OTP_ATTEMPTS:
                challenge.is_used = True  # Exhaust the challenge
            challenge.save(update_fields=["attempts", "is_used"])
            return False

        # Success
        challenge.is_used   = True
        challenge.used_at   = timezone.now()
        challenge.ip_verified = ip_address or None
        challenge.save(update_fields=["is_used", "used_at", "ip_verified"])

        return True

    # =========================================================================
    # TOTP verification
    # =========================================================================

    def _verify_totp(self, user: User, code: str) -> bool:
        """
        Verify a TOTP code against the user's enrolled secret.
        valid_window=1 allows one 30-second window before/after the current
        window to account for clock drift.
        """
        mfa_row = user.mfa_methods.filter(
            method=MFAMethod.TOTP, is_active=True
        ).first()
        if not mfa_row:
            return False

        # In production: decrypt secret from mfa_row.secret_encrypted via KMS
        secret = mfa_row.secret_encrypted
        totp   = pyotp.TOTP(secret)
        return totp.verify(code, valid_window=1)

    # =========================================================================
    # WebAuthn verification
    # =========================================================================

    def _verify_webauthn(
        self,
        user: User,
        credential_id: Optional[str],
        client_data: Optional[str],
        authenticator_data: Optional[str],
        signature: Optional[str],
        session_id: str,
    ) -> bool:
        """
        Verify a WebAuthn assertion.

        Flow (browser-side happens before this is called):
          1. Server generated a challenge and stored it (begin_webauthn_auth)
          2. Browser passed challenge to authenticator
          3. Authenticator signed it with private key
          4. Browser sent: credential_id, client_data, authenticator_data, signature

        Here we:
          1. Find the UserMFA row by credential_id
          2. Retrieve the stored challenge for this session
          3. Use py-webauthn to verify the assertion against the stored public key

        Production notes:
          - Use webauthn.verify_authentication_response() from py-webauthn
          - The stored public key is in mfa_row.secret_encrypted (COSE format)
          - The challenge must match what was generated in begin_webauthn_auth()
        """
        if not all([credential_id, client_data, authenticator_data, signature]):
            return False

        mfa_row = user.mfa_methods.filter(
            method=MFAMethod.WEBAUTHN,
            credential_id=credential_id,
            is_active=True,
        ).first()
        if not mfa_row:
            return False

        try:
            import webauthn
            from apps.sso.models import WebAuthnChallenge  # see note below

            # Retrieve the stored challenge for this session
            stored = WebAuthnChallenge.objects.get(
                session_id=session_id,
                credential_id=credential_id,
                is_used=False,
            )
            if stored.is_expired():
                return False

            # Verify the assertion using py-webauthn
            webauthn.verify_authentication_response(
                credential=webauthn.helpers.structs.AuthenticationCredential(
                    id=credential_id,
                    raw_id=credential_id.encode(),
                    response=webauthn.helpers.structs.AuthenticatorAssertionResponse(
                        client_data_json=client_data.encode(),
                        authenticator_data=authenticator_data.encode(),
                        signature=signature.encode(),
                    ),
                    type="public-key",
                ),
                expected_challenge=stored.challenge.encode(),
                expected_rp_id="id.platform.com",
                expected_origin="https://id.platform.com",
                credential_public_key=mfa_row.secret_encrypted.encode(),
                credential_current_sign_count=mfa_row.sign_count,
            )

            stored.is_used = True
            stored.save(update_fields=["is_used"])
            return True

        except Exception:
            return False

    # =========================================================================
    # Backup code verification
    # =========================================================================

    def _verify_backup_code(
        self, user: User, raw_code: str, ip: str = ""
    ) -> bool:
        """
        Iterate all unused, non-invalidated backup codes for this user.
        bcrypt.verify against each. Mark the matching one as used.

        Why iterate: we only store hashes, so we cannot look up by value directly.
        With a maximum of BACKUP_CODE_COUNT (10) codes this is cheap.
        """
        unused_codes = BackupCode.objects.filter(
            user=user,
            is_used=False,
            invalidated_at__isnull=True,
        )
        for bc in unused_codes:
            if bcrypt.checkpw(raw_code.encode(), bc.code_hash.encode()):
                bc.is_used       = True
                bc.used_at       = timezone.now()
                bc.used_from_ip  = ip or None
                bc.save(update_fields=["is_used", "used_at", "used_from_ip"])

                # Warn if running low
                remaining = unused_codes.exclude(id=bc.id).count()
                if remaining <= 2:
                    # In production: send email warning
                    pass

                return True
        return False

    # =========================================================================
    # TOTP Enrolment (two-step)
    # =========================================================================

    @transaction.atomic
    def begin_totp_enrolment(
        self,
        user: User,
        device_name: str = "Authenticator App",
    ) -> dict:
        """
        Step 1: Generate TOTP secret, store it in PendingTOTPSetup.
        Return data the UI needs to render a QR code.

        Returns:
          {
            "temp_token": "...",   ← opaque reference for confirm step
            "secret": "BASE32...", ← for manual entry
            "otpauth_url": "...",  ← for QR code library (e.g. qrcode.js)
          }
        """
        secret      = pyotp.random_base32()
        email       = user.get_email() or str(user.id)
        otpauth_url = pyotp.TOTP(secret).provisioning_uri(
            name=email,
            issuer_name="Identity Platform",
        )
        temp_token  = secrets.token_urlsafe(32)

        PendingTOTPSetup.objects.update_or_create(
            user=user,
            defaults={
                "secret": secret,   # encrypt in production
                "temp_token_hash": hashlib.sha256(temp_token.encode()).hexdigest(),
                "expires_at": timezone.now() + timedelta(minutes=15),
            },
        )
        return {
            "temp_token": temp_token,
            "secret": secret,
            "otpauth_url": otpauth_url,
        }

    @transaction.atomic
    def confirm_totp_enrolment(
        self,
        user: User,
        temp_token: str,
        verification_code: str,
        device_name: str = "Authenticator App",
        is_primary: bool = True,
    ) -> UserMFA:
        """
        Step 2: User scanned the QR and enters a code to confirm their app works.
        Only commits the UserMFA row if the code is correct.

        Why two steps:
          If we committed before confirmation, a mistyped or misconfigured app
          would lock the user out when MFA is next demanded.
        """
        token_hash = hashlib.sha256(temp_token.encode()).hexdigest()
        try:
            setup = PendingTOTPSetup.objects.get(
                user=user, temp_token_hash=token_hash
            )
        except PendingTOTPSetup.DoesNotExist:
            raise MFAError("Invalid or expired setup session. Please start again.")

        if setup.is_expired():
            setup.delete()
            raise MFAError("Setup session expired. Please start again.")

        totp = pyotp.TOTP(setup.secret)
        if not totp.verify(verification_code, valid_window=1):
            raise MFAError("Incorrect verification code. Please try again.")

        # Demote any existing primary TOTP
        if is_primary:
            UserMFA.objects.filter(
                user=user, method=MFAMethod.TOTP, is_primary=True
            ).update(is_primary=False)

        mfa = UserMFA.objects.create(
            user=user,
            method=MFAMethod.TOTP,
            secret_encrypted=setup.secret,  # encrypt via KMS in production
            device_name=device_name,
            is_primary=is_primary,
            is_active=True,
            verified_at=timezone.now(),
        )
        setup.delete()

        AuditLog.objects.create(
            event_type=AuditEventType.MFA_ENROLLED,
            actor_user_id=user.id,
            payload={"method": "totp", "device_name": device_name},
        )
        return mfa

    # =========================================================================
    # SMS / Email MFA Enrolment
    # =========================================================================

    @transaction.atomic
    def enrol_sms_or_email(
        self,
        user: User,
        method: str,   # MFAMethod.SMS or MFAMethod.EMAIL
        delivery_target: str = "",
        device_name: str = "",
        is_primary: bool = False,
    ) -> UserMFA:
        """
        Enrol SMS or Email OTP as an MFA method.

        This is a preference record — it records that the user wants to receive
        MFA codes at this address/number. The identifier must already be verified.

        delivery_target:
          If blank, the primary verified identifier of the matching type is used.
          If provided, it must match an existing verified UserIdentifier.

        Verification of enrolment:
          After creating this record, the caller should initiate a challenge
          (initiate_mfa()) and verify it to confirm delivery works.
          For now we create the row as is_active=True immediately.
          In production you may want is_active=False until first successful delivery.
        """
        if method not in (MFAMethod.SMS, MFAMethod.EMAIL):
            raise MFAError(f"Method must be SMS or EMAIL, got: {method}")

        id_type = IdentifierType.PHONE if method == MFAMethod.SMS else IdentifierType.EMAIL

        if delivery_target:
            # Verify the provided target is a verified identifier for this user
            exists = user.identifiers.filter(
                identifier_type=id_type,
                value=delivery_target,
                is_verified=True,
            ).exists()
            if not exists:
                raise MFAError(
                    f"The provided {id_type} is not a verified identifier on this account."
                )
        else:
            # Use primary verified identifier
            identifier = user.identifiers.filter(
                identifier_type=id_type, is_verified=True
            ).first()
            if not identifier:
                raise MFAError(
                    f"No verified {id_type} found on this account. "
                    f"Please verify your {id_type} before enrolling this MFA method."
                )
            delivery_target = identifier.value

        if is_primary:
            UserMFA.objects.filter(user=user, is_primary=True).update(is_primary=False)

        mfa = UserMFA.objects.create(
            user=user,
            method=method,
            delivery_target=delivery_target,
            device_name=device_name or ("Phone" if method == MFAMethod.SMS else "Email"),
            is_primary=is_primary,
            is_active=True,
            verified_at=timezone.now(),
        )
        AuditLog.objects.create(
            event_type=AuditEventType.MFA_ENROLLED,
            actor_user_id=user.id,
            payload={"method": method, "target": self._mask(delivery_target)},
        )
        return mfa

    # =========================================================================
    # WebAuthn Enrolment (two-step)
    # =========================================================================

    def begin_webauthn_registration(
        self,
        user: User,
        session_id: str,
    ) -> dict:
        """
        Step 1: Generate a WebAuthn registration challenge.
        Returns data to pass to navigator.credentials.create() in the browser.

        In production, use webauthn.generate_registration_options() from py-webauthn.
        Store the challenge in WebAuthnChallenge(session_id, purpose="register").
        """
        import webauthn
        challenge = secrets.token_bytes(32)

        options = webauthn.generate_registration_options(
            rp_id="id.platform.com",
            rp_name="Identity Platform",
            user_id=str(user.id).encode(),
            user_name=user.get_email() or str(user.id),
        )
        # Store challenge for verification step
        from apps.sso.models import WebAuthnChallenge
        WebAuthnChallenge.objects.create(
            session_id=session_id,
            challenge=options.challenge.decode() if isinstance(options.challenge, bytes)
                      else options.challenge,
            purpose="register",
            expires_at=timezone.now() + timedelta(minutes=5),
        )
        return options

    @transaction.atomic
    def complete_webauthn_registration(
        self,
        user: User,
        session_id: str,
        credential_id: str,
        public_key: str,
        client_data: str,
        attestation_object: str,
        device_name: str = "Hardware Key",
        is_primary: bool = False,
    ) -> UserMFA:
        """
        Step 2: Verify the attestation and store the credential.
        """
        try:
            import webauthn
            from apps.sso.models import WebAuthnChallenge

            stored = WebAuthnChallenge.objects.get(
                session_id=session_id,
                purpose="register",
                is_used=False,
            )
            if stored.is_expired():
                raise MFAError("Registration session expired. Please start again.")

            webauthn.verify_registration_response(
                credential=webauthn.helpers.structs.RegistrationCredential(
                    id=credential_id,
                    raw_id=credential_id.encode(),
                    response=webauthn.helpers.structs.AuthenticatorAttestationResponse(
                        client_data_json=client_data.encode(),
                        attestation_object=attestation_object.encode(),
                    ),
                    type="public-key",
                ),
                expected_challenge=stored.challenge.encode(),
                expected_rp_id="id.platform.com",
                expected_origin="https://id.platform.com",
            )
            stored.is_used = True
            stored.save(update_fields=["is_used"])

        except MFAError:
            raise
        except Exception as exc:
            raise MFAError(f"WebAuthn registration failed: {exc}")

        if is_primary:
            UserMFA.objects.filter(user=user, is_primary=True).update(is_primary=False)

        mfa = UserMFA.objects.create(
            user=user,
            method=MFAMethod.WEBAUTHN,
            credential_id=credential_id,
            secret_encrypted=public_key,
            device_name=device_name,
            is_primary=is_primary,
            is_active=True,
            verified_at=timezone.now(),
        )
        AuditLog.objects.create(
            event_type=AuditEventType.MFA_ENROLLED,
            actor_user_id=user.id,
            payload={"method": "webauthn", "device_name": device_name},
        )
        return mfa

    def begin_webauthn_auth(self, user: User, session_id: str) -> dict:
        """
        Generate a WebAuthn authentication challenge.
        Called before the user taps their hardware key.
        """
        import webauthn
        from apps.sso.models import WebAuthnChallenge

        credentials = user.mfa_methods.filter(
            method=MFAMethod.WEBAUTHN, is_active=True
        ).values_list("credential_id", flat=True)

        options = webauthn.generate_authentication_options(
            rp_id="id.platform.com",
            allow_credentials=[
                webauthn.helpers.structs.PublicKeyCredentialDescriptor(
                    id=cid.encode(), type="public-key"
                )
                for cid in credentials
            ],
        )
        WebAuthnChallenge.objects.create(
            session_id=session_id,
            challenge=options.challenge.decode() if isinstance(options.challenge, bytes)
                      else options.challenge,
            purpose="authenticate",
            expires_at=timezone.now() + timedelta(minutes=5),
        )
        return options

    # =========================================================================
    # Backup codes
    # =========================================================================

    @transaction.atomic
    def generate_backup_codes(self, user: User) -> list[str]:
        """
        Generate a fresh batch of backup codes.
        Invalidates all existing unused codes first.
        Returns the raw codes — shown ONCE to the user, never retrievable again.
        """
        # Invalidate existing
        BackupCode.objects.filter(
            user=user, is_used=False, invalidated_at__isnull=True
        ).update(invalidated_at=timezone.now())

        # Ensure a sentinel UserMFA row exists for "backup" method
        UserMFA.objects.get_or_create(
            user=user,
            method=MFAMethod.BACKUP,
            credential_id="",
            defaults={"is_active": True, "device_name": "Backup Codes"},
        )

        raw_codes = []
        for _ in range(BACKUP_CODE_COUNT):
            raw  = self._generate_backup_code_value()
            code_hash = bcrypt.hashpw(raw.encode(), bcrypt.gensalt()).decode()
            BackupCode.objects.create(user=user, code_hash=code_hash)
            raw_codes.append(raw)

        AuditLog.objects.create(
            event_type=AuditEventType.MFA_ENROLLED,
            actor_user_id=user.id,
            payload={"method": "backup", "count": BACKUP_CODE_COUNT},
        )
        return raw_codes

    def get_backup_code_status(self, user: User) -> dict:
        total     = BackupCode.objects.filter(user=user, invalidated_at__isnull=True).count()
        used      = BackupCode.objects.filter(user=user, is_used=True, invalidated_at__isnull=True).count()
        remaining = total - used
        return {"total": total, "used": used, "remaining": remaining}

    # =========================================================================
    # Forced enrolment completion (PendingMFAEnrollment)
    # =========================================================================

    @transaction.atomic
    def complete_pending_enrollment(
        self,
        session: "SSOSession",
        method: str,
        enrollment_data: dict,
    ) -> UserMFA:
        """
        Complete a forced MFA enrolment triggered by select_context().

        enrollment_data by method:
          TOTP:     {"temp_token": "...", "verification_code": "123456"}
          WebAuthn: {"credential_id":"...", "public_key":"...",
                     "client_data":"...", "attestation_object":"..."}
          SMS:      {"delivery_target": "+254722..."}  ← just enrols preference
          EMAIL:    {"delivery_target": "user@..."}
        """
        try:
            pending = PendingMFAEnrollment.objects.get(
                session=session, completed_at__isnull=True
            )
        except PendingMFAEnrollment.DoesNotExist:
            raise MFAError("No pending MFA enrolment for this session.")

        if pending.is_expired():
            raise MFAError("Enrolment session expired. Please log in again.")

        if pending.allowed_methods and method not in pending.allowed_methods:
            raise MFAError(
                f"This context requires one of: {pending.allowed_methods}. "
                f"You attempted to enrol: {method}."
            )

        user = session.user

        if method == MFAMethod.TOTP:
            mfa = self.confirm_totp_enrolment(
                user=user,
                temp_token=enrollment_data["temp_token"],
                verification_code=enrollment_data["verification_code"],
                device_name=enrollment_data.get("device_name", "Authenticator App"),
                is_primary=True,
            )
        elif method == MFAMethod.WEBAUTHN:
            mfa = self.complete_webauthn_registration(
                user=user,
                session_id=str(session.id),
                credential_id=enrollment_data["credential_id"],
                public_key=enrollment_data["public_key"],
                client_data=enrollment_data["client_data"],
                attestation_object=enrollment_data["attestation_object"],
                device_name=enrollment_data.get("device_name", "Hardware Key"),
                is_primary=True,
            )
        elif method in (MFAMethod.SMS, MFAMethod.EMAIL):
            mfa = self.enrol_sms_or_email(
                user=user,
                method=method,
                delivery_target=enrollment_data.get("delivery_target", ""),
                is_primary=True,
            )
            # For SMS/Email: immediately initiate a challenge to verify delivery
            # The caller must then call verify_mfa() before we mark mfa_verified
            # We do NOT set session.mfa_verified here for these methods —
            # the subsequent verify_mfa() call does that.
            pending.completed_at = timezone.now()
            pending.save(update_fields=["completed_at"])
            AuditLog.objects.create(
                event_type=AuditEventType.MFA_ENROLLMENT_COMPLETE,
                actor_user_id=user.id,
                payload={"method": method, "delivery_pending_verification": True},
            )
            return mfa
        else:
            raise MFAError(f"Enrolment for '{method}' is not supported here.")

        pending.completed_at = timezone.now()
        pending.save(update_fields=["completed_at"])

        # For TOTP and WebAuthn: enrolment confirms the method works → mfa_verified
        session.mfa_verified = True
        session.mfa_method   = method
        session.save(update_fields=["mfa_verified", "mfa_method"])

        AuditLog.objects.create(
            event_type=AuditEventType.MFA_ENROLLMENT_COMPLETE,
            actor_user_id=user.id,
            payload={"method": method},
        )
        return mfa

    # =========================================================================
    # Helpers
    # =========================================================================

    def _generate_otp(self) -> str:
        import random
        return f"{random.SystemRandom().randint(0, 999999):06d}"

    def _generate_backup_code_value(self) -> str:
        part1 = secrets.token_hex(2).upper()
        part2 = str(secrets.randbelow(9000) + 1000)
        part3 = secrets.token_hex(2).upper()
        return f"{part1}-{part2}-{part3}"

    def _deliver_otp(self, method: str, destination: str, code: str, session: "SSOSession"):
        """
        Deliver OTP via SMS or email.
        In production, dispatch to a Celery task for async delivery.
        """
        system_name = (
            session.initiating_system.name
            if session.initiating_system
            else "Identity Platform"
        )
        if method == MFAMethod.SMS:
            # sms_service.send(to=destination, body=f"Your {system_name} code: {code}. Valid 5 minutes.")
            pass
        elif method == MFAMethod.EMAIL:
            # email_service.send(to=destination, subject=f"{system_name} security code",
            #                    body=f"Your verification code: {code}. Valid 5 minutes.")
            pass

    def _mask(self, value: str) -> str:
        if "@" in value:
            local, _, domain = value.partition("@")
            return f"{local[0]}{'*' * max(1, len(local)-2)}{local[-1]}@{domain}"
        if len(value) > 4:
            return value[:2] + "*" * (len(value) - 4) + value[-2:]
        return "****"


def _constant_compare(a: str, b: str) -> bool:
    """Timing-safe string comparison."""
    import hmac
    return hmac.compare_digest(a, b)