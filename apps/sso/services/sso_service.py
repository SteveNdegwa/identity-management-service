import hashlib
import hmac
import secrets
import uuid
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Optional

import bcrypt
import jwt
import pyotp
from django.conf import settings
from django.db import transaction
from django.utils import timezone

from apps.accounts.models import (
    User,
    UserIdentifier,
    IdentifierType,
    SystemUser,
    MFAMethod,
    UserMFA, BackupCode,
)
from apps.accounts.identifier_utils import IdentifierNormaliser, detect_identifier_type
from apps.organizations.models import OrganizationMembership
from apps.permissions.services.permission_resolver import PermissionResolverService
from apps.sso.models import (
    SSOSession,
    SSOSessionSystemAccess,
    AuthorizationCode,
    TokenSet,
    AccessToken,
    RefreshToken,
    MagicLink,
    LoginContextSelection, PasswordlessChallenge,
)
from apps.systems.models import SystemClient, System
from apps.audit.models import AuditLog, AuditEventType


ACCESS_TOKEN_TTL = getattr(settings, "SSO_ACCESS_TOKEN_TTL", 900)
REFRESH_TOKEN_TTL = getattr(settings, "SSO_REFRESH_TOKEN_TTL", 86400)
SSO_SESSION_TTL = getattr(settings, "SSO_SESSION_TTL", 604800)
AUTH_CODE_TTL = 120
MAGIC_LINK_TTL = 900
PASSWORDLESS_TTL = 300
JWT_ALGORITHM = getattr(settings, "SSO_JWT_ALGORITHM", "RS256")
MAX_OTP_ATTEMPTS  = 3


@dataclass
class LoginContext:
    system_user_id: str
    system_id: str
    system_name: str
    organization_id: Optional[str]
    organization_name: Optional[str]
    country_code: str
    country_name: str
    role_id: str
    role_name: str
    all_branches: bool
    branch_count: int


@dataclass
class TokenResponse:
    access_token: str
    refresh_token: str
    id_token: str
    token_type: str = "Bearer"
    expires_in: int = ACCESS_TOKEN_TTL
    scope: str = ""


@dataclass
class MFARequirement:
    required: bool
    reason: str
    allowed_methods: list = field(default_factory=list)


class AuthenticationError(Exception):
    pass


class OAuthError(Exception):
    def __init__(self, error: str, description: str = ""):
        self.error = error
        self.description = description
        super().__init__(f"{error}: {description}")


class MFARequiredError(Exception):
    def __init__(self, requirement: MFARequirement):
        self.requirement = requirement


class MFAEnrollmentRequiredError(Exception):
    def __init__(self, requirement: MFARequirement):
        self.requirement = requirement


class MFAMethodNotAcceptableError(Exception):
    def __init__(self, requirement: MFARequirement, used_method: str):
        self.requirement = requirement
        self.used_method = used_method


class SSOService:

    def __init__(self):
        self._perm = PermissionResolverService()
        self._normaliser = IdentifierNormaliser()

    @transaction.atomic
    def authenticate_password(
        self,
        login_value: str,
        password: str,
        client: SystemClient,
        ip_address: str = "",
        user_agent: str = "",
        device_id: str = "",
        device_name: str = "",
    ) -> SSOSession:
        system = client.system
        config = client.get_effective_config()

        if not config["allow_password_login"]:
            raise AuthenticationError(
                "Password login is not enabled for this system."
            )

        detected_type = detect_identifier_type(login_value)
        if config["allowed_login_identifier_types"] and \
                detected_type not in config["allowed_login_identifier_types"]:
            raise AuthenticationError(
                f"This system only accepts login via: "
                f"{config['allowed_login_identifier_types']}."
            )

        user = self._resolve_user_safe(login_value, detected_type)

        if user.is_locked():
            self._audit(
                AuditEventType.LOGIN_LOCKED,
                user,
                ip=ip_address,
                system=system,
                outcome="failure",
                payload={"locked_until": str(user.locked_until)}
            )
            raise AuthenticationError("Account is temporarily locked.")

        if not user.check_password(password):
            self._handle_failed_login(user, ip_address, system)
            raise AuthenticationError("Invalid credentials.")

        self._reset_lock(user)

        session = self._create_session(
            user=user,
            client=client,
            auth_method=SSOSession.AuthMethod.PASSWORD,
            ip_address=ip_address,
            user_agent=user_agent,
            device_id=device_id,
            device_name=device_name,
        )
        self._audit(
            AuditEventType.LOGIN_SUCCESS,
            user,
            ip=ip_address,
            system=system,
            payload={"session_id": str(session.id)}
        )
        return session

    def initiate_passwordless(
        self,
        login_value: str,
        client: SystemClient,
        ip_address: str = "",
    ) -> dict:
        system = client.system
        config = client.get_effective_config()

        if not config["allow_passwordless_login"]:
            raise AuthenticationError(
                "Passwordless login is not enabled for this system."
            )

        self._rate_limit_passwordless(login_value, ip_address)

        user, identifier = self._resolve_user_and_identifier_silent(login_value)
        if user is None:
            return {
                "challenge_id": None,
                "masked_destination": self._mask(login_value),
                "expires_in": PASSWORDLESS_TTL,
            }

        if user.is_locked():
            return {
                "challenge_id": None,
                "masked_destination": self._mask(login_value),
                "expires_in": PASSWORDLESS_TTL,
            }

        raw_code = self._generate_otp()
        code_hash = hashlib.sha256(raw_code.encode()).hexdigest()
        challenge = PasswordlessChallenge.objects.create(
            user=user,
            identifier=identifier,
            client=client,
            code_hash=code_hash,
            expires_at=timezone.now() + timedelta(seconds=PASSWORDLESS_TTL),
            ip_requested=ip_address or None,
        )

        self._deliver_otp(identifier, raw_code, system)

        self._audit(
            AuditEventType.PASSWORDLESS_INITIATED,
            user,
            ip=ip_address,
            system=system,
            payload={"type": identifier.identifier_type}
        )

        return {
            "challenge_id": str(challenge.id),
            "masked_destination": self._mask(identifier.value),
            "expires_in": PASSWORDLESS_TTL,
        }

    @transaction.atomic
    def verify_passwordless(
        self,
        challenge_id: str,
        code: str,
        client: SystemClient,
        ip_address: str = "",
        user_agent: str = "",
        device_id: str = "",
        device_name: str = "",
    ) -> SSOSession:
        try:
            challenge = PasswordlessChallenge.objects.select_related(
                "user", "identifier"
            ).get(id=challenge_id, is_used=False)
        except PasswordlessChallenge.DoesNotExist:
            raise AuthenticationError("Invalid or expired code.")

        if challenge.is_expired():
            raise AuthenticationError("Code has expired. Please request a new one.")

        submitted_hash = hashlib.sha256(code.encode()).hexdigest()
        if not hmac.compare_digest(submitted_hash, challenge.code_hash):
            challenge.attempts += 1
            if challenge.attempts >= MAX_OTP_ATTEMPTS:
                challenge.is_used = True
            challenge.save(update_fields=["attempts", "is_used"])

            remaining = max(0, MAX_OTP_ATTEMPTS - challenge.attempts)
            if remaining == 0:
                raise AuthenticationError(
                    "Too many incorrect attempts. Please request a new code."
                )
            raise AuthenticationError(
                f"Incorrect code. {remaining} attempt(s) remaining."
            )

        challenge.is_used = True
        challenge.used_at = timezone.now()
        challenge.ip_verified = ip_address or None
        challenge.save(update_fields=["is_used", "used_at", "ip_verified"])

        if not challenge.identifier.is_verified:
            challenge.identifier.is_verified = True
            challenge.identifier.verified_at = timezone.now()
            challenge.identifier.save(update_fields=["is_verified", "verified_at"])

        auth_method = (
            SSOSession.AuthMethod.SMS_OTP
            if challenge.identifier.identifier_type == IdentifierType.PHONE
            else SSOSession.AuthMethod.EMAIL_OTP
        )

        session = self._create_session(
            user=challenge.user,
            client=client,
            auth_method=auth_method,
            ip_address=ip_address,
            user_agent=user_agent,
            device_id=device_id,
            device_name=device_name,
            mfa_verified=True,
        )

        self._audit(
            AuditEventType.PASSWORDLESS_VERIFIED,
            challenge.user,
            ip=ip_address,
            system=client.system,
            payload={"session_id": str(session.id)}
        )

        return session

    def initiate_magic_link(
        self,
        email: str,
        client: SystemClient,
        redirect_uri: str,
        scopes: list,
        ip_address: str = "",
    ) -> dict:
        config = client.get_effective_config()
        if not config["allow_magic_link_login"]:
            raise AuthenticationError(
                "Magic link login is not enabled for this system."
            )

        self._rate_limit_magic_link(email, ip_address)

        user, identifier = self._resolve_user_and_identifier_silent(
            email, IdentifierType.EMAIL
        )
        if user is None or not identifier or not identifier.is_verified:
            return {
                "masked_destination": self._mask(email),
                "expires_in": MAGIC_LINK_TTL,
            }

        raw_token  = secrets.token_urlsafe(48)
        token_hash = hashlib.sha256(raw_token.encode()).hexdigest()

        MagicLink.objects.create(
            user=user,
            identifier=identifier,
            client=client,
            token_hash=token_hash,
            redirect_uri=redirect_uri,
            scopes=scopes,
            expires_at=timezone.now() + timedelta(seconds=MAGIC_LINK_TTL),
            ip_requested=ip_address or None,
        )

        self._deliver_magic_link(identifier, raw_token, client.system)

        self._audit(
            AuditEventType.MAGIC_LINK_SENT,
            user,
            ip=ip_address,
            system=client.system
        )

        return {
            "masked_destination": self._mask(email),
            "expires_in": MAGIC_LINK_TTL,
        }

    @transaction.atomic
    def verify_magic_link(
        self,
        raw_token: str,
        ip_address: str = "",
        user_agent: str = "",
    ) -> tuple[SSOSession, str]:
        token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
        try:
            link = MagicLink.objects.select_related(
                "user", "identifier", "client"
            ).get(token_hash=token_hash, is_used=False)
        except MagicLink.DoesNotExist:
            raise AuthenticationError("Invalid or expired magic link.")

        if link.is_expired():
            raise AuthenticationError(
                "This link has expired. Please request a new one."
            )

        link.is_used = True
        link.used_at = timezone.now()
        link.ip_used = ip_address or None
        link.save(update_fields=["is_used", "used_at", "ip_used"])

        session = self._create_session(
            user=link.user,
            client=link.client,
            auth_method=SSOSession.AuthMethod.MAGIC_LINK,
            ip_address=ip_address,
            user_agent=user_agent,
            mfa_verified=True,
        )

        self._audit(
            AuditEventType.MAGIC_LINK_USED,
            link.user,
            ip=ip_address,
            system=link.client.system,
            payload={"session_id": str(session.id)}
        )

        return session, link.redirect_uri

    def verify_mfa(
        self,
        session: SSOSession,
        method: str,
        code: str,
        ip_address: str = "",
    ) -> bool:
        mfa_entry = session.user.mfa_methods.filter(
            method=method, is_active=True
        ).first()
        if not mfa_entry:
            raise AuthenticationError(f"MFA method '{method}' is not enrolled.")

        verified = self._validate_mfa_code(mfa_entry, code, method)

        if verified:
            session.mfa_verified = True
            session.mfa_method = method
            session.save(update_fields=["mfa_verified", "mfa_method"])
            mfa_entry.last_used_at = timezone.now()
            mfa_entry.save(update_fields=["last_used_at"])
            self._audit(
                AuditEventType.MFA_VERIFIED,
                session.user,
                ip=ip_address,
                payload={"method": method}
            )
        else:
            self._audit(
                AuditEventType.MFA_FAILED,
                session.user,
                ip=ip_address,
                payload={"method": method},
                outcome="failure"
            )

        return verified

    def _validate_mfa_code(self, mfa_entry: UserMFA, code: str, method: str) -> bool:
        if method == MFAMethod.TOTP:
            secret = mfa_entry.secret_encrypted
            totp = pyotp.TOTP(secret)
            return totp.verify(code, valid_window=1)

        if method == MFAMethod.BACKUP:
            return self._verify_backup_code(mfa_entry.user, code)

        # SMS / Email OTP: these use PasswordlessChallenge, not UserMFA directly
        # If called here it means the OTP was delivered via a separate channel
        # and the code is being validated against a short-lived hash
        # stored on the session or a challenge record.
        raise NotImplementedError(
            f"MFA method '{method}' must be verified via its own flow "
            f"(PasswordlessChallenge for SMS/email, WebAuthn assertion for hardware keys)."
        )

    @staticmethod
    def _verify_backup_code(user: User, raw_code: str) -> bool:
        for bc in BackupCode.objects.filter(user=user, is_used=False, invalidated_at__isnull=True):
            if bcrypt.checkpw(raw_code.encode(), bc.code_hash.encode()):
                bc.is_used = True
                bc.used_at = timezone.now()
                bc.save(update_fields=["is_used", "used_at"])
                return True
        return False

    def get_login_contexts(self, session: SSOSession) -> list[LoginContext]:
        """
        Return all contexts the user can select after authentication.
        Each context is one OrganizationMembership row.
        """
        if not session.mfa_verified:
            # MFA not yet done — only show contexts that don't require MFA
            # OR show all and let select_context() enforce the requirement
            pass

        memberships = (
            OrganizationMembership.objects
            .filter(
                system_user__user=session.user,
                is_active=True,
                deleted_at__isnull=True,
            )
            .filter(
                models.Q(expires_at__isnull=True) |
                models.Q(expires_at__gt=timezone.now())
            )
            .select_related(
                "system_user__system",
                "organization",
                "country",
                "role",
            )
            .prefetch_related("branch_grants")
        )

        contexts = []
        for m in memberships:
            if m.system_user.is_suspended:
                continue
            contexts.append(LoginContext(
                system_user_id=str(m.system_user_id),
                system_id=str(m.system_user.system_id),
                system_name=m.system_user.system.name,
                organization_id=str(m.organization_id),
                organization_name=m.organization.name,
                country_code=m.country.code,
                country_name=m.country.name,
                role_id=str(m.role_id),
                role_name=m.role.name,
                all_branches=m.all_branches,
                branch_count=m.branch_grants.count() if not m.all_branches else 0,
            ))
        return contexts

    # =========================================================================
    # 6. Context selection → Authorization Code
    # =========================================================================

    @transaction.atomic
    def select_context(
        self,
        session: SSOSession,
        system_user_id: str,
        organization_id: str,
        country_code: str,
        client: SystemClient,
        redirect_uri: str,
        scopes: list,
        state: str = "",
        nonce: str = "",
        code_challenge: str = "",
        code_challenge_method: str = "S256",
    ) -> str:
        """
        User selects a context. Enforces MFA policy for that context.
        Returns raw authorization code on success.

        MFA enforcement:
          If MFA is required for this context AND:
            - session.mfa_verified is False → store pending context, raise MFARequiredError
            - session.mfa_verified is True but wrong method → raise MFAMethodNotAcceptableError
            - no MFA enrolled → store pending context, raise MFAEnrollmentRequiredError
        """
        # Validate redirect_uri
        if redirect_uri not in client.redirect_uris:
            raise OAuthError("invalid_request", "Redirect URI not registered.")

        system_user = SystemUser.objects.select_related("system").get(
            id=system_user_id,
            user=session.user,
            status=SystemUserStatus.ACTIVE,
        )

        if system_user.is_suspended:
            raise AuthenticationError("Your account is suspended in this system.")

        try:
            membership = OrganizationMembership.objects.select_related(
                "role", "country", "organization",
            ).get(
                system_user=system_user,
                organization_id=organization_id,
                country__code=country_code,
                is_active=True,
            )
        except OrganizationMembership.DoesNotExist:
            raise AuthenticationError("You do not have access to this context.")

        if membership.is_expired():
            raise AuthenticationError("Your membership in this context has expired.")

        # Resolve MFA requirement for this context
        requirement = self._resolve_mfa_requirement(
            session.user,
            system_user.system,
            membership.organization,
            membership.country,
            membership.role,
        )

        if requirement.required:
            has_enrolled = session.user.mfa_methods.filter(is_active=True).exists()

            if not has_enrolled:
                # No MFA enrolled at all — must enrol before proceeding
                self._store_pending_context(
                    session, system_user_id, organization_id, country_code, requirement
                )
                from apps.accounts.models import PendingMFAEnrollment
                PendingMFAEnrollment.objects.update_or_create(
                    session=session,
                    defaults={
                        "required_by": requirement.reason,
                        "allowed_methods": requirement.allowed_methods,
                        "context_system_user_id": uuid.UUID(system_user_id),
                        "context_org_id": uuid.UUID(organization_id),
                        "context_country_code": country_code,
                        "expires_at": timezone.now() + timedelta(minutes=15),
                        "completed_at": None,
                    },
                )
                self._audit(AuditEventType.MFA_ENROLLMENT_REQUIRED, session.user,
                            payload={"reason": requirement.reason,
                                     "allowed_methods": requirement.allowed_methods})
                raise MFAEnrollmentRequiredError(requirement)

            if not session.mfa_verified:
                # MFA enrolled but not yet done in this session
                self._store_pending_context(
                    session, system_user_id, organization_id, country_code, requirement
                )
                raise MFARequiredError(requirement)

            if requirement.allowed_methods and \
                    session.mfa_method not in requirement.allowed_methods:
                # MFA done but with wrong method
                session.mfa_verified = False
                session.mfa_method   = ""
                self._store_pending_context(
                    session, system_user_id, organization_id, country_code, requirement
                )
                session.save(update_fields=["mfa_verified", "mfa_method",
                                            "pending_context_system_user_id",
                                            "pending_context_org_id",
                                            "pending_context_country_code",
                                            "mfa_required_reason",
                                            "mfa_allowed_methods"])
                raise MFAMethodNotAcceptableError(requirement, session.mfa_method)

        # MFA satisfied — clear any pending context
        session.clear_pending_mfa_context()

        # Issue authorization code
        raw_code = secrets.token_urlsafe(32)
        AuthorizationCode.objects.create(
            code=raw_code,
            user=session.user,
            client=client,
            sso_session=session,
            system_user=system_user,
            organization_id=organization_id,
            country=membership.country,
            redirect_uri=redirect_uri,
            scopes=scopes,
            state=state,
            nonce=nonce,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
            expires_at=timezone.now() + timedelta(seconds=AUTH_CODE_TTL),
        )

        # Track system access for global logout
        SSOSessionSystemAccess.objects.get_or_create(
            session=session,
            system=system_user.system,
        )

        # Record context selection
        LoginContextSelection.objects.create(
            sso_session=session,
            system_user=system_user,
            organization_id=organization_id,
            country=membership.country,
            role=membership.role,
            role_name_snapshot=membership.role.name,
        )

        self._audit(AuditEventType.CONTEXT_SELECTED, session.user,
                    system=system_user.system,
                    payload={
                        "org": str(organization_id),
                        "country": country_code,
                        "role": membership.role.name,
                    })
        return raw_code

    # =========================================================================
    # 7. Token exchange
    # =========================================================================

    @transaction.atomic
    def exchange_code(
        self,
        raw_code: str,
        client: SystemClient,
        redirect_uri: str,
        code_verifier: str = "",
    ) -> TokenResponse:
        """
        Exchange an authorization code for tokens.
        Single-use. Validates PKCE if code_challenge was set.
        """
        try:
            auth_code = AuthorizationCode.objects.select_related(
                "user", "client", "sso_session",
                "system_user__system", "organization", "country",
            ).get(code=raw_code, is_used=False)
        except AuthorizationCode.DoesNotExist:
            raise OAuthError("invalid_grant", "Authorization code not found or already used.")

        if auth_code.is_expired():
            raise OAuthError("invalid_grant", "Authorization code expired.")

        if auth_code.client_id != client.id:
            raise OAuthError("invalid_client", "Client mismatch.")

        if auth_code.redirect_uri != redirect_uri:
            raise OAuthError("invalid_grant", "Redirect URI mismatch.")

        if auth_code.code_challenge:
            if not code_verifier:
                raise OAuthError("invalid_grant", "code_verifier is required (PKCE).")
            self._verify_pkce(code_verifier, auth_code.code_challenge,
                              auth_code.code_challenge_method)

        if auth_code.sso_session and auth_code.sso_session.requires_reauth:
            raise OAuthError(
                "session_expired",
                "Your session requires re-authentication. Please log in again.",
            )

        auth_code.is_used = True
        auth_code.used_at = timezone.now()
        auth_code.save(update_fields=["is_used", "used_at"])

        return self._issue_tokens(
            session=auth_code.sso_session,
            user=auth_code.user,
            client=client,
            system_user=auth_code.system_user,
            organization=auth_code.organization,
            country=auth_code.country,
            scopes=auth_code.scopes,
            nonce=auth_code.nonce,
        )

    # =========================================================================
    # 8. Token refresh
    # =========================================================================

    @transaction.atomic
    def refresh_tokens(
        self,
        raw_refresh_token: str,
        client: SystemClient,
    ) -> TokenResponse:
        """
        Issue new access + refresh tokens using a refresh token.
        Implements rotation: old token marked used, new one issued.
        Reuse detection: if already used → revoke entire token family.
        """
        token_hash = _hash(raw_refresh_token)

        try:
            rt = RefreshToken.objects.select_related(
                "token_set__sso_session",
                "token_set__user",
                "token_set__system_user__system",
                "token_set__organization",
                "token_set__country",
            ).get(token_hash=token_hash)
        except RefreshToken.DoesNotExist:
            raise OAuthError("invalid_grant", "Refresh token not found.")

        # Reuse detection
        if rt.is_used or rt.is_revoked:
            # Possible token theft — revoke the entire token family
            rt.token_set.is_active = False
            rt.token_set.save(update_fields=["is_active"])
            self._audit(
                AuditEventType.TOKEN_REFRESH_REUSE,
                rt.token_set.user,
                payload={"token_set_id": str(rt.token_set_id)},
                outcome="failure",
            )
            raise OAuthError(
                "invalid_grant",
                "Refresh token reuse detected. Session has been revoked for security."
            )

        if rt.expires_at < timezone.now():
            raise OAuthError("invalid_grant", "Refresh token has expired.")

        ts = rt.token_set
        if not ts.is_active:
            raise OAuthError("invalid_grant", "Token set has been revoked.")

        if ts.sso_session and ts.sso_session.is_expired():
            raise OAuthError("invalid_grant", "SSO session has expired.")

        if ts.sso_session and ts.sso_session.requires_reauth:
            raise OAuthError(
                "session_expired",
                "Re-authentication required. Please log in again.",
            )

        # Mark old refresh token as used
        rt.is_used = True
        rt.used_at = timezone.now()
        rt.save(update_fields=["is_used", "used_at"])

        response = self._issue_tokens(
            session=ts.sso_session,
            user=ts.user,
            client=client,
            system_user=ts.system_user,
            organization=ts.organization,
            country=ts.country,
            scopes=ts.scopes,
        )
        # Link rotation chain
        new_rt = RefreshToken.objects.filter(
            token_set=ts
        ).order_by("-created_at").first()
        if new_rt:
            rt.rotated_to = new_rt
            rt.save(update_fields=["rotated_to"])

        self._audit(AuditEventType.TOKEN_REFRESHED, ts.user,
                    payload={"token_set_id": str(ts.id)})
        return response

    # =========================================================================
    # 9. Logout
    # =========================================================================

    @transaction.atomic
    def logout(
        self,
        session: SSOSession,
        reason: str = "logout",
        ip_address: str = "",
    ) -> None:
        """
        Local logout: revoke this session and all its tokens.
        Back-channel logout signals sent to all systems the session accessed.
        """
        session.revoke(reason=reason)
        self._send_backchannel_logout(session)
        self._audit(AuditEventType.SESSION_REVOKED, session.user,
                    ip=ip_address, payload={"session_id": str(session.id),
                                            "reason": reason})

    @transaction.atomic
    def logout_all(
        self,
        user: User,
        reason: str = "global_logout",
        ip_address: str = "",
    ) -> int:
        """
        Global logout: revoke ALL active sessions for this user.
        Returns the count of revoked sessions.
        """
        sessions = SSOSession.objects.filter(user=user, is_active=True)
        count = sessions.count()
        for session in sessions:
            session.revoke(reason=reason)
            self._send_backchannel_logout(session)

        self._audit(AuditEventType.LOGOUT_GLOBAL, user, ip=ip_address,
                    payload={"sessions_revoked": count})
        return count

    def revoke_token(
        self,
        token_hash: str,
        client: SystemClient,
        ip_address: str = "",
    ) -> None:
        """Revoke a specific refresh token."""
        try:
            rt = RefreshToken.objects.select_related("token_set__user").get(
                token_hash=token_hash,
                token_set__client=client,
            )
        except RefreshToken.DoesNotExist:
            return  # RFC 7009: silently succeed

        rt.is_revoked = True
        rt.revoked_at = timezone.now()
        rt.save(update_fields=["is_revoked", "revoked_at"])

        self._audit(AuditEventType.TOKEN_REVOKED, rt.token_set.user,
                    ip=ip_address, payload={"jti": str(rt.jti)})

    # =========================================================================
    # 10. Introspection
    # =========================================================================

    def introspect(self, raw_access_token: str) -> dict:
        """
        Validate an access token and return its claims.
        Returns {"active": False} for invalid/expired tokens.
        """
        try:
            payload = jwt.decode(
                raw_access_token,
                settings.SSO_PUBLIC_KEY,
                algorithms=[JWT_ALGORITHM],
                options={"verify_exp": True},
            )
        except jwt.PyJWTError:
            return {"active": False}

        jti = payload.get("jti")
        if not jti:
            return {"active": False}

        try:
            at = AccessToken.objects.select_related("token_set").get(
                jti=jti, is_revoked=False
            )
        except AccessToken.DoesNotExist:
            return {"active": False}

        if at.expires_at < timezone.now():
            return {"active": False}

        if not at.token_set.is_active:
            return {"active": False}

        payload["active"] = True
        return payload

    # =========================================================================
    # Internal — token issuance
    # =========================================================================

    @transaction.atomic
    def _issue_tokens(
        self,
        session: Optional[SSOSession],
        user: User,
        client: SystemClient,
        system_user: Optional[SystemUser],
        organization,
        country,
        scopes: list,
        nonce: str = "",
    ) -> TokenResponse:
        now = timezone.now()

        perm_ctx = None
        if system_user and organization and country:
            perm_ctx = self._perm.resolve(
                system_user, str(organization.id), country.code
            )

        ts = TokenSet.objects.create(
            sso_session=session,
            user=user,
            client=client,
            system_user=system_user,
            organization=organization,
            country=country,
            scopes=scopes,
        )

        access_ttl = client.access_token_ttl or ACCESS_TOKEN_TTL
        at_claims  = self._build_access_token_claims(
            user, system_user, organization, country,
            scopes, perm_ctx, now, access_ttl, nonce,
        )
        raw_at = self._sign_jwt(at_claims)
        AccessToken.objects.create(
            token_set=ts,
            token_hash=_hash(raw_at),
            jti=uuid.UUID(at_claims["jti"]),
            expires_at=now + timedelta(seconds=access_ttl),
            role_snapshot=perm_ctx.role if perm_ctx else "",
            permissions_snapshot=list(perm_ctx.permissions) if perm_ctx else [],
        )

        refresh_ttl = client.refresh_token_ttl or REFRESH_TOKEN_TTL
        raw_rt      = secrets.token_urlsafe(48)
        RefreshToken.objects.create(
            token_set=ts,
            token_hash=_hash(raw_rt),
            jti=uuid.uuid4(),
            expires_at=now + timedelta(seconds=refresh_ttl),
        )

        id_claims = self._build_id_token_claims(
            user, system_user, organization, country, perm_ctx,
            client, scopes, nonce, now,
        )
        raw_id = self._sign_jwt(id_claims)

        self._audit(AuditEventType.TOKEN_ISSUED, user,
                    payload={"token_set_id": str(ts.id),
                             "system": system_user.system.name if system_user else ""})

        return TokenResponse(
            access_token=raw_at,
            refresh_token=raw_rt,
            id_token=raw_id,
            expires_in=access_ttl,
            scope=" ".join(scopes),
        )

    def _build_access_token_claims(
        self, user, system_user, organization, country,
        scopes, perm_ctx, now, ttl, nonce
    ) -> dict:
        claims = {
            "iss": settings.SSO_ISSUER,
            "sub": str(user.id),
            "aud": str(system_user.system_id) if system_user else "",
            "iat": int(now.timestamp()),
            "exp": int((now + timedelta(seconds=ttl)).timestamp()),
            "jti": str(uuid.uuid4()),
            "scope": " ".join(scopes),
        }
        if "email" in scopes:
            claims["email"] = user.get_email() or ""
        if system_user:
            claims["system_user_id"] = str(system_user.id)
            claims["system_id"]      = str(system_user.system_id)
        if organization:
            claims["org_id"]   = str(organization.id)
            claims["org_name"] = organization.name
        if country:
            claims["country"] = country.code
        if perm_ctx:
            claims["role"]        = perm_ctx.role
            claims["permissions"] = list(perm_ctx.permissions)
            claims["branches"]    = perm_ctx.accessible_branch_ids
        if nonce:
            claims["nonce"] = nonce
        return claims

    def _build_id_token_claims(
        self, user, system_user, organization, country,
        perm_ctx, client, scopes, nonce, now
    ) -> dict:
        claims = {
            "iss": settings.SSO_ISSUER,
            "sub": str(user.id),
            "aud": client.client_id,
            "iat": int(now.timestamp()),
            "exp": int((now + timedelta(seconds=3600)).timestamp()),
            "jti": str(uuid.uuid4()),
        }
        if "email" in scopes:
            claims["email"] = user.get_email() or ""
        if "profile" in scopes and system_user:
            claims["name"]        = system_user.full_name
            claims["given_name"]  = system_user.first_name
            claims["family_name"] = system_user.last_name
        if "roles" in scopes and perm_ctx:
            claims["role"]        = perm_ctx.role
            claims["permissions"] = list(perm_ctx.permissions)
        if country:
            claims["country"] = country.code
        if organization:
            claims["org_id"]   = str(organization.id)
            claims["org_name"] = organization.name
        if nonce:
            claims["nonce"] = nonce
        return claims

    def _sign_jwt(self, claims: dict) -> str:
        return jwt.encode(claims, settings.SSO_PRIVATE_KEY, algorithm=JWT_ALGORITHM)

    # =========================================================================
    # Internal — session creation
    # =========================================================================

    def _create_session(
        self,
        user: User,
        client: SystemClient,
        auth_method: str,
        ip_address: str = "",
        user_agent: str = "",
        device_id: str = "",
        device_name: str = "",
        mfa_verified: bool = False,
    ) -> SSOSession:
        has_mfa = user.mfa_methods.filter(is_active=True).exists()
        raw_token = secrets.token_urlsafe(48)

        return SSOSession.objects.create(
            user=user,
            initiating_system=client.system,
            session_token_hash=_hash(raw_token),
            ip_address=ip_address or None,
            user_agent=user_agent,
            device_id=device_id,
            device_name=device_name,
            auth_method=auth_method,
            mfa_verified=mfa_verified or not has_mfa,
            expires_at=timezone.now() + timedelta(seconds=SSO_SESSION_TTL),
        )

    # =========================================================================
    # Internal — MFA policy
    # =========================================================================

    def _resolve_mfa_requirement(
        self, user, system, organization, country, role
    ) -> MFARequirement:
        required = False
        reason   = ""
        allowed  = []

        # Country-level (regulatory — cannot be overridden)
        if country.mfa_required:
            required = True
            reason   = f"Required by {country.name} regulatory policy"

        # System-level
        if system.mfa_required:
            required = True
            reason   = f"Required by {system.name}"
        if system.allowed_mfa_methods:
            allowed = system.allowed_mfa_methods

        # Role-level
        if role.mfa_required:
            required = True
            reason   = f"Required for {role.name} role"
        if role.mfa_allowed_methods:
            if allowed:
                allowed = [m for m in allowed if m in role.mfa_allowed_methods]
            else:
                allowed = role.mfa_allowed_methods

        # Org-level (from OrganizationSettings)
        from apps.organizations.models import OrganizationSettings
        try:
            org_mfa = OrganizationSettings.objects.get(
                organization=organization, key="mfa_required"
            ).typed_value()
            if org_mfa is True:
                # Org can ADD requirement but cannot remove if system enforces it
                if not (system.mfa_required and system.mfa_required_enforced):
                    required = True
                    reason   = f"Required by {organization.name}"
            elif org_mfa is False and system.mfa_required_enforced:
                # Org tried to disable but system enforces — ignore
                pass
        except OrganizationSettings.DoesNotExist:
            pass

        try:
            org_methods_setting = OrganizationSettings.objects.get(
                organization=organization, key="mfa_allowed_methods"
            ).typed_value()
            if org_methods_setting:
                if allowed:
                    allowed = [m for m in allowed if m in org_methods_setting]
                else:
                    allowed = org_methods_setting
        except OrganizationSettings.DoesNotExist:
            pass

        return MFARequirement(required=required, reason=reason, allowed_methods=allowed)

    def _store_pending_context(
        self,
        session: SSOSession,
        system_user_id: str,
        org_id: str,
        country_code: str,
        requirement: MFARequirement,
    ):
        session.pending_context_system_user_id = uuid.UUID(system_user_id)
        session.pending_context_org_id         = uuid.UUID(org_id)
        session.pending_context_country_code   = country_code
        session.mfa_required_reason            = requirement.reason
        session.mfa_allowed_methods            = requirement.allowed_methods
        session.save(update_fields=[
            "pending_context_system_user_id",
            "pending_context_org_id",
            "pending_context_country_code",
            "mfa_required_reason",
            "mfa_allowed_methods",
        ])

    # =========================================================================
    # Internal — PKCE
    # =========================================================================

    def _verify_pkce(self, verifier: str, challenge: str, method: str):
        import base64
        if method == "S256":
            digest   = hashlib.sha256(verifier.encode()).digest()
            computed = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
            if not hmac.compare_digest(computed, challenge):
                raise OAuthError("invalid_grant", "PKCE verification failed.")
        elif method == "plain":
            if not hmac.compare_digest(verifier, challenge):
                raise OAuthError("invalid_grant", "PKCE verification failed.")

    @staticmethod
    def _resolve_user_safe(login_value: str, detected_type: str) -> User:
        try:
            return User.objects.get_by_identifier(login_value, detected_type)
        except User.DoesNotExist:
            _dummy_bcrypt()
            raise AuthenticationError("Invalid credentials.")

    def _resolve_user_and_identifier_silent(
        self,
        value: str,
        identifier_type: str = None,
    ) -> tuple[Optional[User], Optional[UserIdentifier]]:
        # noinspection PyBroadException
        try:
            detected = identifier_type or detect_identifier_type(value)
            normalised = self._normaliser.normalise(value, detected)
            row = UserIdentifier.objects.select_related("user").filter(
                identifier_type=detected,
                value_normalised=normalised,
            ).first()
            if not row:
                _dummy_bcrypt()
                return None, None
            return row.user, row
        except Exception:
            return None, None

    @staticmethod
    def _deliver_otp(identifier: UserIdentifier, raw_code: str, system: System):
        if identifier.identifier_type == IdentifierType.PHONE:
            pass
        elif identifier.identifier_type == IdentifierType.EMAIL:
            pass

    def _deliver_magic_link(self, identifier: UserIdentifier, raw_token: str, system: System):
        pass

    def _send_backchannel_logout(self, session: SSOSession):
        """
        Notify all systems the session accessed that it has been revoked.
        In production, dispatch to Celery for async HTTP delivery.
        """
        # for system_access in session.accessed_systems.through.objects.filter(session=session):
        #     for webhook in system_access.system.webhooks.filter(
        #         is_active=True, event_types__contains=["session.revoked"]
        #     ):
        #         deliver_webhook.delay(webhook.id, {"event": "session.revoked",
        #                                            "sub": str(session.user_id),
        #                                            "sid": str(session.id)})
        pass

    # =========================================================================
    # Internal — rate limiting
    # =========================================================================

    def _rate_limit_passwordless(self, login_value: str, ip_address: str):
        detected = detect_identifier_type(login_value)
        normalised = self._normaliser.normalise(login_value, detected)

        window = timezone.now() - timedelta(minutes=10)
        by_identifier = PasswordlessChallenge.objects.filter(
            identifier__value_normalised=normalised,
            created_at__gte=window,
        ).count()
        if by_identifier >= 5:
            raise AuthenticationError(
                "Too many codes requested for this number. "
                "Please wait a few minutes before trying again."
            )

        if ip_address:
            by_ip = PasswordlessChallenge.objects.filter(
                ip_requested=ip_address,
                created_at__gte=timezone.now() - timedelta(hours=1),
            ).count()
            if by_ip >= 10:
                raise AuthenticationError(
                    "Too many requests from this device. Please try again later."
                )

    def _rate_limit_magic_link(self, email: str, ip_address: str):
        normalised = self._normaliser.normalise(email, IdentifierType.EMAIL)
        window     = timezone.now() - timedelta(minutes=10)
        count      = MagicLink.objects.filter(
            identifier__value_normalised=normalised,
            created_at__gte=window,
        ).count()
        if count >= 3:
            raise AuthenticationError(
                "Too many sign-in links requested. "
                "Please check your inbox or wait a few minutes."
            )

    # =========================================================================
    # Internal — lock handling
    # =========================================================================

    def _handle_failed_login(self, user: User, ip: str, system):
        user.failed_login_attempts += 1
        if user.failed_login_attempts >= 5:
            user.locked_until = timezone.now() + timedelta(minutes=15)
        user.save(update_fields=["failed_login_attempts", "locked_until"])
        self._audit(
            AuditEventType.LOGIN_FAILED,
            user,
            ip=ip,
            system=system,
            payload={"attempts": user.failed_login_attempts},
            outcome="failure"
        )

    def _reset_lock(self, user: User):
        user.failed_login_attempts = 0
        user.locked_until          = None
        user.save(update_fields=["failed_login_attempts", "locked_until"])

    # =========================================================================
    # Internal — helpers
    # =========================================================================

    def _generate_otp(self) -> str:
        import random
        return f"{random.SystemRandom().randint(0, 999999):06d}"

    def _mask(self, value: str) -> str:
        if "@" in value:
            local, _, domain = value.partition("@")
            return f"{local[0]}{'*' * max(1, len(local) - 2)}{local[-1]}@{domain}"
        if len(value) > 4:
            return value[:2] + "*" * (len(value) - 4) + value[-2:]
        return "****"

    def _audit(
        self,
        event_type: str,
        user: Optional[User] = None,
        ip: str = "",
        system=None,
        payload: dict = None,
        outcome: str = "success",
    ):
        AuditLog.objects.create(
            event_type=event_type,
            actor_user_id=user.id if user else None,
            actor_email=user.get_email() or "" if user else "",
            actor_ip=ip or None,
            system_id=system.id if system else None,
            system_name=system.name if system else "",
            payload=payload or {},
            outcome=outcome,
        )


# =============================================================================
# Utilities
# =============================================================================

def _hash(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()

def _dummy_bcrypt():
    """Constant-time dummy op to prevent timing attacks on user lookups."""
    bcrypt.checkpw(b"dummy", b"$2b$12$aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")

from django.db import models  # noqa — needed for Q() in get_login_contexts
from apps.accounts.models import SystemUserStatus  # noqa