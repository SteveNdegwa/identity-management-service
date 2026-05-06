import base64
import hashlib
import hmac
import secrets
import uuid
from dataclasses import dataclass, field
from datetime import timedelta, datetime
from typing import Optional, Tuple, List

import bcrypt
import jwt

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import transaction
from django.utils import timezone

from accounts.models import User, IdentifierType, SystemUser, SystemUserStatus, SocialAccount
from accounts.identifier_utils import IdentifierNormaliser, detect_identifier_type
from audit.models import AuditLog, AuditEventType
from notifications.services.notification_service import NotificationService
from organizations.models import OrganizationSettings
from permissions.services.permission_resolver import PermissionResolverService
from sso.models import (
    SSOSession,
    SSOSessionSystemAccess,
    SSOSessionMFAVerification,
    AuthorizationCode,
    TokenSet,
    AccessToken,
    RefreshToken,
    MagicLink,
    LoginContextSelection,
    PasswordlessChallenge,
    PendingContextMFA,
    MFAMethod,
)
from systems.models import SystemClient, System
from permissions.services.permission_resolver import ResolvedContext
from utils.common import generate_otp, hash_value, mask, dummy_bcrypt
from utils.social_providers import normalize_social_provider

ACCESS_TOKEN_TTL = getattr(settings, "SSO_ACCESS_TOKEN_TTL", 900)
REFRESH_TOKEN_TTL = getattr(settings, "SSO_REFRESH_TOKEN_TTL", 86400)
SSO_SESSION_TTL = getattr(settings, "SSO_SESSION_TTL", 604800)
AUTH_CODE_TTL = 120
MAGIC_LINK_TTL = 900
PASSWORDLESS_TTL = 300
JWT_ALGORITHM = getattr(settings, "SSO_JWT_ALGORITHM", "RS256")
MAX_OTP_ATTEMPTS = 3


@dataclass
class LoginContext:
    system_user_id: str
    system_name: str
    organization_name: Optional[str]
    country_code: str
    country_name: str
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
    allowed_methods: List[dict] = field(default_factory=list)
    reauth_window_minutes: int = 0


class AuthenticationError(Exception):
    pass


class OAuthError(Exception):
    def __init__(self, error: str, description: str = ""):
        self.error       = error
        self.description = description
        super().__init__(f"{error}: {description}")


class MFARequiredError(Exception):
    def __init__(self, requirement: MFARequirement, pending_context_id: str = ""):
        self.requirement = requirement
        self.pending_context_id = pending_context_id


class IdentifierVerificationRequiredError(Exception):
    def __init__(self, requirements: list):
        self.requirements = requirements
        super().__init__("Required identifiers must be verified before continuing.")


class SystemReauthRequiredError(Exception):
    def __init__(self, system: System, session: SSOSession):
        self.system  = system
        self.session = session
        super().__init__(
            f"Re-authentication required for system '{system.name}'. "
            "Please re-login using your existing session."
        )


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
            reauth_session_id: str = "",
    ) -> SSOSession:
        system = client.system
        config = client.get_effective_config()

        if not config["allow_password_login"]:
            raise AuthenticationError("Password login is not enabled for this system.")

        detected_type = detect_identifier_type(login_value)
        user = self._resolve_user_safe(login_value, detected_type, system.realm)

        if user.is_locked():
            raise AuthenticationError("Account is temporarily locked.")

        if not user.check_password(password):
            self._handle_failed_login(user, ip_address, system)
            raise AuthenticationError("Invalid credentials.")

        self._reset_lock(user)

        session = self._get_or_create_session(
            user=user,
            client=client,
            auth_method=SSOSession.AuthMethod.PASSWORD,
            ip_address=ip_address,
            user_agent=user_agent,
            device_id=device_id,
            device_name=device_name,
            reauth_session_id=reauth_session_id,
        )

        self._audit(
            AuditEventType.LOGIN_SUCCESS,
            user,
            ip=ip_address,
            system=system,
            payload={"session_id": str(session.id)}
        )
        return session

    @transaction.atomic
    def authenticate_pin(
            self,
            login_value: str,
            pin: str,
            client: SystemClient,
            ip_address: str = "",
            user_agent: str = "",
            device_id: str = "",
            device_name: str = "",
            reauth_session_id: str = "",
    ) -> SSOSession:
        system = client.system

        if system.password_type != System.PasswordType.PIN:
            raise AuthenticationError("PIN login is not enabled for this system.")

        detected_type = detect_identifier_type(login_value)
        user = self._resolve_user_safe(login_value, detected_type, system.realm)

        if user.is_locked():
            raise AuthenticationError("Account is temporarily locked.")

        if not user.check_pin(pin):
            self._handle_failed_login(user, ip_address, system)
            raise AuthenticationError("Invalid credentials.")

        self._reset_lock(user)

        session = self._get_or_create_session(
            user=user,
            client=client,
            auth_method=SSOSession.AuthMethod.PIN,
            ip_address=ip_address, user_agent=user_agent,
            device_id=device_id, device_name=device_name,
            reauth_session_id=reauth_session_id,
        )

        self._audit(
            AuditEventType.LOGIN_SUCCESS,
            user,
            ip=ip_address,
            system=system,
            payload={"session_id": str(session.id)}
        )
        return session

    @transaction.atomic
    def authenticate_social(
            self,
            client: SystemClient,
            provider: str,
            uid: str,
            ip_address: str = "",
            user_agent: str = "",
            device_id: str = "",
            device_name: str = "",
            reauth_session_id: str = "",
    ) -> SSOSession:
        config = client.get_effective_config()
        if not config["allow_social_login"]:
            raise AuthenticationError("Social login is not enabled for this system.")

        try:
            provider = normalize_social_provider(provider)
        except ValidationError as exc:
            raise AuthenticationError(exc.messages[0])

        allowed_providers = config["allowed_social_providers"] or []
        if allowed_providers and provider not in allowed_providers:
            raise AuthenticationError(
                f"This system only accepts social login via: {allowed_providers}."
            )

        uid = (uid or "").strip()
        if not uid:
            raise AuthenticationError("Social account uid is required.")

        try:
            social = SocialAccount.objects.select_related("user").get(
                provider=provider, uid=uid, user__realm=client.system.realm,
            )
        except SocialAccount.DoesNotExist:
            raise AuthenticationError("Invalid social account.")

        user = social.user
        if user.is_locked():
            raise AuthenticationError("Account is temporarily locked.")

        session = self._get_or_create_session(
            user=user,
            client=client,
            auth_method=SSOSession.AuthMethod.SOCIAL,
            ip_address=ip_address,
            user_agent=user_agent,
            device_id=device_id,
            device_name=device_name,
            reauth_session_id=reauth_session_id,
        )

        self._audit(
            AuditEventType.LOGIN_SUCCESS,
            user,
            ip=ip_address,
            system=client.system,
            payload={"session_id": str(session.id), "provider": provider}
        )
        return session

    def initiate_passwordless(
            self,
            login_value: str,
            client: SystemClient,
            ip_address: str = ""
    ) -> dict:
        config = client.get_effective_config()
        if not config["allow_passwordless_login"]:
            raise AuthenticationError("Passwordless login is not enabled for this system.")

        self._rate_limit_passwordless(login_value, ip_address)

        user, contact_type = self._resolve_user_and_contact_silent(login_value)
        masked = mask(login_value)

        if user is None or contact_type is None or user.is_locked():
            return {"challenge_id": None, "masked_destination": masked, "expires_in": PASSWORDLESS_TTL}
        if contact_type == IdentifierType.EMAIL and not user.email_verified:
            return {"challenge_id": None, "masked_destination": masked, "expires_in": PASSWORDLESS_TTL}
        if contact_type == IdentifierType.PHONE and not user.phone_verified:
            return {"challenge_id": None, "masked_destination": masked, "expires_in": PASSWORDLESS_TTL}

        raw_code = generate_otp()
        code_hash = hash_value(raw_code)
        destination = user.email if contact_type == IdentifierType.EMAIL else user.phone_number

        challenge = PasswordlessChallenge.objects.create(
            user=user,
            client=client,
            purpose=PasswordlessChallenge.Purpose.LOGIN,
            contact_type=contact_type,
            delivery_target=destination,
            code_hash=code_hash,
            expires_at=timezone.now() + timedelta(seconds=PASSWORDLESS_TTL),
            ip_requested=ip_address or None,
        )
        NotificationService.deliver_otp(
            identifier_type=contact_type,
            value=destination,
            raw_code=raw_code,
            system=client.system,
        )

        self._audit(
            AuditEventType.PASSWORDLESS_INITIATED,
            user,
            ip=ip_address,
            system=client.system,
            payload={"type": contact_type}
        )
        return {
            "challenge_id": str(challenge.id),
            "masked_destination": mask(destination),
            "expires_in": PASSWORDLESS_TTL,
        }

    @transaction.atomic
    def verify_passwordless(
            self,
            client: SystemClient,
            challenge_id: str,
            code: str,
            ip_address: str = "",
            user_agent: str = "",
            device_id: str = "",
            device_name: str = "",
            reauth_session_id: str = "",
    ) -> SSOSession:
        challenge = self._consume_passwordless_challenge(
            client=client,
            challenge_id=challenge_id,
            code=code,
            ip_address=ip_address,
            purpose=PasswordlessChallenge.Purpose.LOGIN,
        )
        auth_method = (
            SSOSession.AuthMethod.SMS_OTP
            if challenge.contact_type == IdentifierType.PHONE
            else SSOSession.AuthMethod.EMAIL_OTP
        )
        session = self._get_or_create_session(
            user=challenge.user,
            client=challenge.client,
            auth_method=auth_method,
            ip_address=ip_address,
            user_agent=user_agent,
            device_id=device_id,
            device_name=device_name,
            reauth_session_id=reauth_session_id,
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
            scopes: list,
            ip_address: str = ""
    ) -> dict:
        config = client.get_effective_config()
        if not config["allow_magic_link_login"]:
            raise AuthenticationError("Magic link login is not enabled for this system.")

        self._rate_limit_magic_link(email, ip_address)
        user, contact_type = self._resolve_user_and_contact_silent(email, IdentifierType.EMAIL)
        masked = mask(email)

        if not user or contact_type != IdentifierType.EMAIL or not user.email_verified:
            return {"masked_destination": masked, "expires_in": MAGIC_LINK_TTL}

        raw_token  = secrets.token_urlsafe(48)
        token_hash = hashlib.sha256(raw_token.encode()).hexdigest()

        MagicLink.objects.create(
            user=user,
            client=client,
            contact_type=IdentifierType.EMAIL,
            delivery_target=user.email,
            token_hash=token_hash,
            scopes=scopes,
            expires_at=timezone.now() + timedelta(seconds=MAGIC_LINK_TTL),
            ip_requested=ip_address or None,
        )
        NotificationService.deliver_magic_link(
            identifier_type=IdentifierType.EMAIL,
            value=user.email,
            raw_token=raw_token,
            system=client.system,
        )
        self._audit(AuditEventType.MAGIC_LINK_SENT, user, ip=ip_address, system=client.system)
        return {"masked_destination": masked, "expires_in": MAGIC_LINK_TTL}

    @transaction.atomic
    def verify_magic_link(
            self,
            client: SystemClient,
            raw_token: str,
            ip_address: str = "",
            user_agent: str = "",
            reauth_session_id: str = "",
    ) -> SSOSession:
        token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
        try:
            link = MagicLink.objects.select_related("user", "client").get(
                token_hash=token_hash, is_used=False,
            )
        except MagicLink.DoesNotExist:
            raise AuthenticationError("Invalid or expired magic link.")

        if link.client != client:
            raise AuthenticationError("Invalid client for this authentication request.")
        if link.is_expired():
            raise AuthenticationError("This link has expired. Please request a new one.")

        link.is_used = True
        link.used_at = timezone.now()
        link.ip_used = ip_address or None
        link.save(update_fields=["is_used", "used_at", "ip_used"])

        session = self._get_or_create_session(
            user=link.user,
            client=link.client,
            auth_method=SSOSession.AuthMethod.MAGIC_LINK,
            ip_address=ip_address,
            user_agent=user_agent,
            reauth_session_id=reauth_session_id,
        )
        self._audit(
            AuditEventType.MAGIC_LINK_USED,
            link.user,
            ip=ip_address,
            system=link.client.system,
            payload={"session_id": str(session.id)}
        )
        return session

    def get_ready_contexts(self, session: SSOSession, client: SystemClient) -> list:
        self.ensure_required_identifiers_satisfied(session.user, client.system)
        self._check_system_mfa(session, client)
        return self.get_login_contexts(session, client.system)

    @staticmethod
    def get_login_contexts(session: SSOSession, system: System) -> list:
        system_users = (
            SystemUser.objects
            .filter(user=session.user, system=system, status=SystemUserStatus.ACTIVE)
            .select_related("user", "system", "organization", "country", "role")
            .prefetch_related("branch_access")
        )
        if not system_users.exists():
            raise ValidationError(
                f"User '{session.user_id}' has no active membership in '{system.name}'."
            )
        return [
            LoginContext(
                system_user_id=str(su.id),
                system_name=su.system.name,
                organization_name=su.organization.name if su.organization else None,
                country_code=su.country.code,
                country_name=su.country.name,
                role_name=su.role.name,
                all_branches=su.all_branches,
                branch_count=su.branch_access.count() if not su.all_branches else 0,
            )
            for su in system_users
        ]

    @transaction.atomic
    def initiate_mfa_otp(
            self,
            session: SSOSession,
            method: str,
            client: SystemClient,
            ip_address: str = "",
    ) -> dict:
        if method not in (MFAMethod.SMS, MFAMethod.EMAIL):
            raise AuthenticationError(
                "Invalid MFA method. Only 'sms' and 'email_otp' are supported."
            )

        user = session.user
        id_type, destination = self._mfa_destination(user, method)

        self._rate_limit_otp(destination, ip_address)

        raw_code = generate_otp()
        code_hash = hash_value(raw_code)

        challenge = PasswordlessChallenge.objects.create(
            user=user, client=client, sso_session=session,
            purpose=PasswordlessChallenge.Purpose.MFA,
            contact_type=id_type,
            delivery_target=destination,
            code_hash=code_hash,
            expires_at=timezone.now() + timedelta(seconds=PASSWORDLESS_TTL),
            ip_requested=ip_address or None,
        )
        NotificationService.deliver_otp(
            identifier_type=id_type,
            value=destination,
            raw_code=raw_code,
            system=client.system,
        )

        self._audit(
            AuditEventType.PASSWORDLESS_INITIATED,
            user,
            ip=ip_address,
            system=client.system,
            payload={"method": method, "purpose": "mfa"}
        )
        return {
            "challenge_id": str(challenge.id),
            "masked_destination": mask(destination),
            "expires_in": PASSWORDLESS_TTL,
        }

    @transaction.atomic
    def verify_system_mfa_otp(
            self,
            session: SSOSession,
            client: SystemClient,
            challenge_id: str,
            code: str,
            ip_address: str = "",
    ) -> None:
        challenge = self._consume_mfa_challenge(
            session=session,
            client=client,
            challenge_id=challenge_id,
            code=code,
            ip_address=ip_address,
        )
        method = MFAMethod.SMS if challenge.contact_type == IdentifierType.PHONE else MFAMethod.EMAIL
        self._record_mfa_verification(session, method, client.system, ip_address)

        access, _ = SSOSessionSystemAccess.objects.get_or_create(
            session=session,
            system=client.system,
        )
        access.touch_mfa_verification()

    @transaction.atomic
    def verify_context_mfa_otp(
            self,
            session: SSOSession,
            client: SystemClient,
            challenge_id: str,
            code: str,
            pending_context_id: str,
            ip_address: str = "",
    ) -> str:
        challenge = self._consume_mfa_challenge(
            session=session,
            client=client,
            challenge_id=challenge_id,
            code=code,
            ip_address=ip_address,
        )
        method = MFAMethod.SMS if challenge.contact_type == IdentifierType.PHONE else MFAMethod.EMAIL
        self._record_mfa_verification(session, method, client.system, ip_address)

        access, _ = SSOSessionSystemAccess.objects.get_or_create(
            session=session, system=client.system,
        )
        access.touch_mfa_verification()

        return self.satisfy_pending_context_mfa(session, pending_context_id)

    @transaction.atomic
    def select_context(
            self,
            session: SSOSession,
            system_user_id: str,
            client: SystemClient,
            redirect_uri: str,
            scopes: list,
            state: str = "",
            nonce: str = "",
            code_challenge: str = "",
            code_challenge_method: str = "S256",
    ) -> str:
        self.ensure_required_identifiers_satisfied(session.user, client.system)

        if redirect_uri not in client.redirect_uris:
            raise OAuthError("invalid_request", "Redirect URI not registered.")

        system_user = (
            SystemUser.objects
            .select_related("system", "role", "organization", "country")
            .get(id=system_user_id, user=session.user, status=SystemUserStatus.ACTIVE)
        )

        requirement = self._resolve_context_mfa_requirement(system_user)

        if requirement.required:
            allowed_method_names = (
                {m["method"] for m in requirement.allowed_methods}
                if requirement.allowed_methods else {MFAMethod.SMS, MFAMethod.EMAIL}
            )
            if self._session_mfa_satisfied(session, allowed_method_names, requirement.reauth_window_minutes):
                pass
            else:
                pending_context = self._create_pending_context(
                    session=session,
                    system_user=system_user,
                    requirement=requirement,
                    client=client,
                    redirect_uri=redirect_uri,
                    scopes=scopes,
                    state=state,
                    nonce=nonce,
                    code_challenge=code_challenge,
                    code_challenge_method=code_challenge_method,
                )
                raise MFARequiredError(requirement, pending_context_id=str(pending_context.id))

        return self._issue_auth_code(
            session=session,
            system_user=system_user,
            client=client,
            redirect_uri=redirect_uri,
            scopes=scopes,
            state=state,
            nonce=nonce,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
        )

    @transaction.atomic
    def satisfy_pending_context_mfa(self, session: SSOSession, pending_context_id: str) -> str:
        try:
            pending = PendingContextMFA.objects.select_related(
                "system_user__system", "system_user__organization",
                "system_user__country", "system_user__role", "client",
            ).get(id=pending_context_id, session=session, satisfied_at__isnull=True)
        except PendingContextMFA.DoesNotExist:
            raise AuthenticationError("Pending MFA context not found or already satisfied.")

        if pending.is_expired():
            raise AuthenticationError("Pending MFA context has expired.")

        pending.satisfied_at = timezone.now()
        pending.save(update_fields=["satisfied_at"])

        return self._issue_auth_code(
            session=session,
            system_user=pending.system_user,
            client=pending.client,
            redirect_uri=pending.redirect_uri,
            scopes=pending.scopes,
            state=pending.state,
            nonce=pending.nonce,
            code_challenge=pending.code_challenge,
            code_challenge_method=pending.code_challenge_method,
        )

    @transaction.atomic
    def exchange_code(
            self,
            raw_code: str,
            client: SystemClient,
            redirect_uri: str,
            code_verifier: str = "",
            client_secret: str = "",
    ) -> TokenResponse:
        try:
            auth_code = AuthorizationCode.objects.select_related(
                "user", "client", "sso_session",
                "system_user__system", "system_user__organization",
                "system_user__country",
            ).get(code=raw_code, is_used=False)
        except AuthorizationCode.DoesNotExist:
            raise OAuthError("invalid_grant", "Authorization code not found or already used.")

        if auth_code.is_expired():
            raise OAuthError("invalid_grant", "Authorization code expired.")
        if auth_code.client_id != client.id:
            raise OAuthError("invalid_client", "Client mismatch.")
        if auth_code.redirect_uri != redirect_uri:
            raise OAuthError("invalid_grant", "Redirect URI mismatch.")

        client_type = client.client_type
        if client_type == SystemClient.ClientType.M2M:
            raise OAuthError(
                "unsupported_grant_type", "M2M clients must use client_credentials flow."
            )
        if client_type == SystemClient.ClientType.PUBLIC:
            if not auth_code.code_challenge:
                raise OAuthError("invalid_grant", "PKCE required for public clients.")
            if not code_verifier:
                raise OAuthError("invalid_grant", "code_verifier is required.")
            self._verify_pkce(
                code_verifier, auth_code.code_challenge, auth_code.code_challenge_method
            )
        elif client_type == SystemClient.ClientType.CONFIDENTIAL:
            if not client_secret:
                raise OAuthError("invalid_client", "Client secret required.")
            if not self._verify_client_secret(client_secret, client.client_secret_hash):
                raise OAuthError("invalid_client", "Invalid client secret.")
            if auth_code.code_challenge:
                if not code_verifier:
                    raise OAuthError("invalid_grant", "code_verifier is required.")
                self._verify_pkce(
                    code_verifier, auth_code.code_challenge, auth_code.code_challenge_method
                )

        if auth_code.sso_session and auth_code.sso_session.requires_reauth:
            raise OAuthError("session_expired", "Your session requires re-authentication.")

        auth_code.is_used = True
        auth_code.used_at = timezone.now()
        auth_code.save(update_fields=["is_used", "used_at"])

        return self._issue_tokens(
            session=auth_code.sso_session,
            client=client,
            system_user=auth_code.system_user,
            scopes=auth_code.scopes,
            nonce=auth_code.nonce,
        )

    @transaction.atomic
    def refresh_tokens(self, raw_refresh_token: str, client: SystemClient) -> TokenResponse:
        token_hash = hash_value(raw_refresh_token)
        try:
            rt = RefreshToken.objects.select_related(
                "token_set__sso_session", "token_set__user",
                "token_set__system_user__system",
                "token_set__system_user__organization",
                "token_set__system_user__country",
                "token_set__client__system",
            ).get(token_hash=token_hash)
        except RefreshToken.DoesNotExist:
            raise OAuthError("invalid_grant", "Refresh token not found.")

        if rt.is_used or rt.is_revoked:
            rt.token_set.is_active = False
            rt.token_set.save(update_fields=["is_active"])
            self._audit(
                AuditEventType.TOKEN_REFRESH_REUSE,
                rt.token_set.user,
                payload={"token_set_id": str(rt.token_set_id)},
                outcome="failure"
            )
            raise OAuthError(
                "invalid_grant", "Refresh token reuse detected. Session has been revoked."
            )

        ts = rt.token_set
        if not ts.is_active:
            raise OAuthError("invalid_grant", "Token set has been revoked.")

        sso_session = ts.sso_session
        if sso_session and sso_session.is_expired():
            raise OAuthError("invalid_grant", "SSO session has expired.")
        if sso_session and sso_session.requires_reauth:
            raise OAuthError("session_expired", "Re-authentication required.")

        system = ts.system_user.system if ts.system_user else client.system

        if rt.expires_at < timezone.now():
            access = self._get_system_access(sso_session, system)

            if access and access.is_refresh_timed_out():
                raise SystemReauthRequiredError(system=system, session=sso_session)

            # Silent reauth
            rt.is_used = True
            rt.used_at = timezone.now()
            rt.save(update_fields=["is_used", "used_at"])
            ts.is_active = False
            ts.save(update_fields=["is_active"])

            response = self._issue_tokens(
                session=sso_session,
                client=client,
                system_user=ts.system_user,
                scopes=ts.scopes,
            )
            self._audit(
                AuditEventType.TOKEN_REFRESHED,
                ts.user,
                payload={"token_set_id": str(ts.id), "silent_reauth": True}
            )
            return response

        # Normal refresh (token still valid)
        rt.is_used = True
        rt.used_at = timezone.now()
        rt.save(update_fields=["is_used", "used_at"])

        response = self._issue_tokens(
            session=sso_session,
            client=client,
            system_user=ts.system_user,
            scopes=ts.scopes,
            ts=ts,
        )

        new_rt = RefreshToken.objects.filter(token_set=ts).order_by("-created_at").first()
        if new_rt:
            rt.rotated_to = new_rt
            rt.save(update_fields=["rotated_to"])

        self._audit(
            AuditEventType.TOKEN_REFRESHED,
            ts.user,
            payload={"token_set_id": str(ts.id)}
        )
        return response

    def revoke_token(
            self,
            raw_token: str,
            client: SystemClient,
            ip_address: str = ""
    ) -> None:
        token_hash = hash_value(raw_token)
        try:
            rt = RefreshToken.objects.select_related("token_set__user").get(
                token_hash=token_hash,
                token_set__client=client,
            )
        except RefreshToken.DoesNotExist:
            return

        rt.is_revoked = True
        rt.revoked_at = timezone.now()
        rt.save(update_fields=["is_revoked", "revoked_at"])

        self._audit(
            AuditEventType.TOKEN_REVOKED,
            rt.token_set.user,
            ip=ip_address,
            payload={"jti": str(rt.jti)}
        )

    @staticmethod
    def introspect(raw_access_token: str) -> dict:
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

        if at.is_expired() or not at.token_set.is_active:
            return {"active": False}

        payload["active"] = True
        return payload

    @transaction.atomic
    def logout(
            self,
            session: SSOSession,
            reason: str = "logout",
            ip_address: str = ""
    ) -> None:
        session.revoke(reason=reason)
        self._send_backchannel_logout(session)
        self._audit(
            AuditEventType.SESSION_REVOKED,
            session.user,
            ip=ip_address,
            payload={"session_id": str(session.id), "reason": reason}
        )

    @transaction.atomic
    def logout_system(
            self,
            session: SSOSession,
            system: System,
            ip_address: str = "",
    ) -> None:
        TokenSet.objects.filter(
            sso_session=session,
            system_user__system=system,
            is_active=True,
        ).update(is_active=False)

        SSOSessionSystemAccess.objects.filter(
            session=session, system=system,
        ).update(is_active=False, revoked_at=timezone.now())

        self._audit(
            AuditEventType.SESSION_REVOKED, session.user, ip=ip_address,
            system=system,
            payload={
                "session_id": str(session.id),
                "reason": "system_logout",
                "system": system.name,
            },
        )

        still_active = SSOSessionSystemAccess.objects.filter(
            session=session, is_active=True,
        ).exists()
        if not still_active:
            session.revoke(reason="last_system_logout")
            self._send_backchannel_logout(session)

    @transaction.atomic
    def logout_all(
            self,
            user: User,
            reason: str = "global_logout",
            ip_address: str = ""
    ) -> int:
        sessions = SSOSession.objects.filter(user=user, is_active=True)
        count = sessions.count()
        for session in sessions:
            session.revoke(reason=reason)
            self._send_backchannel_logout(session)

        self._audit(
            AuditEventType.LOGOUT_GLOBAL,
            user,
            ip=ip_address,
            payload={"sessions_revoked": count}
        )
        return count

    def ensure_required_identifiers_satisfied(self, user: User, system: System) -> None:
        requirements = self.get_unsatisfied_required_identifiers(user, system)
        if requirements:
            raise IdentifierVerificationRequiredError(requirements)

    @staticmethod
    def get_unsatisfied_required_identifiers(user: User, system: System) -> list:
        requirements = []
        if not user.email_verified:
            requirements.append({
                "identifier_type": IdentifierType.EMAIL,
                "status": "unverified",
                "verification_required": True,
                "can_self_verify": True,
                "value": mask(user.email),
            })
        if not user.phone_verified:
            requirements.append({
                "identifier_type": IdentifierType.PHONE,
                "status": "unverified",
                "verification_required": True,
                "can_self_verify": True,
                "value": mask(user.phone_number),
            })
        return requirements

    @staticmethod
    def _get_or_create_session(
            user: User,
            client: SystemClient,
            auth_method: str,
            ip_address: str = "",
            user_agent: str = "",
            device_id: str = "",
            device_name: str = "",
            reauth_session_id: str = "",
    ) -> SSOSession:
        if reauth_session_id:
            try:
                existing = SSOSession.objects.get(
                    id=reauth_session_id,
                    user=user,
                    is_active=True,
                )
                if not existing.is_expired():
                    existing.extend(SSO_SESSION_TTL)

                    access, _ = SSOSessionSystemAccess.objects.get_or_create(
                        session=existing,
                        system=client.system,
                    )
                    if not access.is_active:
                        access.is_active  = True
                        access.revoked_at = None
                        access.save(update_fields=["is_active", "revoked_at"])

                    return existing
            except SSOSession.DoesNotExist:
                pass

        # Normal login
        raw_token = secrets.token_urlsafe(48)
        session = SSOSession.objects.create(
            user=user,
            initiating_system=client.system,
            session_token_hash=hash_value(raw_token),
            ip_address=ip_address or None,
            user_agent=user_agent,
            device_id=device_id,
            device_name=device_name,
            auth_method=auth_method,
            expires_at=timezone.now() + timedelta(seconds=SSO_SESSION_TTL),
        )
        return session

    def _check_system_mfa(self, session: SSOSession, client: SystemClient) -> None:
        system = client.system

        system_requires_mfa = system.mfa_required
        reauth_window = getattr(system, "mfa_reauth_window_minutes", 0)

        if not system_requires_mfa and not reauth_window:
            return

        allowed_method_names = set(
            system.allowed_mfa_methods or [MFAMethod.SMS, MFAMethod.EMAIL]
        )

        if system_requires_mfa:
            if self._session_mfa_satisfied(session, allowed_method_names, reauth_window_minutes=0):
                pass
            else:
                raise MFARequiredError(
                    MFARequirement(
                        required=True,
                        reason=f"Required by {system.name}",
                        allowed_methods=self._build_allowed_methods(
                            session.user, allowed_method_names
                        ),
                    )
                )

        if reauth_window:
            access = self._get_system_access(session, system)
            if access and access.is_mfa_reauth_required():
                raise MFARequiredError(
                    MFARequirement(
                        required=True,
                        reason=f"Periodic MFA re-verification required by {system.name}",
                        allowed_methods=self._build_allowed_methods(
                            session.user, allowed_method_names
                        ),
                        reauth_window_minutes=reauth_window,
                    )
                )

    @staticmethod
    def _get_system_access(
            session: Optional[SSOSession],
            system: System
    ) -> Optional[SSOSessionSystemAccess]:
        if not session:
            return None
        try:
            return SSOSessionSystemAccess.objects.select_related("system").get(
                session=session, system=system,
            )
        except SSOSessionSystemAccess.DoesNotExist:
            return None

    @staticmethod
    def _session_mfa_satisfied(
            session: SSOSession,
            allowed_method_names: set,
            reauth_window_minutes: int,
    ) -> bool:
        qs = session.mfa_verifications.filter(method__in=allowed_method_names)
        if reauth_window_minutes > 0:
            cutoff = timezone.now() - timedelta(minutes=reauth_window_minutes)
            qs = qs.filter(verified_at__gte=cutoff)
        return qs.exists()

    @staticmethod
    def _resolve_context_mfa_requirement(system_user: SystemUser) -> MFARequirement:
        required = False
        reason = ""
        allowed: list = []
        reauth_window = 0

        role = system_user.role
        organization = system_user.organization

        if role.mfa_required:
            required = True
            reason = f"Required for the {role.name} role"
            if role.mfa_allowed_methods:
                allowed = list(role.mfa_allowed_methods)
            reauth_window = max(reauth_window, role.mfa_reauth_window_minutes)

        if organization:
            for key in ("mfa_required", "mfa_allowed_methods", "mfa_reauth_window_minutes"):
                try:
                    val = OrganizationSettings.objects.get(
                        organization=organization, key=key
                    ).typed_value()
                except OrganizationSettings.DoesNotExist:
                    continue

                if key == "mfa_required" and val:
                    required = True
                    reason = reason or f"Required by {organization.name}"
                elif key == "mfa_allowed_methods" and val:
                    allowed = [m for m in allowed if m in val] if allowed else list(val)
                elif key == "mfa_reauth_window_minutes" and val:
                    reauth_window = max(reauth_window, int(val))

        valid = {MFAMethod.SMS, MFAMethod.EMAIL}
        allowed = [m for m in allowed if m in valid] if allowed else []

        return MFARequirement(
            required=required,
            reason=reason,
            allowed_methods=allowed,
            reauth_window_minutes=reauth_window,
        )

    @staticmethod
    def _build_allowed_methods(user: User, method_names: set) -> list:
        result = []
        for method in (MFAMethod.EMAIL, MFAMethod.SMS):
            if method not in method_names:
                continue
            if method == MFAMethod.EMAIL and user.email_verified:
                result.append({"method": method, "destination": mask(user.email)})
            elif method == MFAMethod.SMS and user.phone_verified:
                result.append({"method": method, "destination": mask(user.phone_number)})
        return result

    @staticmethod
    def _mfa_destination(user: User, method: str) -> Tuple[str, str]:
        if method == MFAMethod.EMAIL:
            if not user.email_verified:
                raise AuthenticationError("Email address is not verified.")
            return IdentifierType.EMAIL, user.email
        if method == MFAMethod.SMS:
            if not user.phone_verified:
                raise AuthenticationError("Phone number is not verified.")
            return IdentifierType.PHONE, user.phone_number
        raise AuthenticationError(f"Unsupported MFA method: {method}")

    @staticmethod
    def _record_mfa_verification(
            session: SSOSession,
            method: str,
            system: System,
            ip_address: str,
    ) -> None:
        SSOSessionMFAVerification.objects.create(
            session=session,
            method=method,
            ip_address=ip_address or None,
            system=system,
        )

    @staticmethod
    def _create_pending_context(
            session: SSOSession,
            system_user: SystemUser,
            requirement: MFARequirement,
            client: SystemClient,
            redirect_uri: str,
            scopes: list,
            state: str,
            nonce: str,
            code_challenge: str,
            code_challenge_method: str,
    ) -> PendingContextMFA:
        PendingContextMFA.objects.filter(
            session=session,
            system_user=system_user,
            satisfied_at__isnull=True,
        ).delete()

        return PendingContextMFA.objects.create(
            session=session,
            system_user=system_user,
            mfa_required_reason=requirement.reason,
            mfa_allowed_methods=[m["method"] for m in requirement.allowed_methods],
            mfa_reauth_window_minutes=requirement.reauth_window_minutes,
            expires_at=timezone.now() + timedelta(minutes=15),
            client=client,
            redirect_uri=redirect_uri,
            scopes=scopes,
            state=state,
            nonce=nonce,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
        )

    @staticmethod
    def _consume_mfa_challenge(
            session: SSOSession,
            client: SystemClient,
            challenge_id: str,
            code: str,
            ip_address: str,
    ) -> PasswordlessChallenge:
        try:
            challenge = PasswordlessChallenge.objects.select_related("client").get(
                id=challenge_id,
                sso_session=session,
                purpose=PasswordlessChallenge.Purpose.MFA,
                is_used=False,
            )
        except PasswordlessChallenge.DoesNotExist:
            raise AuthenticationError("Invalid or expired MFA code.")

        if challenge.client != client:
            raise AuthenticationError("Invalid client for this MFA request.")
        if challenge.is_expired():
            raise AuthenticationError("MFA code has expired. Please request a new one.")

        submitted_hash = hash_value(code)
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
        return challenge

    @transaction.atomic
    def _consume_passwordless_challenge(
            self,
            client: SystemClient,
            challenge_id: str,
            code: str,
            ip_address: str,
            purpose: str,
    ) -> PasswordlessChallenge:
        try:
            challenge = PasswordlessChallenge.objects.select_related("user", "client").get(
                id=challenge_id, purpose=purpose, is_used=False,
            )
        except PasswordlessChallenge.DoesNotExist:
            raise AuthenticationError("Invalid or expired code.")

        if challenge.is_expired():
            raise AuthenticationError("Code has expired. Please request a new one.")
        if challenge.client != client:
            raise AuthenticationError("Invalid client for this authentication request.")

        submitted_hash = hash_value(code)
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
        return challenge

    @staticmethod
    def _issue_auth_code(
            session: SSOSession,
            system_user: SystemUser,
            client: SystemClient,
            redirect_uri: str,
            scopes: list,
            state: str,
            nonce: str,
            code_challenge: str,
            code_challenge_method: str,
    ) -> str:
        raw_code = secrets.token_urlsafe(32)
        AuthorizationCode.objects.create(
            code=raw_code,
            user=session.user,
            client=client,
            sso_session=session,
            system_user=system_user,
            redirect_uri=redirect_uri,
            scopes=scopes,
            state=state,
            nonce=nonce,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
            expires_at=timezone.now() + timedelta(seconds=AUTH_CODE_TTL),
        )
        SSOSessionSystemAccess.objects.get_or_create(
            session=session, system=system_user.system,
        )
        LoginContextSelection.objects.create(
            sso_session=session,
            system_user=system_user,
            organization=system_user.organization,
            country=system_user.country,
            role=system_user.role,
            role_name_snapshot=system_user.role.name,
        )
        return raw_code

    @transaction.atomic
    def _issue_tokens(
            self,
            session: SSOSession,
            client: SystemClient,
            system_user: SystemUser,
            scopes: list,
            nonce: str = "",
            ts: Optional[TokenSet] = None,
    ) -> TokenResponse:
        now = timezone.now()
        perm_ctx = self._perm.resolve(system_user)

        ts = ts or TokenSet.objects.create(
            sso_session=session,
            user=session.user,
            client=client,
            system_user=system_user,
            scopes=scopes,
        )

        access_ttl = client.access_token_ttl or ACCESS_TOKEN_TTL
        at_claims = self._build_access_token_claims(
            system_user=system_user,
            scopes=scopes,
            perm_ctx=perm_ctx,
            now=now,
            ttl=access_ttl,
            nonce=nonce,
        )
        raw_at = self._sign_jwt(at_claims)

        AccessToken.objects.create(
            token_set=ts,
            token_hash=hash_value(raw_at),
            jti=uuid.UUID(at_claims["jti"]),
            expires_at=now + timedelta(seconds=access_ttl),
            role_snapshot=perm_ctx.role if perm_ctx else "",
            permissions_snapshot=list(perm_ctx.permissions) if perm_ctx else [],
        )

        refresh_ttl = client.refresh_token_ttl or REFRESH_TOKEN_TTL
        raw_rt = secrets.token_urlsafe(48)
        RefreshToken.objects.create(
            token_set=ts,
            token_hash=hash_value(raw_rt),
            jti=uuid.uuid4(),
            expires_at=now + timedelta(seconds=refresh_ttl),
        )

        id_claims = self._build_id_token_claims(
            system_user=system_user,
            perm_ctx=perm_ctx,
            client=client,
            scopes=scopes,
            nonce=nonce,
            now=now,
        )
        raw_id = self._sign_jwt(id_claims)

        # Extend the SSO session lifetime on every token issuance
        if session:
            session.extend(SSO_SESSION_TTL)

        system = system_user.system
        access, _ = SSOSessionSystemAccess.objects.get_or_create(
            session=session, system=system,
        )
        access.touch_token_refresh()

        self._audit(
            AuditEventType.TOKEN_ISSUED,
            session.user,
            payload={"token_set_id": str(ts.id), "system": system.name}
        )

        return TokenResponse(
            access_token=raw_at,
            refresh_token=raw_rt,
            id_token=raw_id,
            expires_in=access_ttl,
            scope=" ".join(scopes),
        )

    @staticmethod
    def _build_access_token_claims(
            system_user: SystemUser,
            scopes: list,
            perm_ctx: ResolvedContext,
            now: datetime,
            ttl: int,
            nonce: str,
    ) -> dict:
        claims = {
            "iss": settings.SSO_ISSUER,
            "sub": str(system_user.user.id),
            "aud": str(system_user.system.id),
            "iat": int(now.timestamp()),
            "exp": int((now + timedelta(seconds=ttl)).timestamp()),
            "jti": str(uuid.uuid4()),
            "scope": " ".join(scopes),
            "system_user_id": str(system_user.id),
            "system_id": str(system_user.system.id),
            "country": system_user.country.code,
            "role": perm_ctx.role if perm_ctx else "",
            "permissions": list(perm_ctx.permissions) if perm_ctx else [],
            "branches": perm_ctx.accessible_branch_ids if perm_ctx else [],
        }
        if "email" in scopes:
            claims["email"] = system_user.user.get_email() or ""
        if system_user.organization:
            claims["org_id"]   = str(system_user.organization.id)
            claims["org_name"] = system_user.organization.name
        if nonce:
            claims["nonce"] = nonce
        return claims

    @staticmethod
    def _build_id_token_claims(
            system_user: SystemUser,
            perm_ctx: ResolvedContext,
            client: SystemClient,
            scopes: list,
            nonce: str,
            now: datetime,
    ) -> dict:
        claims = {
            "iss": settings.SSO_ISSUER,
            "sub": str(system_user.user.id),
            "aud": client.client_id,
            "iat": int(now.timestamp()),
            "exp": int((now + timedelta(seconds=3600)).timestamp()),
            "jti": str(uuid.uuid4()),
            "country": system_user.country.code,
        }
        if "email" in scopes:
            claims["email"] = system_user.user.get_email() or ""
        if "profile" in scopes:
            claims["name"]        = system_user.full_name
            claims["given_name"]  = system_user.user.first_name
            claims["family_name"] = system_user.user.last_name
        if "roles" in scopes and perm_ctx:
            claims["role"]        = perm_ctx.role
            claims["permissions"] = list(perm_ctx.permissions)
        if system_user.organization:
            claims["org_id"]   = str(system_user.organization.id)
            claims["org_name"] = system_user.organization.name
        if nonce:
            claims["nonce"] = nonce
        return claims

    @staticmethod
    def _sign_jwt(claims: dict) -> str:
        return jwt.encode(claims, settings.SSO_PRIVATE_KEY, algorithm=JWT_ALGORITHM)

    @staticmethod
    def _rate_limit_passwordless(login_value: str, ip_address: str) -> None:
        window = timezone.now() - timedelta(minutes=10)

        if PasswordlessChallenge.objects.filter(
            delivery_target__iexact=login_value,
            created_at__gte=window,
        ).count() >= 5:
            raise AuthenticationError(
                "Too many codes requested. Please wait a few minutes."
            )

        if ip_address:
            if PasswordlessChallenge.objects.filter(
                ip_requested=ip_address,
                created_at__gte=timezone.now() - timedelta(hours=1),
            ).count() >= 10:
                raise AuthenticationError(
                    "Too many requests from this device. Please try again later."
                )

    @staticmethod
    def _rate_limit_magic_link(email: str, ip_address: str) -> None:
        window = timezone.now() - timedelta(minutes=10)
        if MagicLink.objects.filter(
            delivery_target__iexact=email, created_at__gte=window,
        ).count() >= 3:
            raise AuthenticationError(
                "Too many sign-in links requested. "
                "Please check your inbox or wait a few minutes."
            )

    @staticmethod
    def _rate_limit_otp(destination: str, ip_address: str) -> None:
        window = timezone.now() - timedelta(minutes=10)
        if PasswordlessChallenge.objects.filter(
            delivery_target=destination,
            purpose=PasswordlessChallenge.Purpose.MFA,
            created_at__gte=window,
        ).count() >= 5:
            raise AuthenticationError(
                "Too many MFA codes requested. Please wait a few minutes."
            )

        if ip_address:
            if PasswordlessChallenge.objects.filter(
                ip_requested=ip_address,
                created_at__gte=timezone.now() - timedelta(hours=1),
            ).count() >= 10:
                raise AuthenticationError(
                    "Too many requests from this IP. Try again later."
                )

    @staticmethod
    def _resolve_user_safe(login_value: str, detected_type: str, realm) -> User:
        try:
            return User.objects.get_by_identifier(realm, login_value, detected_type)
        except User.DoesNotExist:
            dummy_bcrypt()
            raise AuthenticationError("Invalid credentials.")

    @staticmethod
    def _resolve_user_and_contact_silent(
            value: str,
            identifier_type: Optional[str] = None
    ) -> Tuple[Optional[User], Optional[str]]:
        # noinspection PyBroadException
        try:
            detected = identifier_type or detect_identifier_type(value)
            user = User.objects.get_by_identifier(None, value, detected)
            return user, detected
        except Exception:
            return None, None

    def _handle_failed_login(self, user: User, ip: str, system: System) -> None:
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

    @staticmethod
    def _reset_lock(user: User) -> None:
        user.failed_login_attempts = 0
        user.locked_until = None
        user.save(update_fields=["failed_login_attempts", "locked_until"])

    @staticmethod
    def _verify_client_secret(raw_secret: str, stored_hash: str) -> bool:
        if not raw_secret or not stored_hash:
            return False
        # noinspection PyBroadException
        try:
            return bcrypt.checkpw(
                raw_secret.encode("utf-8"), stored_hash.encode("utf-8")
            )
        except Exception:
            return False

    @staticmethod
    def _verify_pkce(verifier: str, challenge: str, method: str) -> None:
        if method == "S256":
            digest   = hashlib.sha256(verifier.encode()).digest()
            computed = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
            if not hmac.compare_digest(computed, challenge):
                raise OAuthError("invalid_grant", "PKCE verification failed.")
        elif method == "plain":
            if not hmac.compare_digest(verifier, challenge):
                raise OAuthError("invalid_grant", "PKCE verification failed.")

    def _send_backchannel_logout(self, session: SSOSession) -> None:
        pass  # TODO: implement per-system backchannel logout notifications

    @staticmethod
    def _audit(
            event_type: str,
            user: Optional[User] = None,
            ip: str = "",
            system: Optional[System] = None,
            payload: Optional[dict] = None,
            outcome: str = "success",
    ) -> None:
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