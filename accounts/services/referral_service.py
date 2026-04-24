import secrets
from typing import Iterable, Optional

from django.db import transaction
from django.utils import timezone

from accounts.models import Referral, SystemUser, SystemUserStatus


class ReferralServiceError(Exception):
    pass


class ReferralService:
    @transaction.atomic
    def ensure_referral_code(self, system_user: SystemUser) -> Optional[str]:
        if not system_user.system.referrals_enabled:
            return system_user.referral_code

        if system_user.referral_code:
            return system_user.referral_code

        while True:
            code = secrets.token_urlsafe(8).replace("-", "").replace("_", "")[:10].upper()
            if not SystemUser.objects.filter(referral_code=code).exists():
                system_user.referral_code = code
                system_user.save(update_fields=["referral_code"])
                return code

    @transaction.atomic
    def ensure_system_referral_codes(self, system) -> int:
        if not system.referrals_enabled:
            return 0

        updated = 0
        for system_user in SystemUser.objects.filter(system=system, referral_code__isnull=True):
            self.ensure_referral_code(system_user)
            updated += 1
        for system_user in SystemUser.objects.filter(system=system, referral_code=""):
            self.ensure_referral_code(system_user)
            updated += 1
        return updated

    @transaction.atomic
    def attach_referral(self, referred: SystemUser, referral_code: str) -> Referral:
        system = referred.system
        if not system.referrals_enabled:
            raise ReferralServiceError("This system does not allow referrals.")
        if referred.status != SystemUserStatus.ACTIVE:
            raise ReferralServiceError("Only active system users can attach referrals.")
        if Referral.objects.filter(referred=referred).exists():
            raise ReferralServiceError("A referral is already attached to this system user.")

        clean_code = (referral_code or "").strip().upper()
        if not clean_code:
            raise ReferralServiceError("referral_code is required.")

        try:
            referrer = SystemUser.objects.select_related("system").get(
                system=system,
                referral_code=clean_code,
            )
        except SystemUser.DoesNotExist:
            raise ReferralServiceError("Referral code is invalid.")

        if referrer.id == referred.id:
            raise ReferralServiceError("You cannot refer yourself.")
        if referrer.status != SystemUserStatus.ACTIVE:
            raise ReferralServiceError("Referrer must be active.")

        referral = Referral.objects.create(
            referrer=referrer,
            referred=referred,
            system=system,
            referral_code=clean_code,
            is_verified=system.auto_verify_referrals,
            verified_at=timezone.now() if system.auto_verify_referrals else None,
        )
        return referral

    @transaction.atomic
    def verify_referral(self, referral: Referral) -> Referral:
        if referral.is_verified:
            return referral

        referral.is_verified = True
        referral.verified_at = timezone.now()
        referral.save(update_fields=["is_verified", "verified_at"])
        return referral

    @transaction.atomic
    def reward_referral(self, referral: Referral) -> Referral:
        if not referral.is_verified:
            raise ReferralServiceError("An unverified referral cannot be rewarded.")
        if referral.is_rewarded:
            return referral

        referral.is_rewarded = True
        referral.rewarded_at = timezone.now()
        referral.save(update_fields=["is_rewarded", "rewarded_at"])
        return referral

    @transaction.atomic
    def reward_referrals(
        self,
        referrer: SystemUser,
        referral_ids: Optional[Iterable[str]] = None,
    ) -> list[Referral]:
        qs = Referral.objects.filter(
            referrer=referrer,
            is_verified=True,
            is_rewarded=False,
        ).select_related("referrer", "referred", "system")

        if referral_ids:
            qs = qs.filter(id__in=list(referral_ids))

        referrals = list(qs)
        for referral in referrals:
            self.reward_referral(referral)
        return referrals
