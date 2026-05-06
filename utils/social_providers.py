from django.core.exceptions import ValidationError
from django.db import models


class SocialProvider(models.TextChoices):
    GOOGLE = "google", "Google"
    APPLE = "apple", "Apple"
    FACEBOOK = "facebook", "Facebook"
    MICROSOFT = "microsoft", "Microsoft"
    GITHUB = "github", "GitHub"
    LINKEDIN = "linkedin", "LinkedIn"


def normalize_social_provider(provider: str) -> str:
    value = (provider or "").strip().lower()
    if not value:
        raise ValidationError("Social provider is required.")
    if value not in SocialProvider.values:
        allowed = ", ".join(SocialProvider.values)
        raise ValidationError(f"Unsupported social provider '{provider}'. Allowed values: {allowed}.")
    return value


def normalize_social_provider_list(providers) -> list[str]:
    if providers in (None, ""):
        return []
    if not isinstance(providers, list):
        raise ValidationError("Social providers must be provided as a list.")

    normalized = []
    seen = set()
    for provider in providers:
        value = normalize_social_provider(provider)
        if value in seen:
            continue
        seen.add(value)
        normalized.append(value)
    return normalized

