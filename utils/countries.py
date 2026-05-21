from typing import Iterable, Optional

from django.core.exceptions import ValidationError


def _country_lookup(value: str):
    from base.models import Country

    clean_value = str(value or "").strip()
    if not clean_value:
        return None

    try:
        return Country.objects.get(id=clean_value)
    except (Country.DoesNotExist, ValidationError, ValueError):
        pass

    try:
        return Country.objects.get(code__iexact=clean_value)
    except Country.DoesNotExist:
        return None


def country_value_from_data(data: dict) -> Optional[str]:
    return data.get("country_id") or data.get("country_code") or data.get("country")


def has_country_value(data: dict) -> bool:
    return country_value_from_data(data) not in (None, "")


def get_country_from_data(data: dict):
    return _country_lookup(country_value_from_data(data))


def get_countries_from_values(values: Iterable) -> list:
    countries = []
    seen_ids = set()
    for value in values or []:
        if isinstance(value, dict):
            value = country_value_from_data(value)
        country = _country_lookup(value)
        if not country or country.id in seen_ids:
            continue
        countries.append(country)
        seen_ids.add(country.id)
    return countries
