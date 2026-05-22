import hashlib
import json
import logging
import random
from typing import Any

import bcrypt

logger = logging.getLogger(__name__)

DUMMY_BCRYPT_HASH = bcrypt.hashpw(
    b"dummy-password",
    bcrypt.gensalt()
)


def hash_value(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def mask(value: str) -> str:
    if "@" in value:
        local, _, domain = value.partition("@")
        return f"{local[0]}{'*' * max(1, len(local) - 2)}{local[-1]}@{domain}"
    if len(value) > 4:
        return value[:2] + "*" * (len(value) - 4) + value[-2:]
    return "****"


def generate_otp() -> str:
    return f"{random.SystemRandom().randint(0, 999999):06d}"


def dummy_bcrypt():
    bcrypt.checkpw(b"dummy", DUMMY_BCRYPT_HASH)


def get_client_ip(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        return x_forwarded_for.split(',')[0]
    return request.META.get('REMOTE_ADDR')


def sanitize_data(data: dict | None) -> dict | None:
    sensitive_keys = {"password", "old_password", "new_password"}
    if data is None:
        return None
    def _sanitize(obj: Any) -> Any:
        if isinstance(obj, dict):
            return {
                k: ("****" if k.lower() in sensitive_keys else _sanitize(v))
                for k, v in obj.items()
            }
        elif isinstance(obj, list):
            return [_sanitize(item) for item in obj]
        else:
            return obj
    return _sanitize(data)


def parse_form_value(value: Any) -> Any:
    if not isinstance(value, str):
        return value

    clean_value = value.strip()
    if not clean_value:
        return value
    if clean_value[0] not in "[{":
        return value

    try:
        return json.loads(clean_value)
    except json.JSONDecodeError:
        return value


def parse_form_data(data: dict) -> dict:
    return {key: parse_form_value(value) for key, value in data.items()}


def get_request_data(request) -> dict:
    try:
        if request is None:
            return {"data": {}, "files": {}}

        method = request.method
        content_type = request.META.get('CONTENT_TYPE', '')

        if method == 'GET':
            data = request.GET.dict()

        elif 'application/json' in content_type:
            try:
                data = json.loads(request.body)
            except json.JSONDecodeError:
                data = {}

        elif 'multipart/form-data' in content_type or \
                'application/x-www-form-urlencoded' in content_type:
            data = parse_form_data(request.POST.dict())

        else:
            try:
                data = json.loads(request.body)
            except json.JSONDecodeError:
                data = {}

        return data

    except Exception as e:
        logger.exception('get_request_data exception:', e)
        return {}
