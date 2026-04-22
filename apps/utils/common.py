import hashlib
import json
import logging
import random
from typing import Optional, Any

import bcrypt

logger = logging.getLogger(__name__)


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
    bcrypt.checkpw(
        b"dummy",
        b"$2b$12$aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    )


def get_client_ip(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        return x_forwarded_for.split(',')[0]
    return request.META.get('REMOTE_ADDR')


def sanitize_data(data: Optional[dict]) -> Optional[dict]:
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
            data = request.POST.dict()

        else:
            try:
                data = json.loads(request.body)
            except json.JSONDecodeError:
                data = {}

        return data

    except Exception as e:
        logger.exception('get_request_data exception:', e)
        return {}