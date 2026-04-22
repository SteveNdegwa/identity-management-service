import threading
from typing import Optional, Dict, Any

from apps.utils.common import get_client_ip


class RequestContext:
    _storage = threading.local()

    _expected_attrs = {
        "request": None,
        "user_id": None,
        "system_user_id": None,
        "system_client_id": None,
        "is_authenticated": None,
        "token_jti": None,
        "sso_session_id": None,
        "ip_address": None,
        "user_agent": None,
        "session_key": None,
        "request_id": None,
        "request_data": None,
        "view_name": None,
        "view_args": None,
        "view_kwargs": None,
        "response_status": None,
        "response_data": None,
        "exception_type": None,
        "exception_message": None,
        "exception_traceback": None,
        "request_method": None,
        "request_path": None,
        "is_secure": False,
        "started_at": None,
    }

    @classmethod
    def _init_storage(cls) -> None:
        if not hasattr(cls._storage, "__initialized__"):
            for key, default in cls._expected_attrs.items():
                setattr(cls._storage, key, default)
            cls._storage.__initialized__ = True

    @classmethod
    def set(cls, request=None, **kwargs) -> None:
        cls._init_storage()

        for key, value in kwargs.items():
            if key in cls._expected_attrs:
                setattr(cls._storage, key, value)

        if request:
            cls._storage.request = request

            if getattr(cls._storage, "user_id", None) is None and hasattr(request, "user_id"):
                cls._storage.user_id = request.user_id

            if not getattr(cls._storage, "ip_address", None):
                cls._storage.ip_address = get_client_ip(request)

            if not getattr(cls._storage, "user_agent", None):
                cls._storage.user_agent = request.META.get("HTTP_USER_AGENT", "")

            if not getattr(cls._storage, "session_key", None):
                cls._storage.session_key = getattr(request.session, "session_key", None)

            cls._storage.request_method = getattr(request, "method", None)
            cls._storage.request_path = getattr(request, "path", None)
            cls._storage.is_secure = request.is_secure() if hasattr(request, "is_secure") else False

    @classmethod
    def get(cls) -> Dict[str, Optional[Any]]:
        cls._init_storage()
        return {k: getattr(cls._storage, k, v) for k, v in cls._expected_attrs.items()}

    @classmethod
    def update(cls, **kwargs) -> None:
        cls._init_storage()

        for key, value in kwargs.items():
            if key in cls._expected_attrs:
                setattr(cls._storage, key, value)

    @classmethod
    def clear(cls) -> None:
        for key in cls._expected_attrs:
            if hasattr(cls._storage, key):
                delattr(cls._storage, key)

        if hasattr(cls._storage, "__initialized__"):
            delattr(cls._storage, "__initialized__")

    @classmethod
    def exists(cls) -> bool:
        return getattr(cls._storage, "request_id", None) is not None