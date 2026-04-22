import functools
from typing import Optional, Union

from django.core.exceptions import PermissionDenied

from utils.extended_request import ExtendedRequest
from utils.response_provider import ResponseProvider


def user_login_required(required_permission: Optional[Union[str, list[str]]] = None):
    def decorator(func):
        @functools.wraps(func)
        def wrapper(request: ExtendedRequest, *args, **kwargs):
            if not request.is_authenticated:
                return ResponseProvider.unauthorized()

            # Permission check
            if required_permission:
                perms = (
                    required_permission.split(",")
                    if isinstance(required_permission, str)
                    else list(required_permission)
                )
                missing = [p for p in perms if p not in request.user_permissions]
                if missing:
                    return ResponseProvider.forbidden(
                        error="permission_denied",
                        message=f"You do not have the required permission(s): {', '.join(missing)}",
                    )

            return func(request, *args, **kwargs)

        return wrapper

    if callable(required_permission):
        _func = required_permission
        required_permission = None
        return decorator(_func)
    return decorator


def sso_session_required(func):
    @functools.wraps(func)
    def wrapper(request, *args, **kwargs):
        sso_session = request.session
        if not sso_session:
            return ResponseProvider.unauthorized(
                error="invalid_session",
                message="Your session is invalid, expired, or has been revoked. Please authenticate again."
            )
        if sso_session.requires_reauth:
            return ResponseProvider.unauthorized(
                error="requires_reauth",
                message=sso_session.reauth_reason
            )
        return func(request, *args, **kwargs)
    return wrapper