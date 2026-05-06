from django.core.exceptions import ValidationError, ObjectDoesNotExist, PermissionDenied
from django.core.serializers.json import DjangoJSONEncoder
from django.http import JsonResponse


class ResponseProvider:
    @staticmethod
    def _response(success: bool, message: str, status: int, error=None, **kwargs) -> JsonResponse:
        payload = {
            "success": success,
            "message": message,
            **kwargs
        }

        if error:
            payload["error"] = error

        return JsonResponse(payload, status=status, encoder=DjangoJSONEncoder)

    @classmethod
    def handle_exception(cls, ex: Exception) -> JsonResponse:
        if isinstance(ex, ValidationError):
            if hasattr(ex, "messages"):
                error_message = ", ".join(ex.messages)
            else:
                error_message = str(ex)
            return cls.bad_request(message="Validation Error", error=error_message)
        elif isinstance(ex, ObjectDoesNotExist):
            return cls.not_found(error=str(ex))
        elif isinstance(ex, PermissionDenied):
            return cls.forbidden(error=str(ex))
        else:
            return cls.server_error()

    @classmethod
    def success(cls, *, message="Success", **kwargs):
        return cls._response(True, message, 200, **kwargs)

    @classmethod
    def created(cls, *, message="Created", **kwargs):
        return cls._response(True, message, 201, **kwargs)

    @classmethod
    def accepted(cls, *, message="Accepted", **kwargs):
        return cls._response(True, message, 202, **kwargs)

    @classmethod
    def bad_request(cls, *, message="Bad Request", error=None, **kwargs):
        return cls._response(False, message, 400, error=error, **kwargs)

    @classmethod
    def unauthorized(cls, *, message="Unauthorized", error=None, **kwargs):
        return cls._response(False, message, 401, error=error, **kwargs)

    @classmethod
    def forbidden(cls, *, message="Forbidden", error=None, **kwargs):
        return cls._response(False, message, 403, error=error, **kwargs)

    @classmethod
    def not_found(cls, *, message="Resource Not Found", error=None, **kwargs):
        return cls._response(False, message, 404, error=error, **kwargs)

    @classmethod
    def conflict(cls, *, message="Conflict", error=None, **kwargs):
        return cls._response(False, message, 409, error=error, **kwargs)

    @classmethod
    def too_many_requests(cls, *, message="Rate Limit Exceeded", error=None, **kwargs):
        return cls._response(False, message, 429, error=error, **kwargs)

    @classmethod
    def server_error(cls, *, message="Internal Server Error", error=None, **kwargs):
        return cls._response(False, message, 500, error=error, **kwargs)

    @classmethod
    def not_implemented(cls, *, message="Not Implemented", error=None, **kwargs):
        return cls._response(False, message, 501, error=error, **kwargs)

    @classmethod
    def service_unavailable(cls, *, message="Service Unavailable", error=None, **kwargs):
        return cls._response(False, message, 503, error=error, **kwargs)

    @classmethod
    def invalid_session(cls):
        return cls.unauthorized(
            error="invalid_session",
            message="Your session is invalid, expired, or has been revoked. Please authenticate again."
        )
