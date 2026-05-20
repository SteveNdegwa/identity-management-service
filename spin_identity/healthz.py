import os

from django.http import JsonResponse


class HealthCheckMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.path == '/healthz':
            return JsonResponse(
                {
                    'success': True,
                    'app_name': 'idms',
                    'env': os.environ.get('ENV'),
                }
            )
        return self.get_response(request)
