from django.urls import path, include

urlpatterns = [
    path("accounts/", include("apps.accounts.urls")),
    path("auth/", include("apps.sso.urls")),
    path("organizations/", include("apps.organizations.urls")),
]