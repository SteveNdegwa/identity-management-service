from django.urls import include, path

urlpatterns = [
    path('accounts/', include('accounts.urls')),
    path('auth/', include('sso.urls')),
    path('organizations/', include('organizations.urls')),
    path('permissions/', include('permissions.urls')),
    path('systems/', include('systems.urls')),
]
