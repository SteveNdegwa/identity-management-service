from django.urls import path

from systems import views

urlpatterns = [
    path("", views.system_list_view, name="system-list"),
    path("create/", views.system_create_view, name="system-create"),
    path("<str:system_id>/", views.system_detail_view, name="system-detail"),
    path("<str:system_id>/update/", views.system_update_view, name="system-update"),
    path("<str:system_id>/deactivate/", views.system_deactivate_view, name="system-deactivate"),
    path("<str:system_id>/reactivate/", views.system_reactivate_view, name="system-reactivate"),

    path("<str:system_id>/countries/", views.system_country_list_view, name="system-country-list"),
    path("<str:system_id>/countries/add/", views.system_country_add_view, name="system-country-add"),
    path("<str:system_id>/countries/remove/", views.system_country_remove_view, name="system-country-remove"),

    path("<str:system_id>/clients/", views.client_list_view, name="system-client-list"),
    path("<str:system_id>/clients/create/", views.client_create_view, name="system-client-create"),
    path("clients/<str:client_id>/", views.client_detail_view, name="system-client-detail"),
    path("clients/<str:client_id>/update/", views.client_update_view, name="system-client-update"),
    path("clients/<str:client_id>/deactivate/", views.client_deactivate_view, name="system-client-deactivate"),
    path("clients/<str:client_id>/reactivate/", views.client_reactivate_view, name="system-client-reactivate"),

    path("<str:system_id>/settings/", views.setting_list_view, name="system-setting-list"),
    path("<str:system_id>/settings/set/", views.setting_set_view, name="system-setting-set"),
    path("settings/<str:setting_id>/", views.setting_detail_view, name="system-setting-detail"),
]
