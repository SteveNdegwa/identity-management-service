from django.urls import path

from permissions import views

urlpatterns = [
    path("systems/<str:system_id>/categories/", views.category_list_view, name="permission-category-list"),
    path(
        "systems/<str:system_id>/categories/create/",
        views.category_create_view,
        name="permission-category-create"
    ),
    path("categories/<str:category_id>/", views.category_detail_view, name="permission-category-detail"),
    path("categories/<str:category_id>/update/", views.category_update_view, name="permission-category-update"),

    path("systems/<str:system_id>/permissions/", views.permission_list_view, name="permission-list"),
    path("systems/<str:system_id>/permissions/create/", views.permission_create_view, name="permission-create"),
    path("items/<str:permission_id>/", views.permission_detail_view, name="permission-detail"),
    path("items/<str:permission_id>/update/", views.permission_update_view, name="permission-update"),

    path("systems/<str:system_id>/roles/", views.role_list_view, name="role-list"),
    path("systems/<str:system_id>/roles/create/", views.role_create_view, name="role-create"),
    path("roles/<str:role_id>/", views.role_detail_view, name="role-detail"),
    path("roles/<str:role_id>/update/", views.role_update_view, name="role-update"),
    path("roles/<str:role_id>/deactivate/", views.role_deactivate_view, name="role-deactivate"),
    path("roles/<str:role_id>/reactivate/", views.role_reactivate_view, name="role-reactivate"),

    path(
        "system-users/<str:system_user_id>/overrides/",
        views.override_list_view,
        name="permission-override-list"
    ),
    path(
        "system-users/<str:system_user_id>/overrides/create/",
        views.override_create_view,
        name="permission-override-create"
    ),
    path("overrides/<str:override_id>/", views.override_detail_view, name="permission-override-detail"),
    path("overrides/<str:override_id>/revoke/", views.override_revoke_view, name="permission-override-revoke"),
]
