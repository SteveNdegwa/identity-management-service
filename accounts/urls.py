from django.urls import path
from . import views

urlpatterns = [
    # Self-registration
    path("register/", views.register_view, name="account-register"),
    path("register/link/", views.register_link_view, name="account-register-link"),

    # Claim (invite) flow
    path("claim/inspect/", views.claim_inspect_view, name="account-claim-inspect"),
    path("claim/", views.claim_view, name="account-claim"),

    # Own profile
    path("me/", views.me_view, name="account-me"),
    path("me/edit/", views.me_update_view, name="account-me-update"),

    # Identifier management
    path("me/identifiers/", views.identifier_list_view, name="account-identifiers"),
    path("me/identifiers/add/", views.identifier_add_view, name="account-identifier-add"),
    path(
        "me/identifiers/<str:identifier_id>/verify/",
        views.identifier_verify_view,
        name="account-identifier-verify"
    ),
    path(
        "me/identifiers/<str:identifier_id>/primary/",
        views.identifier_promote_view,
        name="account-identifier-primary"
    ),
    path(
        "me/identifiers/<str:identifier_id>/",
        views.identifier_remove_view,
        name="account-identifier-remove"
    ),

    # Admin actions
    path(
        "system-users/provision/",
        views.provision_system_user_view,
        name="account-provision-system-user"
    ),
    path(
        "system-users/<str:system_user_id>/suspend/",
        views.suspend_system_user_view,
        name="account-suspend"
    ),
    path(
        "system-users/<str:system_user_id>/restore/",
        views.restore_system_user_view,
        name="account-restore"
    ),
]