from django.urls import path
from . import views

urlpatterns = [
    # Organizations
    path("", views.organization_list_view, name="organization-list"),
    path("<str:organization_id>/", views.organization_detail_view, name="organization-detail"),
    path("<str:organization_id>/update/", views.organization_update_view, name="organization-update"),
    path("<str:organization_id>/deactivate/", views.organization_deactivate_view, name="organization-deactivate"),
    path("<str:organization_id>/reactivate/", views.organization_reactivate_view, name="organization-reactivate"),

    # Organization countries
    path("<str:organization_id>/countries/", views.org_country_list_view, name="org-country-list"),
    path("<str:organization_id>/countries/add/", views.org_country_add_view, name="org-country-add"),
    path("countries/<str:org_country_id>/update/", views.org_country_update_view, name="org-country-update"),
    path(
        "countries/<str:org_country_id>/deactivate/",
        views.org_country_deactivate_view,
        name="org-country-deactivate"
    ),

    # Branches
    path("<str:organization_id>/branches/", views.branch_list_view, name="branch-list"),
    path("<str:organization_id>/branches/create/", views.branch_create_view, name="branch-create"),
    path("branches/<str:branch_id>/", views.branch_detail_view, name="branch-detail"),
    path("branches/<str:branch_id>/update/", views.branch_update_view, name="branch-update"),
    path("branches/<str:branch_id>/deactivate/", views.branch_deactivate_view, name="branch-deactivate"),
    path("branches/<str:branch_id>/reactivate/", views.branch_reactivate_view, name="branch-reactivate"),

    # Settings
    path("<str:organization_id>/settings/", views.settings_list_view, name="org-settings-list"),
    path("<str:organization_id>/settings/set/", views.settings_set_view, name="org-settings-set"),
    path(
        "<str:organization_id>/settings/<str:key>/delete/",
        views.settings_delete_view,
        name="org-settings-delete"
    ),

    # Onboarding
    path("onboarding/", views.onboarding_create_view, name="onboarding-create"),
    path("onboarding/<str:onboarding_id>/", views.onboarding_detail_view, name="onboarding-detail"),
    path("onboarding/<str:onboarding_id>/update/", views.onboarding_update_view, name="onboarding-update"),
    path("onboarding/<str:onboarding_id>/countries/add/", views.onboarding_country_add_view, name="onboarding-country-add"),
    path("onboarding/countries/<str:country_request_id>/update/", views.onboarding_country_update_view, name="onboarding-country-update"),
    path("onboarding/countries/<str:country_request_id>/remove/", views.onboarding_country_remove_view, name="onboarding-country-remove"),
    path(
        "<str:organization_id>/countries/onboarding/",
        views.organization_country_onboarding_create_view,
        name="organization-country-onboarding-create"
    ),
    path("onboarding/<str:onboarding_id>/submit/", views.onboarding_submit_view, name="onboarding-submit"),
    path(
        "onboarding/<str:onboarding_id>/documents/upload/",
        views.onboarding_upload_document_view,
        name="onboarding-upload-document"
    ),
    path(
        "onboarding/documents/<str:document_id>/remove/",
        views.onboarding_remove_document_view,
        name="onboarding-remove-document"
    ),

    # Reviewer / Admin flows
    path(
        "onboarding/<str:onboarding_id>/start-review/",
        views.onboarding_start_review_view,
        name="onboarding-start-review"
    ),
    path(
        "onboarding/<str:onboarding_id>/request-documents/",
        views.onboarding_request_documents_view,
        name="onboarding-request-documents"
    ),
    path(
        "onboarding/documents/<str:document_id>/review/",
        views.onboarding_review_document_view,
        name="onboarding-review-document"
    ),
    path("onboarding/<str:onboarding_id>/approve/", views.onboarding_approve_view, name="onboarding-approve"),
    path("onboarding/<str:onboarding_id>/reject/", views.onboarding_reject_view, name="onboarding-reject"),
    path("onboarding/<str:onboarding_id>/complete/", views.onboarding_complete_view, name="onboarding-complete"),
    path("onboarding/<str:onboarding_id>/note/", views.onboarding_add_note_view, name="onboarding-add-note"),
]
