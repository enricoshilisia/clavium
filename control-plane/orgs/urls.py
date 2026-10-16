from django.urls import path

from . import views

urlpatterns = [
    path("", views.OrganizationListCreateView.as_view(), name="org-list-create"),
    path("<uuid:org_id>/members/", views.MembershipListView.as_view(), name="member-list-add"),
    path(
        "<uuid:org_id>/members/<uuid:membership_id>/remove/",
        views.MemberRemoveView.as_view(),
        name="member-remove",
    ),
    path("<uuid:org_id>/audit-log/", views.AuditLogView.as_view(), name="audit-log"),
]
