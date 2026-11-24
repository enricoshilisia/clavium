from django.urls import path

from . import views

urlpatterns = [
    path("", views.TeamListView.as_view(), name="team-list"),
    path("key/", views.AccountKeyView.as_view(), name="team-account-key"),
    path("<uuid:team_id>/", views.TeamDetailView.as_view(), name="team-detail"),
    path("<uuid:team_id>/members/", views.MembersView.as_view(), name="team-members"),
    path("<uuid:team_id>/members/<uuid:account_id>/", views.MemberDetailView.as_view(), name="team-member"),
    path("<uuid:team_id>/grants/", views.GrantsView.as_view(), name="team-grants"),
    path("<uuid:team_id>/items/", views.ItemsView.as_view(), name="team-items"),
    path("<uuid:team_id>/rotate/", views.RotateView.as_view(), name="team-rotate"),
    path("<uuid:team_id>/groups/", views.GroupRulesView.as_view(), name="team-groups"),
]
