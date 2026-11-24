from django.urls import path

from entra import views as entra_views

from . import views

urlpatterns = [
    path("", views.home, name="console-home"),
    path("login/", views.login_view, name="console-login"),
    path("logout/", views.logout_view, name="console-logout"),
    path("new/", views.create_org, name="console-create-org"),
    path("invite/<str:token>/", views.invite, name="console-invite"),
    path("<uuid:org_id>/", views.org_dashboard, name="console-org"),
    path("<uuid:org_id>/action/", views.org_action, name="console-action"),
    path("<uuid:org_id>/microsoft/connect/", entra_views.connect, name="entra-connect"),
    path("<uuid:org_id>/microsoft/action/", entra_views.action, name="entra-action"),
    path("microsoft/consented/", entra_views.consented, name="entra-consented"),
    path("microsoft/signed-in/", entra_views.signed_in, name="entra-signed-in"),
]
