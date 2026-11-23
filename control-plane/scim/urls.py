from django.urls import path

from . import views

urlpatterns = [
    path("ServiceProviderConfig", views.service_provider_config),
    path("Users", views.users),
    path("Users/<uuid:member_id>", views.user_detail),
    path("Groups", views.groups),
]
