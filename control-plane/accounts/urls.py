from django.urls import path

from . import views

urlpatterns = [
    path("register/", views.RegisterView.as_view(), name="account-register"),
    path("devices/register/", views.DeviceRegisterView.as_view(), name="device-register"),
    path("devices/", views.DeviceListView.as_view(), name="device-list"),
    path("devices/<uuid:device_id>/revoke/", views.DeviceRevokeView.as_view(), name="device-revoke"),
]
