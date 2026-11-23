from django.urls import path

from . import views

urlpatterns = [
    path("keyring/", views.KeyringView.as_view(), name="sync-keyring"),
    path("items/", views.ItemsView.as_view(), name="sync-items"),
    path("reset/", views.ResetView.as_view(), name="sync-reset"),
]
