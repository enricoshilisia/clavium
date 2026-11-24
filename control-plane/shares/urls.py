from django.urls import path

from . import views

urlpatterns = [
    path("", views.ShareListView.as_view(), name="share-list"),
    path("<uuid:share_id>/", views.ShareDetailView.as_view(), name="share-detail"),
    path("<uuid:share_id>/meta/", views.ShareMetaView.as_view(), name="share-meta"),
    path("<uuid:share_id>/open/", views.ShareOpenView.as_view(), name="share-open"),
]
