from django.urls import path

from . import views

urlpatterns = [
    path("", views.StartView.as_view()),
    path("<uuid:link_id>/", views.PollView.as_view()),
    path("<uuid:link_id>/info/", views.InfoView.as_view()),
    path("<uuid:link_id>/approve/", views.ApproveView.as_view()),
    path("<uuid:link_id>/deny/", views.DenyView.as_view()),
]
