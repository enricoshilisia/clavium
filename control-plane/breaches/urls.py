from django.urls import path

from . import views

urlpatterns = [path("mine/", views.MyBreachesView.as_view(), name="my-breaches")]
