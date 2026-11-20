from django.urls import path

from . import django_views as views

urlpatterns = [
    path("search/", views.search),
    path("ping/<host>/", views.ping),
    path("profile/", views.ProfileView.as_view()),
]
