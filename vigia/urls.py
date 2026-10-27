from django.urls import path

from analysis import auth, views

urlpatterns = [
    path("", views.dashboard, name="dashboard"),
    path("auth/login/", auth.sign_in, name="login"),
    path("auth/callback/", auth.callback, name="callback"),
    path("auth/logout/", auth.sign_out, name="logout"),
    path("auth/logout/callback/", auth.logout_callback, name="logout_callback"),
    path("upload/", views.upload, name="upload"),
    path("results/<uuid:pk>/", views.result, name="result"),
    path("health/", views.health, name="health"),
]
