from django.urls import path

from analysis import auth, views

urlpatterns = [
    path("", views.dashboard, name="dashboard"),
    path("favicon.ico", views.favicon, name="favicon"),
    path("analisis/correos/", views.dashboard, {"module": "eml"}, name="email_analysis"),
    path("analisis/archivos/", views.dashboard, {"module": "file"}, name="file_analysis"),
    path("analisis/urls/", views.dashboard, {"module": "url"}, name="url_analysis"),
    path("analisis/urls/enviar/", views.submit_url, name="submit_url"),
    path("analisis/filtraciones/", views.breach_lookup, name="breach_lookup"),
    path("auth/login/", auth.sign_in, name="login"),
    path("auth/callback/", auth.callback, name="callback"),
    path("auth/logout/", auth.sign_out, name="logout"),
    path("auth/logout/callback/", auth.logout_callback, name="logout_callback"),
    path("upload/", views.upload, name="upload"),
    path("results/<uuid:pk>/", views.result, name="result"),
    path("health/", views.health, name="health"),
]
