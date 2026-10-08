from django.contrib import admin
from django.urls import include, path

from django.db import connection
from django.http import JsonResponse

from accounts import api as acc


def healthz(request):
    try:
        with connection.cursor() as c:
            c.execute("select 1")
        return JsonResponse({"ok": True})
    except Exception:
        return JsonResponse({"ok": False}, status=503)

urlpatterns = [
    path("healthz", healthz),
    path("app/admin/", admin.site.urls),                # yalnız VPN (Caddy)
    path("app/", include("hosting.panel_urls")),
    path("v1/auth/register", acc.RegisterView.as_view()),
    path("v1/auth/verify", acc.VerifyView.as_view()),
    path("v1/auth/login", acc.LoginView.as_view()),
    path("v1/auth/logout", acc.LogoutView.as_view()),
    path("v1/me", acc.MeView.as_view()),
    path("v1/", include("hosting.urls")),
]
