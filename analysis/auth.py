import hashlib
from urllib.parse import urlsplit

from authlib.integrations.django_client import OAuth
from django.conf import settings
from django.contrib.auth import get_user_model, login, logout
from django.http import HttpResponse, HttpResponseBadRequest
from django.shortcuts import redirect
from django.views.decorators.http import require_GET, require_POST

from .models import AuditEvent


def oidc_client():
    issuer = settings.OIDC_ISSUER
    if not issuer or (urlsplit(issuer).scheme != "https" and not settings.DEBUG):
        raise ValueError("Configura un emisor OIDC HTTPS.")
    oauth = OAuth()
    return oauth.register(
        "keycloak",
        client_id=settings.OIDC_CLIENT_ID,
        client_secret=settings.OIDC_CLIENT_SECRET,
        server_metadata_url=f"{issuer}/.well-known/openid-configuration",
        client_kwargs={
            "scope": "openid profile email",
            "code_challenge_method": "S256",
            "timeout": 10,
        },
        claims_options={
            "iss": {"essential": True, "value": issuer},
            "sub": {"essential": True},
            "exp": {"essential": True},
        },
    )


@require_GET
def sign_in(request):
    try:
        return oidc_client().authorize_redirect(request, settings.OIDC_REDIRECT_URI)
    except Exception:
        return HttpResponse("SSO no disponible. Contacta al administrador.", status=503)


@require_GET
def callback(request):
    try:
        token = oidc_client().authorize_access_token(
            request,
            claims_options={
                "iss": {"essential": True, "value": settings.OIDC_ISSUER},
                "sub": {"essential": True},
                "exp": {"essential": True},
            },
            leeway=30,
        )
        claims = token["userinfo"]
        # Authorization uses only claims from the verified ID token.
        if claims.get("iss") != settings.OIDC_ISSUER or not claims.get("sub"):
            raise ValueError("Identidad inválida")
        identity = hashlib.sha256(f"{claims['iss']}|{claims['sub']}".encode()).hexdigest()
        user, created = get_user_model().objects.get_or_create(username=f"oidc_{identity}")
        if not user.is_active:
            raise ValueError("Usuario desactivado")
        if created:
            user.set_unusable_password()
            user.save(update_fields=["password"])
        roles = claims.get("resource_access", {}).get(settings.OIDC_CLIENT_ID, {}).get("roles", [])
        if not isinstance(roles, list) or any(not isinstance(role, str) for role in roles):
            raise ValueError("Roles inválidos")
        login(request, user)
        request.session["roles"] = roles
        import time

        remaining = int(claims["exp"]) - int(time.time())
        if remaining <= 0:
            logout(request)
            raise ValueError("Token caducado")
        request.session.set_expiry(min(1800, remaining))
        # Never retain access/refresh/ID tokens in the session or database.
        AuditEvent.objects.create(actor=user, action="login")
        return redirect("dashboard")
    except Exception:
        logout(request)
        return HttpResponseBadRequest("No se pudo validar el inicio de sesión.")


@require_POST
def sign_out(request):
    if request.user.is_authenticated:
        AuditEvent.objects.create(actor=request.user, action="logout")
    logout(request)
    return redirect("dashboard")


def is_admin(request):
    return request.user.is_authenticated and settings.OIDC_ADMIN_ROLE in request.session.get(
        "roles", []
    )
