import hashlib
import logging
import secrets
from urllib.parse import urlencode, urlsplit, urlunsplit

from authlib.integrations.django_client import OAuth
from django.conf import settings
from django.contrib.auth import get_user_model, login, logout
from django.db import DatabaseError
from django.http import HttpResponse, HttpResponseBadRequest
from django.shortcuts import redirect, render
from django.views.decorators.http import require_GET, require_POST

from .models import AuditEvent

logger = logging.getLogger(__name__)


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
        options = {"prompt": "login"} if request.session.get("force_reauthentication") else {}
        return oidc_client().authorize_redirect(request, settings.OIDC_REDIRECT_URI, **options)
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
        request.session.pop("force_reauthentication", None)
        request.session.pop("oidc_logout_state", None)
        # Never retain access/refresh/ID tokens in the session or database.
        AuditEvent.objects.create(actor=user, action="login")
        return redirect("dashboard")
    except Exception:
        logout(request)
        request.session["force_reauthentication"] = True
        return HttpResponseBadRequest("No se pudo validar el inicio de sesión.")


@require_POST
def sign_out(request):
    actor_id = request.user.pk if request.user.is_authenticated else None
    # End local access before contacting Discovery. An unavailable IdP must not preserve login.
    logout(request)
    request.session["force_reauthentication"] = True
    if actor_id is None:
        return redirect("dashboard")
    try:
        AuditEvent.objects.create(actor_id=actor_id, action="logout")
    except DatabaseError:
        logger.warning("No fue posible registrar el cierre de sesión local.")
    try:
        metadata = oidc_client().load_server_metadata()
        issuer = urlsplit(settings.OIDC_ISSUER)
        endpoint = urlsplit(metadata["end_session_endpoint"])
        if (
            metadata.get("issuer") != settings.OIDC_ISSUER
            or endpoint.scheme not in {"http", "https"}
            or (endpoint.scheme, endpoint.netloc) != (issuer.scheme, issuer.netloc)
            or endpoint.username
            or endpoint.password
            or endpoint.query
            or endpoint.fragment
        ):
            raise ValueError("Endpoint de cierre de sesión inválido")
        origin = urlsplit(settings.OIDC_REDIRECT_URI)
        return_uri = settings.OIDC_POST_LOGOUT_REDIRECT_URI or urlunsplit(
            (origin.scheme, origin.netloc, "/auth/logout/callback/", "", "")
        )
        target = urlsplit(return_uri)
        if (
            (target.scheme, target.netloc) != (origin.scheme, origin.netloc)
            or target.scheme not in {"http", "https"}
            or (target.scheme != "https" and not settings.DEBUG)
            or target.path != "/auth/logout/callback/"
            or target.query
            or target.fragment
            or target.username
            or target.password
        ):
            raise ValueError("URI de retorno inválida")
        state = secrets.token_urlsafe(32)
        request.session["oidc_logout_state"] = state
        # client_id supports Keycloak's logout confirmation without persisting an ID token.
        return redirect(
            urlunsplit(endpoint)
            + "?"
            + urlencode(
                {
                    "client_id": settings.OIDC_CLIENT_ID,
                    "post_logout_redirect_uri": return_uri,
                    "state": state,
                }
            )
        )
    except Exception:
        logger.warning("Sesión local cerrada; no fue posible iniciar el cierre SSO.")
        return render(request, "analysis/logged_out.html", {"sso_unavailable": True})


@require_GET
def logout_callback(request):
    expected = request.session.get("oidc_logout_state")
    supplied = request.GET.get("state", "")
    if (
        not expected
        or not supplied
        or not supplied.isascii()
        or len(supplied) > 128
        or not secrets.compare_digest(expected, supplied)
    ):
        return HttpResponseBadRequest("No se pudo validar el retorno del cierre de sesión.")
    request.session.pop("oidc_logout_state", None)
    # Do not flush here: an older tab must not terminate a newer login.
    if request.user.is_authenticated:
        return redirect("dashboard")
    return render(request, "analysis/logged_out.html")


def is_admin(request):
    return request.user.is_authenticated and settings.OIDC_ADMIN_ROLE in request.session.get(
        "roles", []
    )
