import hashlib
import logging
import secrets
from urllib.parse import urlencode, urlsplit, urlunsplit

from authlib.integrations.base_client.errors import MismatchingStateError
from authlib.integrations.django_client import OAuth
from django.conf import settings
from django.contrib.auth import get_user_model, login, logout
from django.core.exceptions import ValidationError
from django.core.validators import validate_email
from django.db import DatabaseError
from django.http import HttpResponse, HttpResponseBadRequest
from django.shortcuts import redirect, render
from django.urls import reverse
from django.views.decorators.http import require_GET, require_POST

from .models import AuditEvent

logger = logging.getLogger(__name__)


def profile_text(value, limit=150):
    # Optional profile claims are display text, never an identity or authorization source.
    return " ".join(value.split())[:limit] if isinstance(value, str) else ""


def sync_profile(user, claims):
    first = profile_text(claims.get("given_name"))
    last = profile_text(claims.get("family_name"))
    if not first and not last:
        first = profile_text(claims.get("name"))
    user.first_name = first
    user.last_name = last
    user.save(update_fields=["first_name", "last_name"])
    return user.get_full_name() or profile_text(claims.get("preferred_username"))


def log_oidc_failure(stage, error):
    # OAuth exception strings may contain token responses, credentials or request URLs.
    # Log only the Python exception class and a small allowlist of protocol error codes.
    known_codes = {
        "invalid_client",
        "invalid_grant",
        "invalid_request",
        "unauthorized_client",
        "access_denied",
        "invalid_scope",
        "server_error",
        "temporarily_unavailable",
        "login_required",
        "interaction_required",
        "consent_required",
        "mismatching_state",
    }
    code = getattr(error, "error", None)
    if not isinstance(code, str) or code not in known_codes:
        code = "no_especificado"
    logger.warning("Fallo OIDC (%s): tipo=%s codigo=%s", stage, type(error).__name__, code)


def login_start_url():
    target = urlsplit(settings.OIDC_REDIRECT_URI)
    if (
        target.scheme not in {"http", "https"}
        or not target.hostname
        or target.username
        or target.password
        or (target.scheme != "https" and not settings.DEBUG)
    ):
        raise ValueError("Configura un callback OIDC válido.")
    return urlunsplit((target.scheme, target.netloc, reverse("login"), "", ""))


def same_origin(first, second):
    def origin(value):
        parts = urlsplit(value)
        return (
            parts.scheme,
            parts.hostname,
            parts.port or (443 if parts.scheme == "https" else 80),
        )

    return origin(first) == origin(second)


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
        canonical_url = login_start_url()
        if not same_origin(request.build_absolute_uri("/"), canonical_url):
            # Establish the cookie on the callback's host before generating state/nonce/PKCE.
            return redirect(canonical_url)
        options = {"prompt": "login"} if request.session.get("force_reauthentication") else {}
        return oidc_client().authorize_redirect(request, settings.OIDC_REDIRECT_URI, **options)
    except Exception as error:
        log_oidc_failure("inicio", error)
        return HttpResponse("SSO no disponible. Contacta al administrador.", status=503)


@require_GET
def callback(request):
    state = request.GET.get("state", "")
    stored_state = (
        bool(request.session.get(f"_state_keycloak_{state}")) if len(state) <= 512 else False
    )
    cookie_received = bool(request.COOKIES.get(settings.SESSION_COOKIE_NAME))
    session_loaded = bool(request.session.session_key)
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
        import time

        remaining = int(claims["exp"]) - int(time.time())
        if remaining <= 0:
            raise ValueError("Token caducado")
        display_name = sync_profile(user, claims)
        login(request, user)
        request.session["roles"] = roles
        request.session["oidc_display_name"] = display_name
        # Contact information only: never used to grant roles or restrict breach queries.
        contact_email = claims.get("email", "")
        try:
            if not isinstance(contact_email, str) or len(contact_email) > 254:
                raise ValidationError("Invalid email claim")
            validate_email(contact_email)
        except ValidationError:
            contact_email = ""
        request.session["oidc_contact_email"] = contact_email
        request.session.set_expiry(min(1800, remaining))
        request.session.pop("force_reauthentication", None)
        request.session.pop("oidc_logout_state", None)
        # Never retain access/refresh/ID tokens in the session or database.
        AuditEvent.objects.create(actor=user, action="login")
        return redirect("dashboard")
    except MismatchingStateError as error:
        log_oidc_failure("callback", error)
        logger.warning(
            "Estado OIDC no recuperado: cookie_recibida=%s sesion_cargada=%s estado_guardado=%s",
            cookie_received,
            session_loaded,
            stored_state,
        )
        # Reject this callback without flushing other valid pending logins or an existing login.
        try:
            restart_url = login_start_url()
        except ValueError:
            restart_url = reverse("login")
        return render(request, "analysis/login_error.html", {"login_url": restart_url}, status=400)
    except Exception as error:
        log_oidc_failure("callback", error)
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
