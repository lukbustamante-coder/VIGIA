from unittest.mock import Mock, patch
from urllib.parse import parse_qs, urlsplit

import pytest
from django.contrib.auth import get_user_model
from django.contrib.sessions.backends.db import SessionStore
from django.test import Client

from analysis.auth import oidc_client
from analysis.models import AuditEvent

pytestmark = pytest.mark.django_db


@pytest.fixture(autouse=True)
def config(settings):
    settings.DEBUG = True
    settings.SECURE_SSL_REDIRECT = False
    settings.SESSION_COOKIE_SECURE = False
    settings.CSRF_COOKIE_SECURE = False
    settings.OIDC_ISSUER = "https://sso.example.org/realms/company"
    settings.OIDC_CLIENT_ID = "vigia"
    settings.OIDC_REDIRECT_URI = "http://localhost:8000/auth/callback/"
    settings.OIDC_POST_LOGOUT_REDIRECT_URI = ""


@pytest.fixture
def user():
    return get_user_model().objects.create_user(username="logout-user")


@pytest.fixture
def metadata(settings):
    return {
        "issuer": settings.OIDC_ISSUER,
        "authorization_endpoint": settings.OIDC_ISSUER + "/protocol/openid-connect/auth",
        "end_session_endpoint": settings.OIDC_ISSUER + "/protocol/openid-connect/logout",
    }


def test_logout_ends_local_session_before_contacting_sso_and_retains_no_tokens(
    client, user, metadata
):
    client.force_login(user)
    session = client.session
    session["roles"] = ["vigia-admin"]
    session.save()
    old_key = session.session_key
    app = Mock()

    def discover():
        assert SessionStore(session_key=old_key).load() == {}
        return metadata

    app.load_server_metadata.side_effect = discover
    with patch("analysis.auth.oidc_client", return_value=app):
        response = client.post("/auth/logout/?next=https://attacker.example")
    assert response.status_code == 302
    location = urlsplit(response.url)
    assert location.scheme == "https" and location.netloc == "sso.example.org"
    params = parse_qs(location.query)
    assert params["client_id"] == ["vigia"]
    assert params["post_logout_redirect_uri"] == ["http://localhost:8000/auth/logout/callback/"]
    assert params["state"] == [client.session["oidc_logout_state"]]
    assert set(params) == {"client_id", "post_logout_redirect_uri", "state"}
    assert "_auth_user_id" not in client.session and "roles" not in client.session
    assert client.session["force_reauthentication"] is True
    assert AuditEvent.objects.filter(action="logout", actor=user).count() == 1
    assert client.get("/upload/").status_code == 302


def test_logout_requires_post_and_csrf(user, metadata, settings):
    client = Client(enforce_csrf_checks=True)
    client.force_login(user)
    with patch("analysis.auth.oidc_client") as app:
        assert client.get("/auth/logout/").status_code == 405
        assert client.post("/auth/logout/").status_code == 403
        app.assert_not_called()
    assert "_auth_user_id" in client.session
    client.get("/")
    token = client.cookies[settings.CSRF_COOKIE_NAME].value
    with patch("analysis.auth.oidc_client") as factory:
        factory.return_value.load_server_metadata.return_value = metadata
        assert (
            client.post(
                "/auth/logout/", {"csrfmiddlewaretoken": token}, HTTP_ORIGIN="http://testserver"
            ).status_code
            == 302
        )
    assert "_auth_user_id" not in client.session


@pytest.mark.parametrize(
    "endpoint",
    [
        "https://attacker.example/logout",
        "javascript:alert(1)",
        "https://sso.example.org/logout?next=https://attacker.example",
    ],
)
def test_untrusted_logout_endpoint_never_receives_browser(client, user, metadata, endpoint):
    client.force_login(user)
    metadata["end_session_endpoint"] = endpoint
    with patch("analysis.auth.oidc_client") as factory:
        factory.return_value.load_server_metadata.return_value = metadata
        response = client.post("/auth/logout/")
    assert response.status_code == 200
    assert response.context["sso_unavailable"]
    assert "_auth_user_id" not in client.session


@pytest.mark.parametrize(
    "return_uri",
    [
        "https://attacker.example/auth/logout/callback/",
        "http://localhost:8000/other/",
        "http://localhost:8000/auth/logout/callback/?next=https://attacker.example",
    ],
)
def test_invalid_logout_return_uri_falls_back_to_local_logout(
    settings, client, user, metadata, return_uri
):
    settings.OIDC_POST_LOGOUT_REDIRECT_URI = return_uri
    client.force_login(user)
    with patch("analysis.auth.oidc_client") as factory:
        factory.return_value.load_server_metadata.return_value = metadata
        response = client.post("/auth/logout/")
    assert response.status_code == 200
    assert response.context["sso_unavailable"]
    assert "_auth_user_id" not in client.session


def test_idp_failure_keeps_local_logout_and_forces_next_authentication(client, user):
    client.force_login(user)
    with patch("analysis.auth.oidc_client", side_effect=RuntimeError("unavailable")):
        response = client.post("/auth/logout/")
    assert response.status_code == 200
    assert "_auth_user_id" not in client.session
    with patch("analysis.auth.oidc_client") as factory:
        factory.return_value.authorize_redirect.side_effect = RuntimeError("unavailable")
        assert client.get("/auth/login/", HTTP_HOST="localhost:8000").status_code == 503
        assert client.get("/auth/login/", HTTP_HOST="localhost:8000").status_code == 503
        assert all(
            call.kwargs == {"prompt": "login"}
            for call in factory.return_value.authorize_redirect.call_args_list
        )
    assert client.session["force_reauthentication"]


def test_logout_callback_state_is_required_one_time_and_cannot_end_new_login(
    client, user, metadata
):
    client.force_login(user)
    with patch("analysis.auth.oidc_client") as factory:
        factory.return_value.load_server_metadata.return_value = metadata
        client.post("/auth/logout/")
    state = client.session["oidc_logout_state"]
    assert client.get("/auth/logout/callback/").status_code == 400
    assert client.get("/auth/logout/callback/", {"state": "wrong"}).status_code == 400
    assert client.get("/auth/logout/callback/", {"state": "á"}).status_code == 400
    assert client.session["oidc_logout_state"] == state
    response = client.get("/auth/logout/callback/", {"state": state})
    assert response.status_code == 200
    assert "Sesión local cerrada" in response.content.decode()
    assert client.get("/auth/logout/callback/", {"state": state}).status_code == 400
    assert "_auth_user_id" not in client.session


def test_logout_return_does_not_clear_newer_authenticated_session(client, user, metadata):
    client.force_login(user)
    with patch("analysis.auth.oidc_client") as factory:
        factory.return_value.load_server_metadata.return_value = metadata
        client.post("/auth/logout/")
    state = client.session["oidc_logout_state"]
    client.force_login(user)
    assert client.get("/auth/logout/callback/", {"state": state}).status_code == 302
    assert "_auth_user_id" in client.session


def test_next_login_has_real_oidc_prompt_login_parameter(client, user, metadata):
    client.force_login(user)
    app = oidc_client()
    with (
        patch("analysis.auth.oidc_client", return_value=app),
        patch.object(app, "load_server_metadata", return_value=metadata),
    ):
        client.post("/auth/logout/")
        response = client.get("/auth/login/", HTTP_HOST="localhost:8000")
    query = parse_qs(urlsplit(response.url).query)
    assert query["prompt"] == ["login"]
    assert query["code_challenge_method"] == ["S256"]


def test_anonymous_logout_never_triggers_provider_logout(client):
    with patch("analysis.auth.oidc_client") as factory:
        assert client.post("/auth/logout/").status_code == 302
    factory.assert_not_called()


def test_csp_allows_only_configured_sso_origin_for_logout_redirect(client, settings):
    policy = client.get("/health/")["Content-Security-Policy"]
    assert "form-action 'self' https://sso.example.org;" in policy
    assert "attacker.example" not in policy and "form-action *" not in policy
    settings.OIDC_ISSUER = "https://sso.example.org'; form-action *"
    policy = client.get("/health/")["Content-Security-Policy"]
    assert "form-action 'self';" in policy
    assert "form-action *" not in policy
    settings.OIDC_ISSUER = "https://[invalid"
    response = client.get("/health/")
    assert response.status_code == 200
    assert "form-action 'self';" in response["Content-Security-Policy"]
