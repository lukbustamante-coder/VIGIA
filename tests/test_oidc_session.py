import logging
import time
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

import pytest
from django.contrib.auth import get_user_model
from joserfc import jwt
from joserfc.jwk import RSAKey

from analysis.auth import oidc_client

pytestmark = pytest.mark.django_db


@pytest.fixture(autouse=True)
def config(settings):
    settings.DEBUG = True
    settings.SECURE_SSL_REDIRECT = False
    settings.SESSION_COOKIE_SECURE = False
    settings.OIDC_ISSUER = "https://sso.example.org/realms/company"
    settings.OIDC_CLIENT_ID = "vigia"
    settings.OIDC_REDIRECT_URI = "http://testserver/auth/callback/"


@pytest.mark.parametrize("host", ["127.0.0.1:8000", "localhost:8000"])
def test_login_uses_callback_origin_before_creating_state(client, settings, host):
    settings.OIDC_REDIRECT_URI = "http://localhost:8000/auth/callback/"
    if host == "localhost:8000":
        settings.OIDC_REDIRECT_URI = "http://127.0.0.1:8000/auth/callback/"
    with patch("analysis.auth.oidc_client") as provider:
        response = client.get("/auth/login/?next=https://attacker.example", HTTP_HOST=host)
    assert response.status_code == 302
    assert response.url == settings.OIDC_REDIRECT_URI.replace("/auth/callback/", "/auth/login/")
    assert "_state_keycloak_" not in str(dict(client.session))
    provider.assert_not_called()


def test_login_invalid_callback_does_not_redirect(client, settings):
    settings.OIDC_REDIRECT_URI = "javascript:alert(1)"
    with patch("analysis.auth.oidc_client") as provider:
        assert client.get("/auth/login/").status_code == 503
    provider.assert_not_called()


def test_missing_cookie_state_is_rejected_before_token_exchange(client, caplog):
    app = oidc_client()
    caplog.set_level(logging.WARNING, logger="analysis.auth")
    with (
        patch("analysis.auth.oidc_client", return_value=app),
        patch.object(app, "fetch_access_token") as fetch,
    ):
        response = client.get(
            "/auth/callback/", {"state": "private-state-value", "code": "private-code-value"}
        )
    assert response.status_code == 400
    fetch.assert_not_called()
    assert "cookie_recibida=False" in caplog.text
    assert "estado_guardado=False" in caplog.text
    assert "private-state-value" not in caplog.text and "private-code-value" not in caplog.text
    assert "private-state-value" not in response.content.decode()
    assert response.context["login_url"] == "http://testserver/auth/login/"
    assert "_auth_user_id" not in client.session


def test_invalid_callback_does_not_destroy_valid_pending_or_authenticated_session(client, caplog):
    user = get_user_model().objects.create_user(username="valid-pending-user")
    client.force_login(user)
    session = client.session
    session["roles"] = ["vigia-admin"]
    session["_state_keycloak_valid-pending-state"] = {
        "data": {"nonce": "private-nonce", "code_verifier": "private-verifier"},
        "exp": time.time() + 300,
    }
    session.save()
    app = oidc_client()
    with (
        patch("analysis.auth.oidc_client", return_value=app),
        patch.object(app, "fetch_access_token") as fetch,
    ):
        response = client.get("/auth/callback/", {"state": "invalid-state", "code": "test-code"})
    fetch.assert_not_called()
    assert response.status_code == 400
    assert "_auth_user_id" in client.session
    assert client.session["roles"] == ["vigia-admin"]
    assert "_state_keycloak_valid-pending-state" in client.session
    assert "private-verifier" not in caplog.text and "private-nonce" not in caplog.text


def test_isolated_cookie_allows_signed_login_despite_other_django_cookie(client, settings):
    assert settings.SESSION_COOKIE_NAME == "vigia_sessionid"
    assert settings.CSRF_COOKIE_NAME == "vigia_csrftoken"
    key = RSAKey.generate_key(parameters={"kid": "session-test"})
    app = oidc_client()
    metadata = {
        "issuer": settings.OIDC_ISSUER,
        "authorization_endpoint": settings.OIDC_ISSUER + "/protocol/openid-connect/auth",
        "id_token_signing_alg_values_supported": ["RS256"],
    }
    with (
        patch("analysis.auth.oidc_client", return_value=app),
        patch.object(app, "load_server_metadata", return_value=metadata),
    ):
        response = client.get("/auth/login/")
        assert response.cookies[settings.SESSION_COOKIE_NAME]["httponly"]
        assert response.cookies[settings.SESSION_COOKIE_NAME]["samesite"] == "Lax"
        params = parse_qs(urlsplit(response.url).query)
        client.cookies["sessionid"] = "cookie-from-another-localhost-app"
        claims = {
            "iss": settings.OIDC_ISSUER,
            "sub": "session-test-user",
            "aud": "vigia",
            "iat": int(time.time()),
            "exp": int(time.time()) + 300,
            "nonce": params["nonce"][0],
            "given_name": "María José",
            "family_name": "Pérez Soto",
        }
        token = jwt.encode({"alg": "RS256", "kid": "session-test"}, claims, key)
        with (
            patch.object(
                app,
                "fetch_access_token",
                return_value={"id_token": token, "access_token": "test-access-token"},
            ) as fetch,
            patch.object(app, "fetch_jwk_set", return_value={"keys": [key.as_dict(private=False)]}),
        ):
            callback = {"state": params["state"][0], "code": "test-code"}
            assert client.get("/auth/callback/", callback).status_code == 302
            assert "_auth_user_id" in client.session
            assert client.session["oidc_display_name"] == "María José Pérez Soto"
            assert "María José Pérez Soto" in client.get("/").content.decode()
            # A stale refresh must not consume a second token or log out the successful login.
            assert client.get("/auth/callback/", callback).status_code == 400
            assert "_auth_user_id" in client.session
            assert fetch.call_count == 1
