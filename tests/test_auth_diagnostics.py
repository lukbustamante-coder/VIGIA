import logging
from unittest.mock import patch

import pytest
from authlib.integrations.base_client.errors import OAuthError


@pytest.fixture(autouse=True)
def config(settings):
    settings.DEBUG = True
    settings.SECURE_SSL_REDIRECT = False


@pytest.mark.django_db
@pytest.mark.parametrize(
    "error,code",
    [
        (RuntimeError("private-token-and-password"), "no_especificado"),
        (
            OAuthError(error="invalid_client", description="private-token-and-password"),
            "invalid_client",
        ),
        (
            OAuthError(
                error="private-token-and-password", description="private-token-and-password"
            ),
            "no_especificado",
        ),
    ],
)
def test_callback_diagnostic_never_logs_sensitive_exception_details(client, caplog, error, code):
    caplog.set_level(logging.WARNING, logger="analysis.auth")
    with patch("analysis.auth.oidc_client") as factory:
        factory.return_value.authorize_access_token.side_effect = error
        response = client.get("/auth/callback/")
    assert response.status_code == 400
    assert f"Fallo OIDC (callback): tipo={type(error).__name__} codigo={code}" in caplog.text
    assert "private-token-and-password" not in caplog.text
    assert b"private-token-and-password" not in response.content
    assert "_auth_user_id" not in client.session


@pytest.mark.django_db
def test_signin_diagnostic_is_safe_and_keeps_public_error_generic(client, caplog):
    caplog.set_level(logging.WARNING, logger="analysis.auth")
    with patch("analysis.auth.oidc_client", side_effect=RuntimeError("private-token-and-password")):
        response = client.get("/auth/login/")
    assert response.status_code == 503
    assert "Fallo OIDC (inicio): tipo=RuntimeError codigo=no_especificado" in caplog.text
    assert "private-token-and-password" not in caplog.text
    assert b"RuntimeError" not in response.content
