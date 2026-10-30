import json
from types import SimpleNamespace
from unittest.mock import patch

import pytest
import requests
from django.contrib.auth import get_user_model
from django.test import Client
from django.urls import reverse

from analysis.breaches import API, MAX_RESPONSE_BYTES, lookup_account
from analysis.models import AuditEvent, Submission


def api_response(status=200, body=None, raw=None):
    content = raw if raw is not None else json.dumps(body).encode()
    return SimpleNamespace(
        status_code=status, iter_content=lambda **kwargs: iter([content]), close=lambda: None
    )


def record(**kwargs):
    return {
        "Name": "ExampleIncident",
        "Title": "Example incident",
        "BreachDate": "2024-02-03",
        "DataClasses": ["Email addresses", "Passwords"],
        **kwargs,
    }


@pytest.fixture(autouse=True)
def config(settings):
    settings.DEBUG = True
    settings.SECURE_SSL_REDIRECT = False
    settings.HIBP_ENABLED = True
    settings.HIBP_API_KEY = "test-key"
    settings.BREACH_PROVIDER = "hibp"


@pytest.fixture
def signed_in(client, db):
    user = get_user_model().objects.create_user(username="breach-reader")
    client.force_login(user)
    session = client.session
    session["oidc_email"] = "test@example.org"
    session.save()
    return client, user


def test_hibp_uses_fixed_endpoint_encoded_email_and_key_only_in_headers():
    with patch("analysis.breaches.requests.get", return_value=api_response(body=[record()])) as get:
        result = lookup_account("name+tag@example.org", "test-key")
    assert result["status"] == "found"
    (url,) = get.call_args.args
    assert url == API + "name%2Btag%40example.org"
    options = get.call_args.kwargs
    assert options["headers"]["hibp-api-key"] == "test-key"
    assert options["headers"]["user-agent"].startswith("VIGIA")
    assert options["params"] == {"truncateResponse": "false", "includeUnverified": "false"}
    assert options["allow_redirects"] is False and options["timeout"] == (5, 15)
    assert "test-key" not in url and "test-key" not in str(result)


@pytest.mark.parametrize(
    "http,expected",
    [
        (404, "no_records"),
        (401, "authentication_error"),
        (403, "access_denied"),
        (429, "quota_exceeded"),
        (302, "unavailable"),
        (500, "unavailable"),
    ],
)
def test_only_no_record_response_is_classified_as_no_records(http, expected):
    with patch("analysis.breaches.requests.get", return_value=api_response(http)):
        assert lookup_account("test@example.org", "key")["status"] == expected


@pytest.mark.parametrize(
    "body",
    [
        {"error": "provider error"},
        ["unexpected"],
        [record(Title=None, Name=None)],
        [record(DataClasses="Passwords")],
    ],
)
def test_malformed_json_schema_does_not_become_a_negative_lookup(body):
    with patch("analysis.breaches.requests.get", return_value=api_response(body=body)):
        assert lookup_account("test@example.org", "key")["status"] == "invalid_response"


def test_response_limit_and_timeout_do_not_imply_account_is_safe():
    with patch(
        "analysis.breaches.requests.get",
        return_value=api_response(raw=b"x" * (MAX_RESPONSE_BYTES + 1)),
    ):
        assert lookup_account("test@example.org", "key")["status"] == "invalid_response"
    with patch(
        "analysis.breaches.requests.get", side_effect=requests.Timeout("secret-address@example.org")
    ):
        result = lookup_account("test@example.org", "key")
    assert result == {"status": "timeout"}
    assert "secret-address" not in str(result)


def test_missing_key_and_empty_provider_records():
    with patch("analysis.breaches.requests.get") as get:
        assert lookup_account("test@example.org", "")["status"] == "not_configured"
    get.assert_not_called()
    with patch("analysis.breaches.requests.get", return_value=api_response(body=[])):
        assert lookup_account("test@example.org", "key")["status"] == "no_records"


def test_anonymous_queries_require_sso(client):
    with patch("analysis.views.lookup_account") as lookup:
        get = client.get(reverse("breach_lookup"))
        post = client.post(reverse("breach_lookup"), {"email": "test@example.org", "consent": "on"})
    assert get.status_code == post.status_code == 302
    assert "/auth/login/" in get["Location"]
    lookup.assert_not_called()


def test_new_module_is_available_without_api_key_and_does_not_transmit_on_get(signed_in, settings):
    client, _ = signed_in
    settings.HIBP_API_KEY = ""
    with patch("analysis.views.lookup_account") as lookup:
        response = client.get(reverse("breach_lookup") + "?email=private@example.org")
    html = response.content.decode()
    assert response.status_code == 200
    assert 'aria-current="page"' in html and "Filtraciones de cuentas" in html
    assert "La consulta automática no está habilitada" in html
    for name in ["Have I Been Pwned", "HPI Identity Leak Checker", "F-Secure", "Malwarebytes"]:
        assert name in html
    assert "private@example.org" not in html
    assert 'type="password"' not in html
    assert 'name="email"' not in html
    assert response["Cache-Control"] == "no-store"
    lookup.assert_not_called()


@pytest.mark.parametrize("email,consent", [("not-an-email", "on"), ("test@example.org", "")])
def test_invalid_or_unconsented_queries_are_rejected(signed_in, email, consent):
    client, _ = signed_in
    with patch("analysis.views.lookup_account") as lookup:
        response = client.post(reverse("breach_lookup"), {"email": email, "consent": consent})
    assert response.status_code == 400
    assert not AuditEvent.objects.filter(action="breach_lookup").exists()
    lookup.assert_not_called()


def test_valid_lookup_displays_metadata_but_does_not_retain_address_or_response(signed_in):
    client, user = signed_in
    address = "private-query@example.org"
    session = client.session
    session["oidc_email"] = address
    session.save()
    with patch(
        "analysis.breaches.requests.get",
        return_value=api_response(
            body=[record(Description="PRIVATE DESCRIPTION", Password="SECRET PASSWORD")]
        ),
    ):
        response = client.post(reverse("breach_lookup"), {"email": address, "consent": "on"})
    html = response.content.decode()
    assert response.status_code == 200
    assert "Se encontraron registros de exposición" in html and "Example incident" in html
    assert "Direcciones de correo" in html and "Contraseñas" in html
    assert "SECRET PASSWORD" not in html and "PRIVATE DESCRIPTION" not in html
    assert Submission.objects.count() == 0
    audit = AuditEvent.objects.get(action="breach_lookup", actor=user)
    assert audit.submission_id is None
    assert address not in str(audit.__dict__)
    assert client.session["oidc_email"] == address
    assert "Example incident" not in str(dict(client.session))
    assert "ni confirma acceso actual" in html


def test_external_data_is_escaped_in_results(signed_in):
    client, _ = signed_in
    with patch(
        "analysis.breaches.requests.get",
        return_value=api_response(
            body=[
                record(
                    Title="<script>alert(1)</script>", DataClasses=["<img src=x onerror=alert(1)>"]
                )
            ]
        ),
    ):
        response = client.post(
            reverse("breach_lookup"), {"email": "test@example.org", "consent": "on"}
        )
    html = response.content.decode()
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html and "&lt;img" in html


@pytest.mark.parametrize("http", [401, 429, 503])
def test_provider_errors_never_display_no_records_or_leak_key(signed_in, http):
    client, _ = signed_in
    with patch("analysis.breaches.requests.get", return_value=api_response(http)):
        response = client.post(
            reverse("breach_lookup"), {"email": "test@example.org", "consent": "on"}
        )
    html = response.content.decode()
    assert "Sin registros en la fuente" not in html and "test-key" not in html


@pytest.mark.parametrize("global_limit", [False, True])
def test_persistent_rate_limits_block_provider_calls(signed_in, global_limit):
    client, user = signed_in
    actor = get_user_model().objects.create_user(username="other-reader") if global_limit else user
    AuditEvent.objects.bulk_create(
        [
            AuditEvent(actor=actor, action="breach_lookup")
            for _ in range(200 if global_limit else 20)
        ]
    )
    with patch("analysis.views.lookup_account") as lookup:
        response = client.post(
            reverse("breach_lookup"), {"email": "test@example.org", "consent": "on"}
        )
    assert response.status_code == 429
    assert "Consulta temporalmente limitada" in response.content.decode()
    lookup.assert_not_called()


def test_disabled_provider_ignores_forged_post(signed_in, settings):
    client, _ = signed_in
    settings.HIBP_ENABLED = False
    with patch("analysis.views.lookup_account") as lookup:
        response = client.post(
            reverse("breach_lookup"), {"email": "test@example.org", "consent": "on"}
        )
    assert response.status_code == 200
    assert not AuditEvent.objects.filter(action="breach_lookup").exists()
    lookup.assert_not_called()


def test_lookup_post_requires_csrf(signed_in):
    _, user = signed_in
    csrf_client = Client(enforce_csrf_checks=True)
    csrf_client.force_login(user)
    with patch("analysis.views.lookup_account") as lookup:
        response = csrf_client.post(
            reverse("breach_lookup"), {"email": "test@example.org", "consent": "on"}
        )
    assert response.status_code == 403
    lookup.assert_not_called()
