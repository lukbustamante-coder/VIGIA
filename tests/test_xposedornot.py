import json
from datetime import timedelta
from types import SimpleNamespace
from unittest.mock import patch

import pytest
import requests
from django.contrib.auth import get_user_model
from django.urls import reverse
from django.utils import timezone

from analysis.breaches import XON_API, lookup_xposedornot
from analysis.models import AuditEvent, Submission


def response(http=200, body=None, raw=None):
    data = json.dumps(body).encode() if raw is None else raw
    return SimpleNamespace(
        status_code=http, iter_content=lambda **kwargs: iter([data]), close=lambda: None
    )


def found(names=None):
    return {
        "status": "success",
        "breaches": [names or ["ExampleIncident"]],
        "email": "private@example.org",
    }


@pytest.fixture(autouse=True)
def config(settings):
    settings.DEBUG = True
    settings.SECURE_SSL_REDIRECT = False
    settings.BREACH_PROVIDER = "xposedornot"
    settings.HIBP_ENABLED = False
    settings.HIBP_API_KEY = ""


@pytest.fixture
def signed_in(client, db):
    user = get_user_model().objects.create_user(username="free-reader")
    client.force_login(user)
    session = client.session
    session["oidc_email"] = "test@example.org"
    session.save()
    return client, user


def test_free_api_needs_no_key_and_encodes_email_at_fixed_endpoint():
    with patch("analysis.breaches.requests.get", return_value=response(body=found())) as get:
        result = lookup_xposedornot("name+tag@example.org")
    assert result["status"] == "found"
    assert get.call_args.args == (XON_API + "name%2Btag%40example.org",)
    assert "hibp-api-key" not in get.call_args.kwargs["headers"]
    assert "Authorization" not in get.call_args.kwargs["headers"]
    assert get.call_args.kwargs["allow_redirects"] is False
    assert get.call_args.kwargs["timeout"] == (5, 15)
    assert result["breaches"] == [{"title": "ExampleIncident", "date": "", "data_classes": []}]
    assert "private@example.org" not in str(result)


@pytest.mark.parametrize("http", [200, 404])
def test_documented_no_match_payload_is_accepted(http):
    with patch(
        "analysis.breaches.requests.get",
        return_value=response(http, {"Error": "Not found", "email": None}),
    ):
        assert lookup_xposedornot("test@example.org")["status"] == "no_records"


@pytest.mark.parametrize(
    "http,body",
    [
        (404, {"error": "Route not found"}),
        (404, {"Error": "Not found"}),
        (200, {"status": "success", "breaches": []}),
        (200, {"status": "success", "breaches": [[]]}),
        (200, {"status": "success", "breaches": ["Incorrect shape"]}),
        (200, {"status": "success", "breaches": [[123]]}),
        (200, {"status": "success", "breaches": [["a"], ["b"]]}),
    ],
)
def test_unexpected_response_is_never_reported_as_no_records(http, body):
    with patch("analysis.breaches.requests.get", return_value=response(http, body)):
        assert lookup_xposedornot("test@example.org")["status"] == "invalid_response"


@pytest.mark.parametrize("http", [302, 403, 429, 500])
def test_provider_errors_never_become_no_records(http):
    with patch("analysis.breaches.requests.get", return_value=response(http, {})):
        assert lookup_xposedornot("test@example.org")["status"] != "no_records"


def test_large_response_timeout_and_duplicate_incidents():
    with patch(
        "analysis.breaches.requests.get", return_value=response(raw=b"x" * (1024 * 1024 + 1))
    ):
        assert lookup_xposedornot("test@example.org")["status"] == "invalid_response"
    with patch("analysis.breaches.requests.get", side_effect=requests.Timeout):
        assert lookup_xposedornot("test@example.org")["status"] == "timeout"
    with patch("analysis.breaches.requests.get", return_value=response(body=found(["A", "A"]))):
        assert len(lookup_xposedornot("test@example.org")["breaches"]) == 1


def test_tab_has_free_search_without_hibp_subscription_and_identifies_recipient(signed_in):
    client, _ = signed_in
    with patch("analysis.views.lookup_xposedornot") as lookup:
        html = client.get(reverse("breach_lookup")).content.decode()
    assert 'name="email"' in html and "API básica gratuitas" in html
    assert "La dirección completa se enviará a XposedOrNot" in html
    assert "25 por hora y 100 por día" in html
    lookup.assert_not_called()


def test_free_lookup_displays_only_selected_source_without_fallback_or_storage(signed_in):
    client, user = signed_in
    session = client.session
    session["oidc_email"] = "private@example.org"
    session.save()
    with (
        patch("analysis.breaches.requests.get", return_value=response(body=found())) as get,
        patch("analysis.views.lookup_account") as paid,
    ):
        result = client.post(
            reverse("breach_lookup"),
            {"email": "private@example.org", "consent": "on", "provider": "hibp"},
        )
    html = result.content.decode()
    assert result.status_code == 200 and get.call_count == 1
    paid.assert_not_called()
    assert "indicadas por XposedOrNot" in html and "ExampleIncident" in html
    assert "Fecha de filtración:" not in html
    assert Submission.objects.count() == 0
    audit = AuditEvent.objects.get(actor=user, action="breach_lookup_xon")
    assert "private@example.org" not in str(audit.__dict__)
    assert client.session["oidc_email"] == "private@example.org"
    assert "ExampleIncident" not in str(dict(client.session))


@pytest.mark.parametrize("window", ["second", "hour", "day"])
def test_free_provider_rate_limits_prevent_requests(signed_in, window):
    client, user = signed_in
    actor = get_user_model().objects.create_user(username="other")
    count = {"second": 1, "hour": 25, "day": 100}[window]
    events = [AuditEvent(actor=actor, action="breach_lookup_xon") for _ in range(count)]
    AuditEvent.objects.bulk_create(events)
    if window != "second":
        delta = timedelta(minutes=2) if window == "hour" else timedelta(hours=2)
        AuditEvent.objects.filter(action="breach_lookup_xon").update(
            created_at=timezone.now() - delta
        )
    with patch("analysis.views.lookup_xposedornot") as lookup:
        result = client.post(
            reverse("breach_lookup"), {"email": "test@example.org", "consent": "on"}
        )
    assert result.status_code == 429
    lookup.assert_not_called()
    assert AuditEvent.objects.filter(action="breach_lookup_xon").count() == count


def test_disabled_provider_prevents_free_requests(signed_in, settings):
    client, _ = signed_in
    settings.BREACH_PROVIDER = "disabled"
    with patch("analysis.views.lookup_xposedornot") as lookup:
        result = client.post(
            reverse("breach_lookup"), {"email": "test@example.org", "consent": "on"}
        )
    lookup.assert_not_called()
    assert "Consulta automática no disponible" in result.content.decode()


def test_unchecked_consent_and_external_html_are_handled(signed_in):
    client, _ = signed_in
    with patch("analysis.views.lookup_xposedornot") as lookup:
        result = client.post(reverse("breach_lookup"), {"email": "test@example.org"})
    assert result.status_code == 400
    lookup.assert_not_called()
    with patch(
        "analysis.breaches.requests.get",
        return_value=response(body=found(["<img src=x onerror=alert(1)>"])),
    ):
        result = client.post(
            reverse("breach_lookup"), {"email": "test@example.org", "consent": "on"}
        )
    assert "<img src=x onerror" not in result.content.decode()
    assert "&lt;img" in result.content.decode()
