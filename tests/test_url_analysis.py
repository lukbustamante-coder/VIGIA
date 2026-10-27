import base64
import json
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest
import requests
from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.test import Client

from analysis.forms import URLAnalysisForm
from analysis.models import AuditEvent, Submission
from analysis.scanner import poll_virustotal
from analysis.url_inspection import analyze_url, lookup_url, normalize_url


@pytest.fixture(autouse=True)
def config(settings, monkeypatch, tmp_path):
    settings.DEBUG = True
    settings.SECURE_SSL_REDIRECT = False
    settings.VT_ALLOW_URL_SUBMISSION = False
    settings.PRIVATE_STORAGE = tmp_path / "uploads"
    monkeypatch.delenv("VT_API_KEY", raising=False)
    monkeypatch.delenv("VT_ALLOW_URL_SUBMISSION", raising=False)
    monkeypatch.delenv("AI_API_KEY", raising=False)


def vt_response(status=200, stats=None):
    result = Mock(status_code=status)
    result.json.return_value = {
        "data": {
            "attributes": {
                "last_analysis_stats": stats if stats is not None else {"undetected": 60},
                "last_analysis_date": 1700000000,
            }
        }
    }
    return result


@pytest.mark.parametrize(
    "url",
    [
        "file:///etc/passwd",
        "javascript:alert(1)",
        "ftp://example.org/a",
        "example.org",
        "https://user:password@example.org/",
        "http://127.0.0.1/",
        "http://224.0.0.1/",
        "http://[ff02::1]/",
        "http://10.0.0.1/",
        "http://169.254.169.254/",
        "http://[::1]/",
        "http://localhost/",
        "http://server.local/",
        "http://intranet/",
        "http://2130706433/",
        "http://0177.0.0.1/",
        "http://example.org:99999/",
        "https://example.org/a\nb",
        "https://example.org/a\\b",
        "http://[::ffff:127.0.0.1]/",
        "http://[2001:4860:4860::8888%zone]/",
        "https://example.org/" + "a" * 2048,
    ],
)
def test_unsupported_and_internal_url_inputs_are_rejected(url):
    with pytest.raises(ValueError):
        normalize_url(url)


def test_normalization_preserves_sensitive_parameters_without_resolving_or_fetching_target():
    with patch("socket.getaddrinfo", side_effect=AssertionError("No target DNS")):
        assert (
            normalize_url("HTTPS://Example.ORG/a?token=private#fragment")
            == "https://example.org/a?token=private#fragment"
        )
        assert normalize_url("https://bücher.de/") == "https://xn--bcher-kva.de/"


@pytest.mark.parametrize(
    "malicious,suspicious,verdict",
    [(0, 0, "no_indicators"), (1, 0, "suspicious"), (0, 1, "suspicious"), (2, 0, "malicious")],
)
def test_url_report_uses_fixed_vt_endpoint_and_actual_statistics(
    monkeypatch, malicious, suspicious, verdict
):
    monkeypatch.setenv("VT_API_KEY", "test-key")
    target = "https://example.org/a?token=private"
    encoded = base64.urlsafe_b64encode(target.encode()).decode().rstrip("=")
    with (
        patch(
            "analysis.url_inspection.requests.get",
            return_value=vt_response(
                stats={"malicious": malicious, "suspicious": suspicious, "undetected": 50}
            ),
        ) as get,
        patch("analysis.url_inspection.requests.post") as post,
    ):
        report = analyze_url(target)
    assert report["verdict"] == verdict
    assert get.call_args.args[0] == f"https://www.virustotal.com/api/v3/urls/{encoded}"
    assert get.call_args.kwargs["allow_redirects"] is False
    assert get.call_args.kwargs["headers"] == {"x-apikey": "test-key"}
    post.assert_not_called()
    assert report["details"]["module"] == "url"


@pytest.mark.parametrize("enabled,consented", [(False, False), (True, False), (False, True)])
def test_unknown_url_is_not_submitted_without_both_permissions(monkeypatch, enabled, consented):
    monkeypatch.setenv("VT_API_KEY", "test-key")
    monkeypatch.setenv("VT_ALLOW_URL_SUBMISSION", str(enabled).lower())
    with (
        patch("analysis.url_inspection.requests.get", return_value=vt_response(status=404)),
        patch("analysis.url_inspection.requests.post") as post,
    ):
        result = analyze_url("https://example.org/", scan_consent=consented)
    post.assert_not_called()
    assert result["verdict"] == "inconclusive"
    assert result["details"]["providers"]["virustotal"]["status"] == "unknown_url"


def test_authorized_url_submission_polls_without_fetching_target_or_calling_ai(monkeypatch):
    monkeypatch.setenv("VT_API_KEY", "test-key")
    monkeypatch.setenv("VT_ALLOW_URL_SUBMISSION", "true")
    submitted = Mock(status_code=200)
    submitted.json.return_value = {"data": {"id": "url-analysis-123"}}
    with (
        patch("analysis.url_inspection.requests.get", return_value=vt_response(status=404)),
        patch("analysis.url_inspection.requests.post", return_value=submitted) as post,
    ):
        initial = analyze_url("https://example.org/path", scan_consent=True)
    assert post.call_args.args[0] == "https://www.virustotal.com/api/v3/urls"
    assert post.call_args.kwargs["data"] == {"url": "https://example.org/path"}
    assert post.call_args.kwargs["allow_redirects"] is False
    assert initial["details"]["providers"]["virustotal"]["url_submitted"]
    with (
        patch(
            "analysis.scanner.fetch_analysis",
            return_value={"status": "ok", "stats": {"malicious": 2, "suspicious": 0}},
        ),
        patch(
            "analysis.url_inspection.lookup_url",
            return_value={"status": "ok", "categories": {"Example service": "education"}},
        ),
        patch("analysis.scanner.requests.post") as repeated,
    ):
        final = poll_virustotal(initial["details"])
    repeated.assert_not_called()
    assert final["verdict"] == "malicious"
    assert final["details"]["iocs"]["urls"] == ["https://example.org/path"]


@pytest.mark.parametrize(
    "code,status",
    [
        (401, "authentication_error"),
        (403, "access_denied"),
        (429, "quota_exceeded"),
        (302, "unavailable"),
    ],
)
def test_vt_errors_and_redirects_produce_inconclusive_results(monkeypatch, code, status):
    monkeypatch.setenv("VT_API_KEY", "test-key")
    with patch("analysis.url_inspection.requests.get", return_value=vt_response(status=code)):
        result = analyze_url("https://example.org/")
    assert result["verdict"] == "inconclusive"
    assert result["details"]["providers"]["virustotal"]["status"] == status


@pytest.mark.parametrize(
    "stats", [{}, {"undetected": True}, {"malicious": -1}, {"undetected": "60"}]
)
def test_invalid_or_empty_statistics_never_mark_url_clean(monkeypatch, stats):
    monkeypatch.setenv("VT_API_KEY", "test-key")
    with patch("analysis.url_inspection.requests.get", return_value=vt_response(stats=stats)):
        assert analyze_url("https://example.org/")["verdict"] == "inconclusive"


def test_timeout_is_not_a_clean_url(monkeypatch):
    monkeypatch.setenv("VT_API_KEY", "test-key")
    with patch("analysis.url_inspection.requests.get", side_effect=requests.Timeout("secret")):
        report = lookup_url("https://example.org/")
    assert report["status"] == "timeout" and "secret" not in json.dumps(report)


def test_url_query_requires_consent_and_rejects_disabled_scan(settings):
    assert not URLAnalysisForm({"url": "https://example.org/"}).is_valid()
    assert not URLAnalysisForm(
        {"url": "https://example.org/", "vt_url_consent": "on", "url_scan_consent": "on"}
    ).is_valid()
    settings.VT_ALLOW_URL_SUBMISSION = True
    assert URLAnalysisForm(
        {"url": "https://example.org/", "vt_url_consent": "on", "url_scan_consent": "on"}
    ).is_valid()


@pytest.mark.django_db
def test_url_post_is_authenticated_csrf_protected_and_post_only():
    client = Client(enforce_csrf_checks=True)
    assert Client().post("/analisis/urls/enviar/").status_code == 302
    assert client.post("/analisis/urls/enviar/").status_code == 403
    user = get_user_model().objects.create_user(username="url-user")
    client.force_login(user)
    assert client.get("/analisis/urls/enviar/").status_code == 405
    assert (
        client.post(
            "/analisis/urls/enviar/", {"url": "https://example.org/", "vt_url_consent": "on"}
        ).status_code
        == 403
    )
    assert not Submission.objects.exists()


@pytest.mark.django_db
def test_actual_url_worker_needs_no_uploaded_file_and_stores_no_target_in_public_result(
    client, settings
):
    owner = get_user_model().objects.create_user(username="url-owner")
    client.force_login(owner)
    response = client.post(
        "/analisis/urls/enviar/",
        {"url": "https://example.org/?token=private", "vt_url_consent": "on"},
    )
    assert response.status_code == 302
    assert AuditEvent.objects.filter(action="url_query_authorized").exists()
    call_command("scan_worker", once=True)
    item = Submission.objects.get()
    assert item.kind == "url" and item.status == "done" and item.verdict == "inconclusive"
    assert item.details["providers"]["virustotal"]["status"] == "not_configured"
    assert not AuditEvent.objects.filter(action="url_query_attempt").exists()
    assert not settings.PRIVATE_STORAGE.exists()
    public = client.get(f"/results/{item.pk}/?format=json").json()
    assert "private" not in json.dumps(public) and "details" not in public
    html = client.get(f"/results/{item.pk}/").content.decode()
    assert 'class="back-link" href="/analisis/urls/"' in html
    assert "VIGIA no abre la página" in html and "Hash del archivo" not in html


@pytest.mark.django_db
@pytest.mark.parametrize("admin", [False, True])
def test_url_tab_filters_module_and_owner(client, admin):
    owner = get_user_model().objects.create_user(username="owner")
    other = get_user_model().objects.create_user(username="other")
    own = Submission.objects.create(
        owner=owner, kind="url", target_url="https://example.org/", filename="URL · example.org"
    )
    others = Submission.objects.create(owner=other, kind="url", filename="Other URL")
    Submission.objects.create(owner=owner, kind="eml", filename="mail.eml")
    client.force_login(owner)
    session = client.session
    session["roles"] = ["vigia-admin"] if admin else []
    session.save()
    response = client.get("/analisis/urls/")
    assert response.status_code == 200 and response.context["module"] == "url"
    assert set(response.context["submissions"]) == ({own, others} if admin else {own})
    assert b'aria-current="page"' in response.content
    client.force_login(other)
    assert client.get(f"/results/{own.pk}/").status_code == 404


@pytest.mark.django_db
def test_url_worker_uses_stdin_and_persisted_polling(client, settings):
    settings.VT_ALLOW_URL_SUBMISSION = True
    user = get_user_model().objects.create_user(username="url-submit")
    client.force_login(user)
    assert (
        client.post(
            "/analisis/urls/enviar/",
            {
                "url": "https://example.org/?token=private",
                "vt_url_consent": "on",
                "url_scan_consent": "on",
            },
        ).status_code
        == 302
    )
    item = Submission.objects.get()
    result = {
        "verdict": "inconclusive",
        "details": {
            "module": "url",
            "local_assessment": {"malicious": False, "suspicious": False, "incomplete": False},
            "providers": {
                "virustotal": {
                    "status": "queued",
                    "analysis_id": "url-test-123",
                    "query_attempted": True,
                    "url_scan_attempted": True,
                }
            },
        },
    }
    with patch(
        "analysis.management.commands.scan_worker.subprocess.run",
        return_value=SimpleNamespace(stdout=json.dumps(result)),
    ) as run:
        call_command("scan_worker", once=True)
    assert run.call_args.args[0][-1] == "--url"
    assert "private" not in str(run.call_args.args[0])
    assert json.loads(run.call_args.kwargs["input"])["url"] == item.target_url
    assert run.call_args.kwargs["env"]["VT_ALLOW_URL_SUBMISSION"] == "true"
    item.refresh_from_db()
    assert item.status == "waiting_vt" and item.vt_deadline_at
    assert AuditEvent.objects.filter(action="url_scan_attempt").exists()


@pytest.mark.django_db
def test_url_submission_shares_existing_user_quota(client):
    owner = get_user_model().objects.create_user(username="quota-user")
    Submission.objects.bulk_create(
        [Submission(owner=owner, kind="file", filename="test.txt") for _ in range(20)]
    )
    client.force_login(owner)
    response = client.post(
        "/analisis/urls/enviar/", {"url": "https://example.org/", "vt_url_consent": "on"}
    )
    assert response.status_code == 429 and Submission.objects.filter(kind="url").count() == 0


@pytest.mark.django_db
def test_url_details_are_admin_only_and_render_as_text(client):
    owner = get_user_model().objects.create_user(username="url-admin")
    target = "https://example.org/?token=private&x=<script>alert(1)</script>"
    item = Submission.objects.create(
        owner=owner,
        kind="url",
        filename="URL · example.org",
        target_url=target,
        status="done",
        verdict="no_indicators",
        details={"providers": {"virustotal": {"status": "ok", "stats": {"undetected": 60}}}},
    )
    client.force_login(owner)
    assert "private" not in client.get(f"/results/{item.pk}/").content.decode()
    session = client.session
    session["roles"] = ["vigia-admin"]
    session.save()
    html = client.get(f"/results/{item.pk}/").content.decode()
    assert "&lt;script&gt;" in html and "<script>alert" not in html
    assert "private" in html and "Reporte de reputación consultado por URL" in html
