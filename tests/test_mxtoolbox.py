import io
import json
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest
import requests
from django.contrib.auth import get_user_model
from django.core.files.uploadedfile import SimpleUploadedFile
from django.core.management import call_command

from analysis.forms import UploadForm
from analysis.models import AuditEvent, Submission
from analysis.mxtoolbox import check_configuration, domain_name, lookup_plan, request_lookup
from analysis.scanner import analyze, poll_virustotal

HEADERS = {
    "selected": {
        "From": ["Private Person <private@sender.example.org>"],
        "Return-Path": ["<private-bounce@bounce.example.org>"],
        "DKIM-Signature": [
            {"d": "signed.example.org", "s": "selector"},
            {"d": "other.example.org", "s": "other"},
        ],
    }
}
EMAIL = (
    b"From: Private Person <private@sender.example.org>\r\n"
    b"Return-Path: <private-bounce@bounce.example.org>\r\n"
    b"Subject: PRIVATE_SUBJECT\r\n"
    b"DKIM-Signature: v=1; d=signed.example.org; s=selector; b=PRIVATE_SIGNATURE\r\n\r\nPRIVATE_BODY"
)


@pytest.fixture(autouse=True)
def config(settings, monkeypatch, tmp_path):
    settings.MXTOOLBOX_ENABLED = False
    settings.MXTOOLBOX_API_KEY = "test-private-key"
    settings.SECURE_SSL_REDIRECT = False
    settings.PRIVATE_STORAGE = tmp_path / "uploads"
    monkeypatch.delenv("MXTOOLBOX_API_KEY", raising=False)
    monkeypatch.delenv("MXTOOLBOX_ENABLED", raising=False)
    monkeypatch.delenv("VT_API_KEY", raising=False)
    monkeypatch.delenv("AI_API_KEY", raising=False)


def response():
    result = Mock(status_code=200)
    result.json.return_value = {"ExampleField": "provider data"}
    return result


def test_lookup_plan_uses_envelope_domain_for_spf_and_one_signature_only():
    plan = lookup_plan(HEADERS)
    assert [(query["command"], query["argument"]) for query in plan] == [
        ("spf", "bounce.example.org"),
        ("dmarc", "sender.example.org"),
        ("dkim", "signed.example.org:selector"),
    ]
    assert "private@" not in json.dumps(plan)
    assert "Private Person" not in json.dumps(plan)


@pytest.mark.parametrize(
    "value",
    [
        "127.0.0.1",
        "8.8.8.8",
        "localhost",
        "server.local",
        "example.org/path",
        "evil.example.org&argument=other.org",
        "example.org\nheader",
        "[::1]",
        None,
    ],
)
def test_invalid_domains_never_become_query_targets(value):
    assert domain_name(value) is None


def test_missing_envelope_and_invalid_dkim_are_explicit():
    plan = lookup_plan(
        {
            "selected": {
                "From": ["a@example.org"],
                "DKIM-Signature": [{"d": "example.org", "s": "invalid&selector"}],
            }
        }
    )
    assert len(plan) == 2 and plan[0]["basis"] == "from_fallback"


@pytest.mark.parametrize("enabled,consented", [(False, False), (True, False), (False, True)])
def test_no_provider_call_without_global_policy_and_per_upload_consent(
    monkeypatch, enabled, consented
):
    monkeypatch.setenv("MXTOOLBOX_ENABLED", str(enabled).lower())
    monkeypatch.setenv("MXTOOLBOX_API_KEY", "test-private-key")
    with patch("analysis.mxtoolbox.requests.get") as get:
        result = check_configuration(HEADERS, consent=consented)
    get.assert_not_called()
    assert result["status"] in {"disabled", "not_authorized"}


def test_requests_use_documented_fixed_endpoint_and_raw_authorization_header(monkeypatch):
    monkeypatch.setenv("MXTOOLBOX_ENABLED", "true")
    monkeypatch.setenv("MXTOOLBOX_API_KEY", "test-private-key")
    with patch("analysis.mxtoolbox.requests.get", return_value=response()) as get:
        result = check_configuration(HEADERS, consent=True)
    assert get.call_count == 3 and result["independently_verified"] is False
    for call in get.call_args_list:
        assert call.args[0].startswith("https://api.mxtoolbox.com/api/v1/Lookup/")
        assert "test-private-key" not in call.args[0]
        assert call.kwargs["headers"] == {"Authorization": "test-private-key"}
        assert call.kwargs["allow_redirects"] is False
        payload = json.dumps(call.kwargs["params"])
        assert "private@" not in payload and "PRIVATE_BODY" not in payload
    assert result["status"] == "response_received"


@pytest.mark.parametrize(
    "code,status", [(401, "authentication_error"), (403, "access_denied"), (429, "quota_exceeded")]
)
def test_authentication_and_quota_errors_stop_further_queries(monkeypatch, code, status):
    monkeypatch.setenv("MXTOOLBOX_ENABLED", "true")
    monkeypatch.setenv("MXTOOLBOX_API_KEY", "test-private-key")
    with patch("analysis.mxtoolbox.requests.get", return_value=Mock(status_code=code)) as get:
        result = check_configuration(HEADERS, consent=True)
    assert get.call_count == 1 and result["checks"][0]["status"] == status
    assert result["planned_count"] == 3


def test_no_network_commands_are_accepted():
    with patch("analysis.mxtoolbox.requests.get") as get:
        for command in ("blacklist", "http", "smtp", "ping", "trace"):
            assert request_lookup(command, "example.org", "test")["status"] == "invalid_request"
    get.assert_not_called()


def test_received_response_is_not_interpreted_as_authentication_pass_and_key_is_redacted():
    mocked = response()
    mocked.json.return_value = {"Errors": ["SPF failed"], "echo": "test-private-key"}
    with patch("analysis.mxtoolbox.requests.get", return_value=mocked):
        result = request_lookup("spf", "example.org", "test-private-key")
    assert result["status"] == "response_received"
    assert "test-private-key" not in json.dumps(result)
    assert "SPF failed" in result["response_excerpt"]
    assert "pass" not in result


def test_timeout_and_redirect_never_expose_exception_details_or_follow_targets():
    with patch("analysis.mxtoolbox.requests.get", side_effect=requests.Timeout("private")):
        result = request_lookup("spf", "example.org", "test")
    assert result["status"] == "timeout" and "private" not in json.dumps(result)
    with patch("analysis.mxtoolbox.requests.get", return_value=Mock(status_code=302)):
        assert request_lookup("spf", "example.org", "test")["status"] == "unavailable"


def test_mxtoolbox_never_changes_the_scanner_verdict_or_gets_mail_content(monkeypatch, tmp_path):
    monkeypatch.setenv("MXTOOLBOX_ENABLED", "true")
    monkeypatch.setenv("MXTOOLBOX_API_KEY", "test-private-key")
    path = tmp_path / "mail.eml"
    path.write_bytes(EMAIL)
    with patch("analysis.mxtoolbox.requests.get", return_value=response()) as get:
        result = analyze(path, "mail.eml", "eml", mxtoolbox_consent=True)
    assert result["verdict"] == "inconclusive"  # VT is absent; DNS queries do not replace it.
    assert get.call_count == 3
    sent = str(get.call_args_list)
    for private in ("PRIVATE_BODY", "PRIVATE_SUBJECT", "PRIVATE_SIGNATURE", "private@"):
        assert private not in sent


def test_polling_keeps_dns_results_without_repeating_them():
    previous = {"status": "response_received", "checks": []}
    details = {
        "module": "eml",
        "local_assessment": {"malicious": False, "suspicious": False, "incomplete": False},
        "providers": {"virustotal": {"analysis_id": "dns-test"}, "mxtoolbox": previous},
    }
    with (
        patch(
            "analysis.scanner.fetch_analysis",
            return_value={
                "status": "ok",
                "stats": {"malicious": 0, "suspicious": 0, "undetected": 60},
            },
        ),
        patch("analysis.mxtoolbox.requests.get") as get,
    ):
        final = poll_virustotal(details)
    get.assert_not_called()
    assert final["details"]["providers"]["mxtoolbox"] == previous


@pytest.mark.django_db
@pytest.mark.parametrize(
    "enabled,kind,valid", [(False, "eml", False), (True, "file", False), (True, "eml", True)]
)
def test_forged_consent_cannot_bypass_policy(settings, enabled, kind, valid):
    settings.MXTOOLBOX_ENABLED = enabled
    file = SimpleUploadedFile(
        "mail.eml" if kind == "eml" else "test.txt", EMAIL if kind == "eml" else b"Test"
    )
    assert UploadForm({"kind": kind, "mxtoolbox_consent": "on"}, {"file": file}).is_valid() is valid


@pytest.mark.django_db
def test_dns_response_is_admin_only_and_escaped(client):
    owner = get_user_model().objects.create_user(username="dns-owner")
    checks = [
        {
            "command": "spf",
            "argument": "private.example.org",
            "status": "response_received",
            "response_excerpt": "<script>secret.example.org</script>",
        }
    ]
    item = Submission.objects.create(
        owner=owner,
        kind="eml",
        filename="mail.eml",
        status="done",
        verdict="no_indicators",
        details={"providers": {"mxtoolbox": {"status": "response_received", "checks": checks}}},
    )
    client.force_login(owner)
    url = f"/results/{item.pk}/"
    public = client.get(url + "?format=json").json()
    assert "secret.example.org" not in json.dumps(public)
    assert "private.example.org" not in json.dumps(public)
    assert "MXToolbox" in client.get(url).content.decode()
    session = client.session
    session["roles"] = ["vigia-admin"]
    session.save()
    html = client.get(url).content.decode()
    assert "&lt;script&gt;secret.example.org" in html
    assert "<script>secret.example.org" not in html


@pytest.mark.django_db
def test_worker_records_authorization_and_gives_key_only_to_authorized_scan(client, settings):
    settings.MXTOOLBOX_ENABLED = True
    owner = get_user_model().objects.create_user(username="dns-worker")
    client.force_login(owner)
    assert (
        client.post(
            "/upload/",
            {
                "kind": "eml",
                "file": SimpleUploadedFile("mail.eml", EMAIL),
                "mxtoolbox_consent": "on",
            },
        ).status_code
        == 302
    )
    item = Submission.objects.get()
    assert item.mxtoolbox_consent
    assert AuditEvent.objects.filter(action="mxtoolbox_authorized").exists()
    report = {
        "verdict": "inconclusive",
        "details": {"providers": {"mxtoolbox": {"checks": [{"request_attempted": True}]}}},
    }
    with patch(
        "analysis.management.commands.scan_worker.subprocess.run",
        return_value=SimpleNamespace(stdout=json.dumps(report)),
    ) as run:
        call_command("scan_worker", once=True)
    assert "--mxtoolbox" in run.call_args.args[0]
    assert run.call_args.kwargs["env"]["MXTOOLBOX_API_KEY"] == "test-private-key"
    assert run.call_args.kwargs["timeout"] == 150
    assert AuditEvent.objects.filter(action="mxtoolbox_attempt").exists()


@pytest.mark.django_db
def test_worker_does_not_forward_dns_key_without_authorization(client, settings):
    settings.MXTOOLBOX_ENABLED = True
    owner = get_user_model().objects.create_user(username="no-dns")
    client.force_login(owner)
    client.post("/upload/", {"kind": "eml", "file": SimpleUploadedFile("mail.eml", EMAIL)})
    report = {"verdict": "inconclusive", "details": {}}
    with patch(
        "analysis.management.commands.scan_worker.subprocess.run",
        return_value=SimpleNamespace(stdout=json.dumps(report)),
    ) as run:
        call_command("scan_worker", once=True)
    assert "--mxtoolbox" not in run.call_args.args[0]
    assert "MXTOOLBOX_API_KEY" not in run.call_args.kwargs["env"]


def test_diagnostic_shows_schema_names_and_types_without_values(settings):
    settings.MXTOOLBOX_ENABLED = True
    output = io.StringIO()
    payload = {
        "Argument": "private.example.org",
        "ApiKey": "private-key",
        "Errors": [{"Name": "private-error", "ID": 123}],
    }
    with patch(
        "analysis.management.commands.diagnose_mxtoolbox.request_lookup",
        return_value={"status": "response_received", "response_excerpt": json.dumps(payload)},
    ) as lookup:
        call_command("diagnose_mxtoolbox", stdout=output)
    lookup.assert_called_once_with("spf", "example.com", "test-private-key")
    result = json.loads(output.getvalue())
    assert result["schema_fields"][0] == {"name": "Argument", "type": "str"}
    assert result["schema_fields"][2]["item_fields"] == [
        {"name": "Name", "type": "str"},
        {"name": "ID", "type": "int"},
    ]
    for private in ("private.example.org", "private-key", "private-error", "123"):
        assert private not in output.getvalue()


def test_diagnostic_provider_error_is_safe(settings):
    settings.MXTOOLBOX_ENABLED = True
    output = io.StringIO()
    with patch(
        "analysis.management.commands.diagnose_mxtoolbox.request_lookup",
        return_value={"status": "authentication_error"},
    ):
        call_command("diagnose_mxtoolbox", stdout=output)
    assert json.loads(output.getvalue()) == {"status": "authentication_error", "schema_fields": []}
