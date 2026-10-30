import hashlib
import json
import smtplib
import time
from datetime import timedelta
from unittest.mock import Mock, patch

import pytest
from django.contrib.auth import get_user_model
from django.core import mail
from django.core.files.uploadedfile import SimpleUploadedFile
from django.core.management import call_command
from django.test import Client
from django.utils import timezone

from analysis.mail_backend import EmailBackend, PartialDelivery
from analysis.models import AuditEvent, IncidentReport, Submission
from analysis.reporting import RECIPIENTS, process_next_report, sample_path, save_sample

pytestmark = pytest.mark.django_db


@pytest.fixture(autouse=True)
def configuration(settings, tmp_path):
    settings.SECURE_SSL_REDIRECT = False
    settings.PRIVATE_STORAGE = tmp_path / "samples"
    settings.REPORT_MAIL_ENABLED = True
    settings.EMAIL_HOST = "smtp.example.org"
    settings.DEFAULT_FROM_EMAIL = "vigia@example.org"
    settings.EMAIL_BACKEND = "django.core.mail.backends.locmem.EmailBackend"


@pytest.fixture
def owner(client):
    user = get_user_model().objects.create_user(username="report-owner", first_name="Ana")
    client.force_login(user)
    return user


def submission(owner, kind="url", verdict="suspicious", status="done", content=b"sample"):
    item = Submission.objects.create(
        owner=owner,
        kind=kind,
        status=status,
        verdict=verdict,
        filename="original.eml" if kind == "eml" else "sample.txt",
        target_url="https://example.org/path?private=token" if kind == "url" else "",
        details={"file": {"sha256": hashlib.sha256(content).hexdigest()}, "findings": ["Test"]},
    )
    return item


def report_url(item):
    return f"/results/{item.pk}/reportar/"


@pytest.mark.parametrize("kind", ["url", "eml", "file"])
@pytest.mark.parametrize("verdict", ["malicious", "suspicious", "inconclusive"])
def test_report_queues_once_then_sends_to_both_recipients_with_evidence(
    client, owner, kind, verdict
):
    data = (
        b"From: test@example.org\nSubject: Original\n\nOriginal sample"
        if kind == "eml"
        else b"sample"
    )
    item = submission(owner, kind, verdict, content=data)
    if kind != "url":
        save_sample(item, data)
    for _ in range(2):
        result = client.post(report_url(item), {"email": "reporter@example.org"})
        assert result.status_code == 302
    assert IncidentReport.objects.count() == 1
    assert len(mail.outbox) == 0
    assert process_next_report()
    assert not process_next_report()
    report = IncidentReport.objects.get()
    assert report.status == "sent" and report.attempts == 1 and report.sent_at
    assert report.submission.status_label == "Reportado"
    message = mail.outbox[0]
    assert set(message.to) == set(RECIPIENTS)
    assert message.reply_to == ["reporter@example.org"]
    assert "reporter@example.org" in message.body and str(item.pk) in message.body
    assert item.result_badge["label"] in message.body
    assert any(attachment.filename.endswith(".json") for attachment in message.attachments)
    if kind == "url":
        assert item.target_url in message.body
        assert len(message.attachments) == 1
    else:
        attached = [a for a in message.attachments if a.mimetype == "application/octet-stream"]
        assert len(attached) == 1 and attached[0].content == data
    client.post(report_url(item), {"email": "reporter@example.org"})
    assert not process_next_report()
    assert len(mail.outbox) == 1
    html = client.get(f"/results/{item.pk}/").content.decode()
    assert "Tu reporte fue enviado" in html and "Reportado" in html
    assert item.target_url not in client.get(f"/results/{item.pk}/?format=json").json().get(
        "report", {}
    )


def test_other_users_and_admins_cannot_report_another_owners_analysis(client, owner):
    item = submission(owner)
    client.force_login(get_user_model().objects.create_user(username="other"))
    session = client.session
    session["roles"] = ["vigia-admin"]
    session.save()
    assert client.post(report_url(item), {"email": "other@example.org"}).status_code == 404
    assert not IncidentReport.objects.exists()


def test_report_requires_login_post_and_csrf(client, owner):
    item = submission(owner)
    assert client.get(report_url(item)).status_code == 405
    secure = Client(enforce_csrf_checks=True)
    secure.force_login(owner)
    assert secure.post(report_url(item), {"email": "owner@example.org"}).status_code == 403
    client.logout()
    assert client.post(report_url(item)).status_code == 302
    assert not IncidentReport.objects.exists()


@pytest.mark.parametrize(
    "status,verdict",
    [("queued", "inconclusive"), ("waiting_vt", "suspicious"), ("done", "no_indicators")],
)
def test_pending_or_no_indicator_results_cannot_be_reported(client, owner, status, verdict):
    item = submission(owner, status=status, verdict=verdict)
    assert client.post(report_url(item), {"email": "owner@example.org"}).status_code == 400
    assert not IncidentReport.objects.exists()


def test_missing_smtp_configuration_never_marks_as_reported(client, owner, settings):
    settings.REPORT_MAIL_ENABLED = False
    item = submission(owner)
    result = client.post(report_url(item), {"email": "owner@example.org"})
    assert result.status_code == 503
    assert "aún no está disponible" in result.content.decode()
    assert not IncidentReport.objects.exists() and not process_next_report()


def test_session_email_is_prefilled_and_used_over_browser_email(client, owner):
    session = client.session
    session["oidc_contact_email"] = "sso@example.org"
    session.save()
    item = submission(owner)
    client.post(report_url(item), {"email": "forged@example.org"})
    assert IncidentReport.objects.get().email == "sso@example.org"


@pytest.mark.parametrize("address", ["", "bad", "name@example.org\r\nBcc: attacker@example.org"])
def test_missing_or_invalid_contact_does_not_queue_report(client, owner, address):
    result = client.post(report_url(submission(owner)), {"email": address})
    assert result.status_code == 400 and not IncidentReport.objects.exists()


def test_old_analysis_requires_original_and_checks_its_hash(client, owner):
    item = submission(owner, kind="file", content=b"original")
    result = client.post(report_url(item), {"email": "owner@example.org"})
    assert result.status_code == 400
    for content, expected in [(b"different", 400), (b"original", 302)]:
        result = client.post(
            report_url(item),
            {"email": "owner@example.org", "sample": SimpleUploadedFile("sample.txt", content)},
        )
        assert result.status_code == expected
    assert sample_path(item).read_bytes() == b"original"
    assert process_next_report()


@pytest.mark.parametrize(
    "error,state",
    [
        (smtplib.SMTPAuthenticationError(535, b"private credentials"), "failed"),
        (smtplib.SMTPServerDisconnected("private response"), "uncertain"),
        (PartialDelivery(), "uncertain"),
        (TimeoutError(), "uncertain"),
    ],
)
def test_failed_or_ambiguous_send_is_not_reported_and_not_retried_automatically(
    client, owner, error, state
):
    item = submission(owner)
    client.post(report_url(item), {"email": "owner@example.org"})
    with patch("analysis.reporting.EmailMessage.send", side_effect=error):
        assert process_next_report()
    report = IncidentReport.objects.get()
    assert report.status == state and report.sent_at is None
    assert not process_next_report()
    page = client.get(f"/results/{item.pk}/").content.decode()
    assert "private credentials" not in page and "private response" not in page
    if state == "uncertain":
        client.post(report_url(item), {"email": "owner@example.org"})
        report.refresh_from_db()
        assert report.status == "uncertain"
    else:
        client.post(report_url(item), {"email": "owner@example.org"})
        assert process_next_report()
        report.refresh_from_db()
        assert report.status == "sent" and report.attempts == 2


def test_interrupted_send_becomes_uncertain_not_queued(owner):
    item = submission(owner)
    report = IncidentReport.objects.create(
        submission=item,
        reporter=owner,
        email="owner@example.org",
        status="sending",
        started_at=timezone.now() - timedelta(minutes=6),
    )
    assert not process_next_report()
    report.refresh_from_db()
    assert report.status == "uncertain"


def test_smtp_backend_does_not_treat_partial_recipient_acceptance_as_success():
    backend = EmailBackend()
    backend.connection = Mock()
    backend.connection.sendmail.return_value = {RECIPIENTS[1]: (550, b"refused")}
    message = mail.EmailMessage("Test", "Body", "vigia@example.org", list(RECIPIENTS))
    with pytest.raises(PartialDelivery):
        backend._send(message)


def test_original_sample_is_private_and_removed_by_retention(client, owner):
    result = client.post(
        "/upload/", {"kind": "file", "file": SimpleUploadedFile("sample.txt", b"original")}
    )
    assert result.status_code == 302
    item = Submission.objects.get()
    assert sample_path(item).read_bytes() == b"original"
    assert sample_path(item).stat().st_mode & 0o777 == 0o600
    assert sample_path(item).parent.stat().st_mode & 0o777 == 0o700
    Submission.objects.filter(pk=item.pk).update(created_at=timezone.now() - timedelta(days=31))
    call_command("purge_submissions")
    assert not sample_path(item).exists()


def test_worker_keeps_original_for_risky_results_and_removes_clean_sample(client, owner):
    for verdict in ["no_indicators", "suspicious"]:
        client.post(
            "/upload/", {"kind": "file", "file": SimpleUploadedFile("sample.txt", b"original")}
        )
        item = Submission.objects.order_by("created_at").last()
        scanned = {"verdict": verdict, "details": {"providers": {}}}
        with patch(
            "analysis.management.commands.scan_worker.subprocess.run",
            return_value=Mock(stdout=json.dumps(scanned)),
        ):
            call_command("scan_worker", once=True)
        assert sample_path(item).exists() is (verdict == "suspicious")


def test_report_evidence_is_not_exposed_in_public_json(client, owner):
    item = submission(owner)
    client.post(report_url(item), {"email": "private@example.org"})
    payload = client.get(f"/results/{item.pk}/?format=json").json()
    assert payload["report"] == {"status": "queued"}
    assert "email" not in payload["report"]
    assert "details" not in payload
    assert AuditEvent.objects.filter(action="support_report_requested").count() == 1


def test_missing_retained_sample_is_a_known_failure_without_smtp_attempt(client, owner):
    item = submission(owner, kind="file")
    save_sample(item, b"sample")
    client.post(report_url(item), {"email": "owner@example.org"})
    sample_path(item).unlink()
    with patch("analysis.reporting.EmailMessage.send") as send:
        assert process_next_report()
    send.assert_not_called()
    assert IncidentReport.objects.get().status == "failed"


def test_report_retry_limit_requires_direct_support_contact(client, owner):
    item = submission(owner)
    IncidentReport.objects.create(
        submission=item, reporter=owner, email="owner@example.org", status="failed", attempts=3
    )
    assert client.post(report_url(item), {"email": "owner@example.org"}).status_code == 429
    assert not process_next_report()


@pytest.mark.parametrize(
    "email,expected",
    [("person@example.org", "person@example.org"), ("bad", ""), (["person@example.org"], "")],
)
def test_sso_contact_claim_is_optional_and_does_not_restrict_breach_lookup(
    client, settings, email, expected
):
    settings.OIDC_ISSUER = "https://sso.example.org/realms/company"
    settings.OIDC_CLIENT_ID = "vigia"
    claims = {
        "iss": settings.OIDC_ISSUER,
        "sub": "contact-user",
        "exp": int(time.time()) + 300,
        "email": email,
        "email_verified": False,
    }
    with patch("analysis.auth.oidc_client") as provider:
        provider.return_value.authorize_access_token.return_value = {"userinfo": claims}
        assert client.get("/auth/callback/").status_code == 302
    assert client.session["oidc_contact_email"] == expected
    settings.BREACH_PROVIDER = "xposedornot"
    page = client.get("/analisis/filtraciones/")
    assert not page.context["form"].fields["email"].disabled
