import json
from datetime import timedelta
from email.message import EmailMessage
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from django.contrib.auth import get_user_model
from django.core.files.uploadedfile import SimpleUploadedFile
from django.core.management import call_command
from django.utils import timezone

from analysis.email_resources import advance, pending, prepare, public_summary, resource_directory
from analysis.forms import UploadForm
from analysis.management.commands.scan_worker import finish_error
from analysis.models import Submission
from analysis.scanner import analyze, poll_virustotal


def email_bytes(attachments=True):
    message = EmailMessage()
    message["From"] = "Alice <alice@example.org>"
    message["To"] = "bob@example.net"
    message.set_content("Review https://example.org/review?token=private-token")
    if attachments:
        message.add_attachment(
            b"private-attachment", maintype="text", subtype="plain", filename="../../private.txt"
        )
    return message.as_bytes()


def response(status=200, stats=None, analysis_id=None):
    return SimpleNamespace(
        status_code=status,
        raise_for_status=lambda: None,
        json=lambda: {
            "data": {
                "id": analysis_id,
                "attributes": {
                    "last_analysis_stats": stats or {"undetected": 60},
                    "stats": stats or {"undetected": 60},
                    "status": "completed",
                },
            }
        },
    )


@pytest.fixture(autouse=True)
def setup(settings, monkeypatch, tmp_path):
    settings.DEBUG = True
    settings.SECURE_SSL_REDIRECT = False
    settings.PRIVATE_STORAGE = tmp_path / "private"
    monkeypatch.setenv("VT_API_KEY", "test-key")
    monkeypatch.setenv("VT_ALLOW_EMAIL_RESOURCES", "true")
    monkeypatch.setenv("VT_ALLOW_SAMPLE_UPLOAD", "true")
    monkeypatch.setenv("VT_ALLOW_URL_SUBMISSION", "true")
    monkeypatch.setenv("AI_PROVIDER", "disabled")


@pytest.mark.parametrize("enabled,consent", [(False, True), (True, False), (False, False)])
def test_disabled_or_unconsented_resources_never_prepare_samples(
    monkeypatch, tmp_path, enabled, consent
):
    monkeypatch.setenv("VT_ALLOW_EMAIL_RESOURCES", str(enabled).lower())
    directory = tmp_path / "resources"
    with patch("requests.get") as get, patch("requests.post") as post:
        report = prepare(email_bytes(), {"https://example.org"}, directory, consent=consent)
    assert report["status"] == "not_authorized"
    assert not directory.exists()
    get.assert_not_called()
    post.assert_not_called()


def test_prepared_samples_are_private_bounded_deduplicated_and_not_in_json(tmp_path):
    directory = tmp_path / "resources"
    report = prepare(
        email_bytes(),
        {"https://example.org", "https://example.org/", "http://127.0.0.1/"},
        directory,
        consent=True,
    )
    assert len(report["items"]) == 2 and report["skipped"] == 1
    paths = list(directory.iterdir())
    assert len(paths) == 1 and paths[0].read_bytes() == b"private-attachment"
    assert directory.stat().st_mode & 0o777 == 0o700
    assert paths[0].stat().st_mode & 0o777 == 0o600
    assert "private-attachment" not in json.dumps(report)
    assert len(paths[0].name) == 64


def test_url_and_attachment_are_submitted_then_polled_without_resending(tmp_path):
    path = tmp_path / "mail"
    path.write_bytes(email_bytes())
    with patch("requests.get", return_value=response()):
        initial = analyze(path, "mail.eml", "eml", email_resources_consent=True)
    assert pending(initial["details"]["email_resources"])
    with (
        patch("requests.get", return_value=response(404)),
        patch("requests.post", return_value=response(analysis_id="resource-123")) as post,
    ):
        intermediate = poll_virustotal(initial["details"], resource_directory(path))
    assert post.call_count == 2
    sample = next(c for c in post.call_args_list if "files" in c.kwargs)
    assert sample.kwargs["files"]["file"][1] == b"private-attachment"
    assert sample.kwargs["files"]["file"][0] == "sample.txt"
    assert not list(resource_directory(path).iterdir())
    assert all(
        item["stage"] == "poll" for item in intermediate["details"]["email_resources"]["items"]
    )
    with (
        patch("requests.get", return_value=response(stats={"malicious": 3})),
        patch("requests.post") as post,
    ):
        final = poll_virustotal(intermediate["details"], resource_directory(path))
    post.assert_not_called()
    assert final["verdict"] == "malicious"
    report = final["details"]["email_resources"]
    assert not pending(report)
    assert "1 de 1 enlaces" in public_summary(report)
    assert "private-token" not in public_summary(report)


def test_resource_uploads_remain_disabled_by_global_sample_and_url_policies(monkeypatch, tmp_path):
    monkeypatch.setenv("VT_ALLOW_SAMPLE_UPLOAD", "false")
    monkeypatch.setenv("VT_ALLOW_URL_SUBMISSION", "false")
    path = tmp_path / "mail"
    path.write_bytes(email_bytes())
    with patch("requests.get", return_value=response()):
        initial = analyze(path, "mail.eml", "eml", email_resources_consent=True)
    with patch("requests.get", return_value=response(404)), patch("requests.post") as post:
        final = poll_virustotal(initial["details"], resource_directory(path))
    post.assert_not_called()
    assert final["verdict"] == "inconclusive"
    assert not pending(final["details"]["email_resources"])
    assert not list(resource_directory(path).iterdir())


def test_get_quota_preserves_pending_sample_but_failed_post_is_not_repeated(tmp_path):
    directory = tmp_path / "resources"
    report = prepare(email_bytes(), set(), directory, consent=True)
    with patch("requests.get", return_value=response(429)), patch("requests.post") as post:
        advance(report, directory)
    post.assert_not_called()
    assert pending(report) and len(list(directory.iterdir())) == 1
    with (
        patch("requests.get", return_value=response(404)),
        patch("requests.post", return_value=response(429)) as post,
    ):
        advance(report, directory)
        advance(report, directory)
    assert post.call_count == 1 and not pending(report)
    assert not list(directory.iterdir())


def test_batches_are_bounded_and_rotate_past_pending_analyses(tmp_path):
    urls = {f"https://example.org/{i}" for i in range(81)}
    report = prepare(email_bytes(False), urls, tmp_path / "resources", consent=True)
    with patch(
        "analysis.email_resources.lookup_url",
        return_value={"status": "queued", "analysis_id": "test-123"},
    ) as lookup:
        advance(report, None)
        assert lookup.call_count == 2
        advance(report, None)
        assert lookup.call_count == 4
    assert sum(item["stage"] == "lookup" for item in report["items"]) == 77


@pytest.mark.django_db
def test_worker_schedules_resources_without_a_parent_analysis_id_and_cleans_samples(settings):
    settings.VT_ALLOW_EMAIL_RESOURCES = True
    settings.PRIVATE_STORAGE.mkdir()
    user = get_user_model().objects.create_user(username="resource-worker")
    item = Submission.objects.create(
        owner=user, kind="eml", filename="mail.eml", email_resources_consent=True
    )
    path = settings.PRIVATE_STORAGE / str(item.pk)
    path.write_bytes(email_bytes())

    def run(args, **kwargs):
        assert kwargs["env"]["VT_ALLOW_EMAIL_RESOURCES"] == "true"
        if "--poll-vt" in args:
            result = poll_virustotal(json.loads(kwargs["input"]), args[-1])
        else:
            assert "--vt-email-resources" in args
            result = analyze(args[3], args[4], args[5], email_resources_consent=True)
        return SimpleNamespace(stdout=json.dumps(result))

    with (
        patch("analysis.management.commands.scan_worker.subprocess.run", side_effect=run),
        patch("requests.get", return_value=response()),
    ):
        call_command("scan_worker", once=True)
        item.refresh_from_db()
        assert item.status == "waiting_vt" and not path.exists()
        assert resource_directory(path).is_dir()
        Submission.objects.filter(pk=item.pk).update(
            vt_next_poll_at=timezone.now() - timedelta(seconds=1)
        )
        call_command("scan_worker", once=True)
        item.refresh_from_db()
    assert item.status == "done" and item.verdict == "no_indicators"
    assert not resource_directory(path).exists()


@pytest.mark.django_db
def test_timeout_removes_private_samples_and_keeps_completed_resource_detection(settings):
    settings.PRIVATE_STORAGE.mkdir()
    user = get_user_model().objects.create_user(username="resource-timeout")
    item = Submission.objects.create(
        owner=user,
        kind="eml",
        filename="mail.eml",
        details={
            "local_assessment": {},
            "email_resources": {
                "items": [
                    {"stage": "done", "provider": {"status": "ok", "stats": {"malicious": 4}}},
                    {"stage": "lookup"},
                ]
            },
        },
    )
    directory = resource_directory(settings.PRIVATE_STORAGE / str(item.pk))
    directory.mkdir()
    (directory / "sample").write_bytes(b"secret")
    finish_error(item, "external_analysis_timeout", "analysis_timeout")
    item.refresh_from_db()
    assert item.verdict == "malicious" and not directory.exists()
    assert not pending(item.details["email_resources"])


@pytest.mark.parametrize("module,enabled", [("file", True), ("eml", False)])
def test_forged_resource_consent_rejected(settings, module, enabled):
    settings.VT_ALLOW_EMAIL_RESOURCES = enabled
    upload = SimpleUploadedFile(
        "mail.eml" if module == "eml" else "note.txt",
        email_bytes(False) if module == "eml" else b"Hello",
    )
    form = UploadForm({"kind": module, "email_resources_consent": "on"}, {"file": upload})
    assert not form.is_valid()
    assert "no está habilitado" in str(form.errors)


@pytest.mark.django_db
def test_public_report_has_short_definitions_and_counts_without_resource_urls(client):
    user = get_user_model().objects.create_user(username="resource-reader")
    item = Submission.objects.create(
        owner=user,
        kind="eml",
        filename="mail.eml",
        status="done",
        verdict="no_indicators",
        details={
            "email_resources": {
                "status": "complete",
                "items": [
                    {
                        "kind": "url",
                        "target": "https://example.org/?token=private-token",
                        "stage": "done",
                        "provider": {"status": "ok", "stats": {"undetected": 60}},
                    }
                ],
            },
        },
    )
    client.force_login(user)
    html = client.get(f"/results/{item.pk}/").content.decode()
    assert "Una IP es" in html and "SPF indica" in html
    assert "DKIM es una firma" in html and "DMARC comprueba" in html
    assert "1 de 1 enlaces" in html and "private-token" not in html
    payload = client.get(f"/results/{item.pk}/?format=json").content.decode()
    assert "private-token" not in payload


def test_disabling_resource_policy_cancels_queued_transfers_and_removes_samples(
    monkeypatch, tmp_path
):
    directory = tmp_path / "resources"
    report = prepare(email_bytes(), {"https://example.org"}, directory, consent=True)
    monkeypatch.setenv("VT_ALLOW_EMAIL_RESOURCES", "false")
    with patch("requests.get") as get, patch("requests.post") as post:
        advance(report, directory)
    assert not pending(report) and not directory.exists()
    get.assert_not_called()
    post.assert_not_called()


@pytest.mark.django_db
def test_consent_is_persisted_and_audited_on_upload(settings, client):
    from analysis.models import AuditEvent

    settings.VT_ALLOW_EMAIL_RESOURCES = True
    user = get_user_model().objects.create_user(username="resource-consent")
    client.force_login(user)
    result = client.post(
        "/upload/",
        {
            "kind": "eml",
            "email_resources_consent": "on",
            "file": SimpleUploadedFile("mail.eml", email_bytes()),
        },
    )
    assert result.status_code == 302
    item = Submission.objects.get(owner=user)
    assert item.email_resources_consent and not item.vt_upload_consent
    assert AuditEvent.objects.filter(
        submission_id=item.pk, action="email_resources_authorized"
    ).exists()


def test_scanner_cli_processes_queue_without_secrets_or_sample_bytes_in_json(tmp_path, monkeypatch):
    import os
    import subprocess
    import sys

    monkeypatch.delenv("VT_API_KEY", raising=False)
    path = tmp_path / "mail"
    path.write_bytes(email_bytes())
    first = subprocess.run(
        [
            sys.executable,
            "-m",
            "analysis.scanner",
            str(path),
            "mail.eml",
            "eml",
            "--vt-email-resources",
        ],
        env=os.environ.copy(),
        capture_output=True,
        text=True,
        check=True,
    )
    result = json.loads(first.stdout)
    directory = resource_directory(path)
    assert pending(result["details"]["email_resources"])
    second = subprocess.run(
        [sys.executable, "-m", "analysis.scanner", "--poll-vt", str(directory)],
        input=json.dumps(result["details"]),
        env=os.environ.copy(),
        capture_output=True,
        text=True,
        check=True,
    )
    result = json.loads(second.stdout)
    assert result["verdict"] == "inconclusive"
    assert not pending(result["details"]["email_resources"])
    assert not list(directory.iterdir())
    assert "private-attachment" not in second.stdout


def test_main_email_and_resource_analyses_resume_together_without_reuploads(tmp_path):
    path = tmp_path / "mail"
    path.write_bytes(email_bytes())
    with (
        patch("requests.get", return_value=response(404)),
        patch("requests.post", return_value=response(analysis_id="main-123")) as post,
    ):
        initial = analyze(
            path, "mail.eml", "eml", upload_consent=True, email_resources_consent=True
        )
    assert post.call_count == 1

    def get(url, **kwargs):
        return response() if "/analyses/" in url else response(404)

    with (
        patch("requests.get", side_effect=get),
        patch("requests.post", return_value=response(analysis_id="child-123")) as post,
    ):
        middle = poll_virustotal(initial["details"], resource_directory(path))
    assert post.call_count == 2
    assert middle["details"]["providers"]["virustotal"]["status"] == "ok"
    with (
        patch("requests.get", return_value=response(stats={"malicious": 1})),
        patch("requests.post") as post,
    ):
        final = poll_virustotal(middle["details"], resource_directory(path))
    post.assert_not_called()
    assert final["verdict"] == "suspicious"
    assert final["details"]["providers"]["virustotal"]["stats"]["malicious"] == 0


@pytest.mark.django_db
def test_purge_removes_orphan_resource_samples_but_preserves_active_jobs(settings):
    settings.PRIVATE_STORAGE.mkdir()
    user = get_user_model().objects.create_user(username="resource-purge")
    item = Submission.objects.create(
        owner=user, filename="mail.eml", kind="eml", status="waiting_vt"
    )
    active = resource_directory(settings.PRIVATE_STORAGE / str(item.pk))
    active.mkdir()
    (active / "pending").write_bytes(b"secret")
    orphan = settings.PRIVATE_STORAGE / "11111111-1111-4111-8111-111111111111.resources"
    orphan.mkdir()
    (orphan / "sample").write_bytes(b"secret")
    call_command("purge_submissions")
    assert active.is_dir() and not orphan.exists()
    item.status = "failed"
    item.save(update_fields=["status"])
    call_command("purge_submissions")
    assert not active.exists()


def test_initial_email_hash_quota_does_not_permanently_block_resource_queue(tmp_path):
    path = tmp_path / "mail"
    path.write_bytes(email_bytes(False))
    with patch("requests.get", return_value=response(429)):
        initial = analyze(path, "mail.eml", "eml", email_resources_consent=True)
    with patch("requests.get", return_value=response()) as get:
        final = poll_virustotal(initial["details"], resource_directory(path))
    assert get.call_count == 1
    assert not pending(final["details"]["email_resources"])
    assert "1 de 1 enlaces" in public_summary(final["details"]["email_resources"])
