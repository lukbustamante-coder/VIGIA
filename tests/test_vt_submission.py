import io
import json
import zipfile
from datetime import timedelta
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from django.contrib.auth import get_user_model
from django.core.files.uploadedfile import SimpleUploadedFile
from django.core.management import call_command
from django.utils import timezone
from pypdf import PdfWriter

from analysis.forms import UploadForm
from analysis.models import AuditEvent, Submission
from analysis.scanner import analyze, poll_virustotal
from analysis.virustotal import fetch_analysis, submit_sample


@pytest.fixture(autouse=True)
def config(settings, monkeypatch, tmp_path):
    settings.DEBUG = True
    settings.SECURE_SSL_REDIRECT = False
    settings.PRIVATE_STORAGE = tmp_path / "uploads"
    monkeypatch.setenv("VT_API_KEY", "test-key")
    monkeypatch.delenv("AI_API_KEY", raising=False)
    monkeypatch.delenv("VT_ALLOW_SAMPLE_UPLOAD", raising=False)


def document(extension):
    output = io.BytesIO()
    if extension == "pdf":
        writer = PdfWriter()
        writer.add_blank_page(width=100, height=100)
        writer.write(output)
    else:
        with zipfile.ZipFile(output, "w") as archive:
            archive.writestr("[Content_Types].xml", "<Types/>")
            archive.writestr("word/document.xml", "<document>Test</document>")
    return output.getvalue()


def hash_response(status=404):
    return SimpleNamespace(
        status_code=status,
        raise_for_status=lambda: None,
        json=lambda: {"data": {"attributes": {"last_analysis_stats": {"undetected": 60}}}},
    )


def upload_response(status=200, analysis_id="test-analysis-123"):
    return SimpleNamespace(
        status_code=status,
        raise_for_status=lambda: None,
        json=lambda: {"data": {"id": analysis_id}},
    )


def analysis_response(status="completed", stats=None, http=200):
    return SimpleNamespace(
        status_code=http,
        raise_for_status=lambda: None,
        json=lambda: {
            "data": {
                "attributes": {
                    "status": status,
                    "stats": stats or {"undetected": 60},
                    "date": 1700000000,
                }
            }
        },
    )


@pytest.mark.parametrize("enabled,consented", [(False, False), (True, False), (False, True)])
def test_no_sample_upload_without_both_switches(monkeypatch, tmp_path, enabled, consented):
    monkeypatch.setenv("VT_ALLOW_SAMPLE_UPLOAD", str(enabled).lower())
    path = tmp_path / "private.txt"
    path.write_bytes(b"private content")
    with patch("requests.get", return_value=hash_response()), patch("requests.post") as post:
        result = analyze(path, path.name, "file", upload_consent=consented)
    post.assert_not_called()
    assert result["details"]["providers"]["virustotal"]["status"] == "unknown_hash"
    assert result["verdict"] == "inconclusive"


@pytest.mark.parametrize("extension", ["pdf", "docx"])
def test_unknown_hash_with_both_authorizations_uploads_actual_document(
    monkeypatch, tmp_path, extension
):
    monkeypatch.setenv("VT_ALLOW_SAMPLE_UPLOAD", "true")
    path = tmp_path / f"confidential-filename.{extension}"
    data = document(extension)
    path.write_bytes(data)
    with (
        patch("requests.get", return_value=hash_response()),
        patch("requests.post", return_value=upload_response()) as post,
    ):
        result = analyze(path, path.name, "file", upload_consent=True)
    assert post.call_count == 1
    assert post.call_args.args == ("https://www.virustotal.com/api/v3/files",)
    filename, sample, _ = post.call_args.kwargs["files"]["file"]
    assert filename == f"sample.{extension}" and sample == data
    assert post.call_args.kwargs["allow_redirects"] is False
    provider = result["details"]["providers"]["virustotal"]
    assert provider["sample_uploaded"] and provider["status"] == "queued"
    assert result["details"]["local_assessment"]["incomplete"] is False


def test_existing_hash_report_does_not_upload_again(monkeypatch, tmp_path):
    monkeypatch.setenv("VT_ALLOW_SAMPLE_UPLOAD", "true")
    path = tmp_path / "sample.txt"
    path.write_bytes(b"test")
    with patch("requests.get", return_value=hash_response(200)), patch("requests.post") as post:
        result = analyze(path, path.name, "file", upload_consent=True)
    assert result["verdict"] == "no_indicators"
    post.assert_not_called()


@pytest.mark.parametrize(
    "http,status",
    [
        (401, "authentication_error"),
        (403, "access_denied"),
        (429, "quota_exceeded"),
        (302, "unavailable"),
    ],
)
def test_submission_errors_do_not_create_fake_results(http, status):
    with patch("requests.post", return_value=upload_response(http)):
        result = submit_sample(b"content", "sample.txt", "test-key")
    assert result["status"] == status
    assert result["upload_attempted"]
    assert not result.get("analysis_id") and not result.get("sample_uploaded")


@pytest.mark.parametrize("analysis_id", ["../files", "https://attacker.example", "", None])
def test_invalid_analysis_id_never_makes_request(analysis_id):
    with patch("requests.get") as get:
        assert fetch_analysis(analysis_id, "test-key")["status"] == "invalid_response"
    get.assert_not_called()


@pytest.mark.parametrize(
    "malicious,expected", [(0, "no_indicators"), (1, "suspicious"), (2, "malicious")]
)
def test_polling_combines_completed_vt_results_with_original_local_evidence(
    monkeypatch, tmp_path, malicious, expected
):
    monkeypatch.setenv("VT_ALLOW_SAMPLE_UPLOAD", "true")
    path = tmp_path / "sample.txt"
    path.write_bytes(b"test")
    with (
        patch("requests.get", return_value=hash_response()),
        patch("requests.post", return_value=upload_response()),
    ):
        initial = analyze(path, path.name, "file", upload_consent=True)
    path.unlink()
    with (
        patch(
            "requests.get",
            return_value=analysis_response(
                stats={"malicious": malicious, "undetected": 60 - malicious}
            ),
        ),
        patch("requests.post") as post,
    ):
        final = poll_virustotal(initial["details"])
    post.assert_not_called()
    assert final["verdict"] == expected
    assert final["details"]["providers"]["virustotal"]["sample_uploaded"]
    assert final["details"]["coverage"]["reputation_available"]
    assert final["details"]["iocs"] == initial["details"]["iocs"]


@pytest.mark.django_db
@pytest.mark.parametrize("enabled", [True, False])
def test_upload_consent_is_enforced_and_audited_in_web_form(settings, client, enabled):
    settings.VT_ALLOW_SAMPLE_UPLOAD = enabled
    user = get_user_model().objects.create_user(username="consenting-user")
    client.force_login(user)
    assert ("vt_upload_consent" in UploadForm().fields) == enabled
    response = client.post(
        "/upload/",
        {
            "kind": "file",
            "vt_upload_consent": "on",
            "file": SimpleUploadedFile("sample.txt", b"test"),
        },
    )
    assert response.status_code == (302 if enabled else 400)
    if enabled:
        item = Submission.objects.get()
        assert item.vt_upload_consent
        assert AuditEvent.objects.filter(
            action="vt_upload_authorized", submission_id=item.pk
        ).exists()
    else:
        assert not Submission.objects.exists()


@pytest.mark.django_db
@pytest.mark.parametrize("extension", ["pdf", "docx"])
def test_worker_upload_wait_poll_complete_without_resending_sample(
    settings, monkeypatch, extension
):
    settings.VT_ALLOW_SAMPLE_UPLOAD = True
    monkeypatch.setenv("VT_ALLOW_SAMPLE_UPLOAD", "true")
    settings.PRIVATE_STORAGE.mkdir()
    user = get_user_model().objects.create_user(username="worker-consent")
    item = Submission.objects.create(
        owner=user, filename=f"private.{extension}", kind="file", vt_upload_consent=True
    )
    path = settings.PRIVATE_STORAGE / str(item.id)
    path.write_bytes(document(extension))

    def scanner_process(args, **kwargs):
        if args[-1] == "--poll-vt":
            assert not path.exists()
            result = poll_virustotal(json.loads(kwargs["input"]))
        else:
            assert args[-1] == "--upload-to-vt"
            assert kwargs["env"]["VT_ALLOW_SAMPLE_UPLOAD"] == "true"
            result = analyze(args[3], args[4], args[5], upload_consent=True)
        return SimpleNamespace(stdout=json.dumps(result))

    with (
        patch(
            "analysis.management.commands.scan_worker.subprocess.run", side_effect=scanner_process
        ),
        patch("requests.get", return_value=hash_response()) as get,
        patch("requests.post", return_value=upload_response()) as post,
    ):
        call_command("scan_worker", once=True)
        item.refresh_from_db()
        assert item.status == "waiting_vt" and item.verdict == "pending"
        assert not path.exists() and item.vt_deadline_at
        deadline = item.vt_deadline_at
        for status in ["in-progress", "completed"]:
            Submission.objects.filter(pk=item.pk).update(
                vt_next_poll_at=timezone.now() - timedelta(seconds=1)
            )
            get.return_value = analysis_response(status)
            call_command("scan_worker", once=True)
            item.refresh_from_db()
        assert item.status == "done" and item.verdict == "no_indicators"
        assert item.vt_poll_count == 2 and item.vt_deadline_at == deadline
        assert item.details["providers"]["virustotal"]["sample_uploaded"]
        assert post.call_count == 1
    assert AuditEvent.objects.filter(action="vt_sample_uploaded").count() == 1
    assert AuditEvent.objects.filter(action="vt_analysis_completed").count() == 1


@pytest.mark.django_db
def test_remote_timeout_preserves_local_detection_and_never_resubmits(client):
    user = get_user_model().objects.create_user(username="remote-timeout")
    item = Submission.objects.create(
        owner=user,
        filename="sample.txt",
        kind="file",
        status="waiting_vt",
        vt_next_poll_at=timezone.now() - timedelta(seconds=1),
        vt_deadline_at=timezone.now() - timedelta(seconds=1),
        details={
            "local_assessment": {"malicious": True, "suspicious": False, "incomplete": False},
            "providers": {
                "virustotal": {
                    "analysis_id": "test-analysis-123",
                    "sample_uploaded": True,
                    "status": "queued",
                }
            },
        },
    )
    with patch("analysis.management.commands.scan_worker.subprocess.run") as process:
        call_command("scan_worker", once=True)
    process.assert_not_called()
    item.refresh_from_db()
    assert item.status == "failed" and item.verdict == "malicious"
    assert item.details["providers"]["virustotal"]["status"] == "analysis_timeout"


@pytest.mark.django_db
def test_waiting_remote_result_does_not_expose_provider_id_to_user(client):
    user = get_user_model().objects.create_user(username="remote-user")
    item = Submission.objects.create(
        owner=user,
        filename="sample.txt",
        kind="file",
        status="waiting_vt",
        details={
            "providers": {"virustotal": {"analysis_id": "private-analysis-id", "status": "queued"}}
        },
    )
    client.force_login(user)
    response = client.get(f"/results/{item.pk}/")
    assert "Esperando a VirusTotal" in response.content.decode()
    assert b"private-analysis-id" not in response.content
    assert b'data-analysis-status="waiting_vt"' in response.content
    assert set(client.get(f"/results/{item.pk}/?format=json").json()) == {
        "id",
        "status",
        "verdict",
        "label",
    }


def test_invalid_upload_response_acknowledges_transfer_without_fake_analysis_id():
    with patch("requests.post", return_value=upload_response(analysis_id="../bad-id")):
        result = submit_sample(b"content", "sample.txt", "test-key")
    assert result["sample_uploaded"] and result["status"] == "invalid_response"
    assert not result.get("analysis_id")


@pytest.mark.django_db
def test_revoked_operator_policy_prevents_upload_of_previously_consented_job(settings, monkeypatch):
    settings.VT_ALLOW_SAMPLE_UPLOAD = False
    monkeypatch.setenv("VT_ALLOW_SAMPLE_UPLOAD", "true")
    settings.PRIVATE_STORAGE.mkdir()
    user = get_user_model().objects.create_user(username="policy-revoked")
    item = Submission.objects.create(
        owner=user, filename="sample.txt", kind="file", vt_upload_consent=True
    )
    path = settings.PRIVATE_STORAGE / str(item.pk)
    path.write_bytes(b"test")

    def scanner_process(args, **kwargs):
        assert "--upload-to-vt" not in args
        assert kwargs["env"]["VT_ALLOW_SAMPLE_UPLOAD"] == "false"
        return SimpleNamespace(stdout=json.dumps(analyze(args[3], args[4], args[5])))

    with (
        patch(
            "analysis.management.commands.scan_worker.subprocess.run", side_effect=scanner_process
        ),
        patch("requests.get", return_value=hash_response()),
        patch("requests.post") as post,
    ):
        call_command("scan_worker", once=True)
    post.assert_not_called()
    item.refresh_from_db()
    assert item.status == "done" and item.verdict == "inconclusive"


@pytest.mark.django_db
def test_poll_quota_backoff_preserves_job_without_reupload(settings):
    user = get_user_model().objects.create_user(username="poll-backoff")
    item = Submission.objects.create(
        owner=user,
        filename="sample.txt",
        kind="file",
        status="waiting_vt",
        vt_next_poll_at=timezone.now() - timedelta(seconds=1),
        vt_deadline_at=timezone.now() + timedelta(minutes=20),
        details={
            "local_assessment": {"malicious": False, "suspicious": False, "incomplete": False},
            "providers": {
                "virustotal": {
                    "analysis_id": "test-analysis",
                    "sample_uploaded": True,
                    "status": "queued",
                }
            },
        },
    )

    def scanner_process(args, **kwargs):
        assert args[-1] == "--poll-vt"
        return SimpleNamespace(stdout=json.dumps(poll_virustotal(json.loads(kwargs["input"]))))

    before = timezone.now()
    with (
        patch(
            "analysis.management.commands.scan_worker.subprocess.run", side_effect=scanner_process
        ),
        patch("requests.get", return_value=analysis_response(http=429)),
        patch("requests.post") as post,
    ):
        call_command("scan_worker", once=True)
    post.assert_not_called()
    item.refresh_from_db()
    assert item.status == "waiting_vt" and item.verdict == "pending"
    assert item.vt_poll_count == 1
    assert item.vt_next_poll_at >= before + timedelta(seconds=60)
    assert item.details["providers"]["virustotal"]["analysis_id"] == "test-analysis"
