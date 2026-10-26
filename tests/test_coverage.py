import hashlib
import io
import json
import zipfile
from unittest.mock import patch

import pytest
import requests
from django.contrib.auth import get_user_model
from django.core.management import call_command
from pypdf import PdfWriter
from pypdf.generic import DecodedStreamObject, NameObject

from analysis.models import Submission
from analysis.scanner import Inspector, analyze


def pdf_sample(encrypted=False, compressed=False):
    writer = PdfWriter()
    writer.add_blank_page(width=100, height=100)
    if encrypted:
        writer.encrypt("test-only-password")
    if compressed:
        content = DecodedStreamObject()
        content.set_data(b"https://pdf-indicator.example/download")
        writer.pages[0][NameObject("/Contents")] = writer._add_object(content.flate_encode())
    result = io.BytesIO()
    writer.write(result)
    return result.getvalue()


def docx_sample():
    result = io.BytesIO()
    with zipfile.ZipFile(result, "w") as archive:
        archive.writestr("[Content_Types].xml", "<Types/>")
        archive.writestr("word/document.xml", "<document><body>Test</body></document>")
    return result.getvalue()


def vt_report(get, status=200, stats=None):
    get.return_value.status_code = status
    get.return_value.json.return_value = {
        "data": {
            "attributes": {
                "last_analysis_stats": stats if stats is not None else {"undetected": 60},
            }
        }
    }


@pytest.mark.parametrize("ext,content", [("pdf", pdf_sample()), ("docx", docx_sample())])
def test_complete_document_with_known_unflagged_hash_is_not_blanket_inconclusive(
    monkeypatch, tmp_path, ext, content
):
    monkeypatch.setenv("VT_API_KEY", "test-key")
    monkeypatch.delenv("AI_API_KEY", raising=False)
    path = tmp_path / f"sample.{ext}"
    path.write_bytes(content)
    with patch("analysis.scanner.requests.get") as get:
        vt_report(get)
        result = analyze(path, path.name, "file")
    assert result["verdict"] == "no_indicators"
    assert result["details"]["coverage"] == {
        "local_complete": True,
        "reputation_available": True,
        "reasons": [],
    }
    assert result["details"]["file"]["sha256"] == hashlib.sha256(content).hexdigest()


@pytest.mark.parametrize("ext,content", [("pdf", pdf_sample()), ("docx", docx_sample())])
def test_unknown_document_hash_stays_inconclusive_without_upload(
    monkeypatch, tmp_path, ext, content
):
    monkeypatch.setenv("VT_API_KEY", "test-key")
    monkeypatch.delenv("AI_API_KEY", raising=False)
    path = tmp_path / f"sample.{ext}"
    path.write_bytes(content)
    with (
        patch("analysis.scanner.requests.get") as get,
        patch("analysis.scanner.requests.post") as post,
    ):
        vt_report(get, status=404)
        result = analyze(path, path.name, "file")
    assert result["verdict"] == "inconclusive"
    coverage = result["details"]["coverage"]
    assert coverage["local_complete"]
    assert not coverage["reputation_available"]
    assert coverage["reasons"][0]["code"] == "unknown_hash"
    post.assert_not_called()


def test_encrypted_pdf_and_invalid_pdf_remain_incomplete():
    for content, reason in [
        (pdf_sample(encrypted=True), "pdf_encrypted"),
        (b"%PDF-1.7\n%%EOF", "pdf_parse_failed"),
    ]:
        scanner = Inspector()
        scanner.inspect(content, "sample.pdf")
        assert scanner.incomplete
        assert scanner.result()["verdict"] == "inconclusive"
        assert reason in [r["code"] for r in scanner.coverage_reasons]


def test_pdf_streams_are_decompressed_for_iocs():
    data = pdf_sample(compressed=True)
    assert b"https://pdf-indicator.example/download" not in data
    scanner = Inspector()
    scanner.inspect(data, "sample.pdf")
    assert not scanner.incomplete
    assert "https://pdf-indicator.example/download" in scanner.iocs["urls"]


def test_obfuscated_pdf_actions_are_detected_without_execution():
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R /Open#41ction 4 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 100 100] /Resources << >> >>",
        b"<< /S /Java#53cript /J#53 (app.alert\\(1\\)) >>",
    ]
    data = bytearray(b"%PDF-1.5\n")
    offsets = [0]
    for index, obj in enumerate(objects, 1):
        offsets.append(len(data))
        data += f"{index} 0 obj\n".encode() + obj + b"\nendobj\n"
    start = len(data)
    data += f"xref\n0 {len(offsets)}\n0000000000 65535 f \n".encode()
    for offset in offsets[1:]:
        data += f"{offset:010d} 00000 n \n".encode()
    data += f"trailer\n<< /Size {len(offsets)} /Root 1 0 R >>\nstartxref\n{start}\n%%EOF\n".encode()
    scanner = Inspector()
    scanner.inspect(bytes(data), "sample.pdf")
    assert scanner.result()["verdict"] == "suspicious"
    assert not scanner.incomplete


def test_pdf_parser_budget_failure_is_not_clean(monkeypatch):
    monkeypatch.setattr("analysis.pdf_inspection.MAX_PDF_OBJECTS", 2)
    scanner = Inspector()
    scanner.inspect(pdf_sample(), "sample.pdf")
    assert scanner.incomplete
    assert scanner.result()["verdict"] == "inconclusive"


@pytest.mark.parametrize(
    "status,reason",
    [
        (401, "authentication_error"),
        (403, "access_denied"),
        (404, "unknown_hash"),
        (429, "quota_exceeded"),
    ],
)
def test_vt_http_failures_have_explicit_reasons(monkeypatch, status, reason):
    monkeypatch.setenv("VT_API_KEY", "test-key")
    with patch("analysis.scanner.requests.get") as get:
        vt_report(get, status=status)
        scanner = Inspector()
        scanner.virus_total("a" * 64)
    result = scanner.result()
    assert result["verdict"] == "inconclusive"
    assert result["details"]["providers"]["virustotal"]["status"] == reason
    assert result["details"]["coverage"]["reasons"][0]["code"] == reason


@pytest.mark.parametrize(
    "error,reason", [(requests.Timeout(), "timeout"), (requests.ConnectionError(), "unavailable")]
)
def test_vt_network_failure_reasons(monkeypatch, error, reason):
    monkeypatch.setenv("VT_API_KEY", "test-key")
    with patch("analysis.scanner.requests.get", side_effect=error):
        scanner = Inspector()
        scanner.virus_total("a" * 64)
    assert scanner.providers["virustotal"]["status"] == reason
    assert scanner.result()["verdict"] == "inconclusive"


@pytest.mark.parametrize(
    "stats,reason",
    [
        ({"failure": 60}, "no_results"),
        ({}, "no_results"),
        ({"malicious": -1}, "invalid_response"),
        ({"malicious": "bad"}, "invalid_response"),
    ],
)
def test_vt_empty_or_invalid_engines_do_not_produce_no_indicators(monkeypatch, stats, reason):
    monkeypatch.setenv("VT_API_KEY", "test-key")
    with patch("analysis.scanner.requests.get") as get:
        vt_report(get, stats=stats)
        scanner = Inspector()
        scanner.virus_total("a" * 64)
    assert scanner.providers["virustotal"]["status"] == reason
    assert scanner.result()["verdict"] == "inconclusive"


@pytest.mark.django_db
def test_operator_diagnostics_do_not_print_iocs_file_contents_or_credentials(monkeypatch):
    monkeypatch.setenv("VT_API_KEY", "test-only-secret-key")
    user = get_user_model().objects.create_user(username="diagnostics")
    item = Submission.objects.create(
        owner=user,
        filename="private-filename.docx",
        kind="file",
        status="done",
        verdict="inconclusive",
        details={
            "incomplete": True,
            "findings": ["Inspección limitada."],
            "iocs": {"emails": ["private@example.org"]},
            "providers": {"virustotal": {"status": "unknown_hash"}},
        },
    )
    output = io.StringIO()
    call_command("diagnose_analysis", str(item.id), stdout=output)
    text = output.getvalue()
    data = json.loads(text)[0]
    assert data["extension"] == ".docx" and data["virustotal_status"] == "unknown_hash"
    assert "private-filename" not in text and "private@example.org" not in text
    assert "test-only-secret-key" not in text


@pytest.mark.django_db
def test_pdf_parses_in_real_limited_worker(settings, tmp_path, monkeypatch):
    monkeypatch.delenv("VT_API_KEY", raising=False)
    monkeypatch.delenv("AI_API_KEY", raising=False)
    settings.PRIVATE_STORAGE = tmp_path / "uploads"
    settings.PRIVATE_STORAGE.mkdir()
    user = get_user_model().objects.create_user(username="pdf-worker")
    item = Submission.objects.create(owner=user, filename="sample.pdf", kind="file")
    path = settings.PRIVATE_STORAGE / str(item.pk)
    path.write_bytes(pdf_sample())
    call_command("scan_worker", once=True)
    item.refresh_from_db()
    assert item.status == "done" and item.verdict == "inconclusive"
    assert item.details["coverage"]["local_complete"]
    assert item.details["providers"]["virustotal"]["status"] == "not_configured"
    assert not path.exists()
