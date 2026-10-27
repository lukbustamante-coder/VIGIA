from email.message import EmailMessage
from unittest.mock import Mock, patch

import pytest

from analysis.scanner import EICAR, Inspector


def inspect_email(body, *, subtype="plain", reply="replies@mailer.example", attachment=None):
    message = EmailMessage()
    message["From"] = "Notifications <notice@example.org>"
    message["To"] = "recipient@example.net"
    message["Reply-To"] = reply
    message["Subject"] = "Test notification"
    message.set_content(body, subtype=subtype)
    if attachment is not None:
        message.add_attachment(attachment, maintype="text", subtype="plain", filename="test.txt")
    inspector = Inspector()
    inspector.inspect(message.as_bytes(), "message.eml", "eml")
    return inspector


def test_different_reply_domain_is_informational_without_claiming_authenticity():
    inspector = inspect_email("Your request has been received.")
    assert inspector.result()["verdict"] == "no_indicators"
    assert any("From y Reply-To" in finding for finding in inspector.findings)
    assert any("SPF/DKIM/DMARC no verificados" in finding for finding in inspector.findings)


@pytest.mark.parametrize(
    "body,subtype",
    [
        ("Example: <script>alert(1)</script> and onerror=handler", "plain"),
        ("<p>Example: &lt;script&gt;alert(1)&lt;/script&gt;</p>", "html"),
        ("<p>Documentation about onload= and onerror=.</p>", "html"),
        ("<!-- <script>alert(1)</script> --><p>Notice</p>", "html"),
        ('<p title="onerror=example">Your request was received.</p>', "html"),
        ('<html><body><a href="https://example.org">View request</a></body></html>', "html"),
    ],
)
def test_passive_email_does_not_trigger_active_html_rule(body, subtype):
    inspector = inspect_email(body, subtype=subtype)
    assert inspector.result()["verdict"] == "no_indicators"


@pytest.mark.parametrize(
    "body",
    [
        "<script>alert(1)</script>",
        '<IFRAME src="https://example.org"></IFRAME>',
        '<img src="missing" ONERROR = "alert(1)">',
        '<body onload="alert(1)">Notice</body>',
        '<img src="missing" onerror="alert(1)"/>',
    ],
)
def test_active_html_remains_suspicious_despite_different_reply_domain(body):
    inspector = inspect_email(body, subtype="html")
    assert inspector.result()["verdict"] == "suspicious"
    assert "Correo HTML con contenido activo." in inspector.findings


def test_attachment_detection_is_preserved():
    inspector = inspect_email("Please review the attachment.", attachment=EICAR)
    assert inspector.result()["verdict"] == "malicious"


def test_unknown_html_charset_does_not_claim_complete_inspection():
    data = (
        b"From: sender@example.org\r\nMIME-Version: 1.0\r\n"
        b"Content-Type: text/html; charset=nonexistent-charset\r\n\r\n<p>Notice</p>"
    )
    inspector = Inspector()
    inspector.inspect(data, "message.eml", "eml")
    assert inspector.result()["verdict"] == "inconclusive"
    assert inspector.local_incomplete


@pytest.mark.parametrize(
    "malicious,suspicious,verdict",
    [(1, 0, "suspicious"), (0, 1, "suspicious"), (2, 0, "malicious")],
)
def test_virustotal_flags_are_not_suppressed(monkeypatch, malicious, suspicious, verdict):
    monkeypatch.setenv("VT_API_KEY", "test-key")
    inspector = inspect_email("Your request has been received.")
    response = Mock(status_code=200)
    response.json.return_value = {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": malicious,
                    "suspicious": suspicious,
                    "undetected": 60,
                }
            }
        }
    }
    with patch("analysis.scanner.requests.get", return_value=response):
        inspector.virus_total("0" * 64)
    assert inspector.result()["verdict"] == verdict
