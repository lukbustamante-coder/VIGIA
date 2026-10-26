import io
import json
import time
import zipfile
from unittest.mock import patch

import pytest
from django.contrib.auth import get_user_model
from django.core.files.uploadedfile import SimpleUploadedFile
from django.core.management import call_command
from django.test import Client
from joserfc import jwt
from joserfc.jwk import RSAKey

from analysis.auth import oidc_client
from analysis.forms import UploadForm
from analysis.models import AuditEvent, Submission
from analysis.scanner import EICAR, Inspector

pytestmark = pytest.mark.django_db


@pytest.fixture(autouse=True)
def configuration(settings, tmp_path):
    settings.DEBUG = True
    settings.SECURE_SSL_REDIRECT = False
    settings.PRIVATE_STORAGE = tmp_path / "uploads"
    settings.OIDC_ISSUER = "https://sso.example.org/realms/vigia"
    settings.OIDC_CLIENT_ID = "vigia"
    settings.OIDC_CLIENT_SECRET = "test-only-client-secret"


@pytest.fixture
def user():
    return get_user_model().objects.create_user(username="alice")


@pytest.fixture
def other():
    return get_user_model().objects.create_user(username="bob")


def upload_file(client, content=b"contenido de prueba", filename="sample.txt", kind="file"):
    return client.post("/upload/", {"kind": kind, "file": SimpleUploadedFile(filename, content)})


def archive(entries):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as stream:
        for name, value in entries.items():
            stream.writestr(name, value)
    return buffer.getvalue()


def test_authentication_required(client):
    assert client.post("/upload/").status_code == 302
    assert client.get("/").status_code == 200
    assert client.get("/health/")["Content-Security-Policy"].startswith("default-src 'none'")


def test_csrf_and_method_enforced(user):
    client = Client(enforce_csrf_checks=True)
    client.force_login(user)
    assert upload_file(client).status_code == 403
    assert client.get("/upload/").status_code == 405
    assert client.get("/auth/logout/").status_code == 405


@pytest.mark.parametrize(
    "origin, expected", [("http://testserver", 302), ("https://other.example", 403), ("null", 403)]
)
def test_upload_csrf_origin_validation(user, origin, expected):
    client = Client(enforce_csrf_checks=True)
    client.force_login(user)
    response = client.get("/")
    assert response["Referrer-Policy"] == "same-origin"
    token = client.cookies["csrftoken"].value
    response = client.post(
        "/upload/",
        {
            "kind": "file",
            "file": SimpleUploadedFile("sample.txt", b"CSRF protected upload"),
            "csrfmiddlewaretoken": token,
        },
        HTTP_ORIGIN=origin,
    )
    assert response.status_code == expected
    assert Submission.objects.count() == (1 if expected == 302 else 0)


def test_user_cannot_read_another_users_result(client, user, other):
    item = Submission.objects.create(
        owner=other,
        filename="secret.txt",
        kind="file",
        details={"iocs": {"urls": ["https://evil.example"]}},
    )
    client.force_login(user)
    assert client.get(f"/results/{item.id}/?format=json").status_code == 404


def test_user_only_sees_verdict_and_admin_sees_iocs(client, user):
    item = Submission.objects.create(
        owner=user,
        filename="sample.txt",
        kind="file",
        verdict="suspicious",
        details={"iocs": {"urls": ["https://evil.example/<script>"]}},
    )
    client.force_login(user)
    assert "details" not in client.get(f"/results/{item.id}/?format=json").json()
    assert b"evil.example" not in client.get(f"/results/{item.id}/").content
    session = client.session
    session["roles"] = ["vigia-admin"]
    session.save()
    assert "details" in client.get(f"/results/{item.id}/?format=json").json()
    html = client.get(f"/results/{item.id}/").content
    assert b"&lt;script&gt;" in html and b"<script>" not in html
    assert AuditEvent.objects.filter(action="view_ioc").count() == 2


@pytest.mark.parametrize(
    "filename,content,kind",
    [
        ("file.exe", b"MZtest", "file"),
        ("x.eml", b"From: a@b.test\n\nbody", "file"),
        ("x.pdf", b"%PDF-1.7", "eml"),
        ("x.pdf", b"MZfake", "file"),
        ("x.docx", archive({"fake": b"x"}), "file"),
        ("x.txt", b"", "file"),
        ("x.txt", b"\x00binary", "file"),
    ],
)
def test_invalid_upload_rejected(filename, content, kind):
    assert not UploadForm(
        {"kind": kind}, {"file": SimpleUploadedFile(filename, content)}
    ).is_valid()


@pytest.mark.parametrize(
    "filename,content,kind",
    [
        ("x.pdf", b"%PDF-1.7\n%%EOF", "file"),
        ("x.eml", b"From: a@b.test\nTo: c@d.test\nSubject: Test\n\nbody", "eml"),
        ("x.zip", archive({"readme.txt": b"hello"}), "file"),
        (
            "x.docx",
            archive({"[Content_Types].xml": b"<Types/>", "word/document.xml": b"<document/>"}),
            "file",
        ),
        ("x.rtf", b"{\\rtf1 test}", "file"),
    ],
)
def test_valid_format_accepted(filename, content, kind):
    assert UploadForm({"kind": kind}, {"file": SimpleUploadedFile(filename, content)}).is_valid()


def test_upload_limits_and_private_storage(client, user, settings):
    client.force_login(user)
    assert upload_file(client).status_code == 302
    item = Submission.objects.get()
    path = settings.PRIVATE_STORAGE / str(item.pk)
    assert path.read_bytes() == b"contenido de prueba"
    assert path.stat().st_mode & 0o777 == 0o600
    assert client.get(f"/media/{item.pk}").status_code == 404
    for i in range(19):
        Submission.objects.create(owner=user, filename=f"{i}.txt", kind="file")
    assert upload_file(client).status_code == 429


def test_real_worker_eicar_and_removal(client, user, settings, monkeypatch):
    monkeypatch.delenv("VT_API_KEY", raising=False)
    monkeypatch.delenv("AI_API_KEY", raising=False)
    client.force_login(user)
    assert upload_file(client, EICAR).status_code == 302
    item = Submission.objects.get()
    call_command("scan_worker", once=True)
    item.refresh_from_db()
    assert item.status == "done"
    assert item.verdict == "malicious"
    assert item.details["iocs"]["sha256"]
    assert not (settings.PRIVATE_STORAGE / str(item.pk)).exists()


def test_mime_attachment_and_spoofed_headers():
    data = (
        b"From: sender@example.org\nReply-To: thief@evil.example\n"
        b"Authentication-Results: forged; spf=pass; dkim=pass\n"
        b"MIME-Version: 1.0\nContent-Type: multipart/mixed; boundary=demo\n\n"
        b"--demo\nContent-Type: text/plain\n\nhttps://evil.example/login\n"
        b"--demo\nContent-Type: application/octet-stream\n"
        b'Content-Disposition: attachment; filename="test.txt"\n\n' + EICAR + b"\n--demo--\n"
    )
    scanner = Inspector()
    scanner.inspect(data, "mail.eml", "eml")
    result = scanner.result()
    assert result["verdict"] == "malicious"
    assert "https://evil.example/login" in result["details"]["iocs"]["urls"]
    assert any("SPF/DKIM/DMARC no verificados" in x for x in scanner.findings)


def test_zip_bomb_and_traversal():
    scanner = Inspector()
    scanner.inspect(archive({"../payload.txt": b"0" * 200000}), "bomb.zip")
    assert scanner.result()["verdict"] == "suspicious"
    assert scanner.incomplete
    assert any("Ruta peligrosa" in x for x in scanner.findings)


def test_office_external_relation():
    scanner = Inspector()
    scanner.inspect(
        archive(
            {
                "[Content_Types].xml": b"<Types/>",
                "word/_rels/document.xml.rels": b'<Relationships><Relationship TargetMode="External" Target="https://evil.example/a"/></Relationships>',
            }
        ),
        "doc.docx",
    )
    assert scanner.result()["verdict"] == "suspicious"


def test_xxe_rejected():
    scanner = Inspector()
    scanner.inspect(
        archive(
            {
                "[Content_Types].xml": b'<!DOCTYPE a [<!ENTITY x SYSTEM "file:///etc/passwd">]><a>&x;</a>',
                "word/document.xml": b"<doc/>",
            }
        ),
        "doc.docx",
    )
    assert scanner.incomplete


def test_vt_only_sends_hash_and_unknown_not_clean(monkeypatch):
    monkeypatch.setenv("VT_API_KEY", "test-key")
    with patch("analysis.scanner.requests.get") as get:
        get.return_value.status_code = 404
        scanner = Inspector()
        scanner.virus_total("a" * 64)
        assert get.call_args.args[0] == "https://www.virustotal.com/api/v3/files/" + "a" * 64
        assert get.call_args.kwargs["allow_redirects"] is False
        assert scanner.result()["verdict"] == "inconclusive"


def test_ai_does_not_send_iocs_or_overrule_verdict(monkeypatch):
    monkeypatch.setenv("AI_API_KEY", "test-key")
    scanner = Inspector()
    scanner.iocs["emails"].add("secret@example.org")
    scanner.malicious = True
    with patch("analysis.scanner.requests.post") as post:
        post.return_value.json.return_value = {"choices": [{"message": {"content": "Seguro"}}]}
        scanner.ai()
        assert "secret@example.org" not in json.dumps(post.call_args.kwargs["json"])
        assert scanner.result()["verdict"] == "malicious"


@pytest.mark.parametrize(
    "change",
    [
        {},
        {"iss": "https://attacker.example"},
        {"aud": "other-client"},
        {"nonce": "wrong-nonce"},
        {"exp": 1},
    ],
)
def test_signed_oidc_tokens_are_validated(client, settings, change):
    key = RSAKey.generate_key(parameters={"kid": "test"})
    app = oidc_client()
    metadata = {
        "issuer": settings.OIDC_ISSUER,
        "authorization_endpoint": settings.OIDC_ISSUER + "/protocol/openid-connect/auth",
        "token_endpoint": settings.OIDC_ISSUER + "/protocol/openid-connect/token",
        "jwks_uri": settings.OIDC_ISSUER + "/protocol/openid-connect/certs",
        "id_token_signing_alg_values_supported": ["RS256"],
    }
    with (
        patch("analysis.auth.oidc_client", return_value=app),
        patch.object(app, "load_server_metadata", return_value=metadata),
    ):
        response = client.get("/auth/login/")
        assert response.status_code == 302
        from urllib.parse import parse_qs, urlsplit

        query = parse_qs(urlsplit(response.url).query)
        assert query["code_challenge_method"] == ["S256"]
        claims = {
            "iss": settings.OIDC_ISSUER,
            "sub": "keycloak-user",
            "aud": "vigia",
            "iat": int(time.time()),
            "exp": int(time.time()) + 300,
            "nonce": query["nonce"][0],
            "resource_access": {"vigia": {"roles": ["vigia-admin"]}},
        }
        claims.update(change)
        token = jwt.encode({"alg": "RS256", "kid": "test"}, claims, key)
        with (
            patch.object(
                app,
                "fetch_access_token",
                return_value={"id_token": token, "access_token": "unused"},
            ),
            patch.object(app, "fetch_jwk_set", return_value={"keys": [key.as_dict(private=False)]}),
        ):
            response = client.get("/auth/callback/", {"code": "test", "state": query["state"][0]})
    if change:
        assert response.status_code == 400
        assert "_auth_user_id" not in client.session
    else:
        assert response.status_code == 302
        assert client.session["roles"] == ["vigia-admin"]
        assert client.session.get_expiry_age() <= 300
        assert "access_token" not in str(dict(client.session))


def test_oidc_callback_requires_state(client):
    assert client.get("/auth/callback/", {"code": "attacker", "state": "fake"}).status_code == 400


def test_streaming_limit_before_storage(client, user, settings):
    settings.MAX_UPLOAD_BYTES = 8
    client.force_login(user)
    assert upload_file(client, b"too much content").status_code == 400
    assert Submission.objects.count() == 0


def test_missing_original_is_failed_not_clean(client, user, settings):
    client.force_login(user)
    item = Submission.objects.create(owner=user, filename="missing.txt", kind="file")
    call_command("scan_worker", once=True)
    item.refresh_from_db()
    assert item.status == "failed"
    assert item.verdict == "inconclusive"


def test_vt_auth_or_rate_error_is_inconclusive(monkeypatch):
    import requests

    monkeypatch.setenv("VT_API_KEY", "test-key")
    with patch("analysis.scanner.requests.get") as get:
        get.return_value.raise_for_status.side_effect = requests.HTTPError("429")
        scanner = Inspector()
        scanner.virus_total("a" * 64)
        assert scanner.result()["verdict"] == "inconclusive"


def test_expired_worker_is_recovered(user):
    from datetime import timedelta

    from django.utils import timezone

    item = Submission.objects.create(
        owner=user,
        kind="file",
        filename="x.txt",
        status="running",
        started_at=timezone.now() - timedelta(minutes=6),
    )
    call_command("scan_worker", once=True)
    item.refresh_from_db()
    assert item.status == "failed" and item.verdict == "inconclusive"
