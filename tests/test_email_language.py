from email.message import EmailMessage

import pytest
from django.contrib.auth import get_user_model

from analysis.email_language import AUTH_RESULTS, explain_method
from analysis.models import Submission
from analysis.presentation import email_explanation
from analysis.scanner import Inspector


@pytest.mark.parametrize("result", list(AUTH_RESULTS))
def test_each_authentication_result_has_distinct_explanation(result):
    report = explain_method("spf", [result, result])
    assert report["declared"] == result.upper()
    assert report["result_label"] == AUTH_RESULTS[result][0]
    assert report["interpretation"] == AUTH_RESULTS[result][1]
    assert "dominio" in report["description"]


def test_mixed_or_unknown_results_do_not_become_successful_validation():
    mixed = explain_method("dkim", ["pass", "fail", "pass"])
    assert mixed["declared"] == "PASS, FAIL"
    assert "Varios resultados" in mixed["result_label"]
    assert "única validación" in mixed["interpretation"]
    missing = explain_method("dkim", ["forged.example", "<script>", 42])
    assert missing["declared"] == "No consta"
    assert "No hay resultado" in missing["result_label"]
    assert "forged.example" not in str(missing)


def test_legacy_record_has_honest_routing_and_attachment_explanations():
    item = Submission(kind="eml", status="done", verdict="inconclusive", details={})
    report = email_explanation(item)
    assert not report["available"]
    assert "no conserva un recuento" in report["routing_explanation"]
    assert "no detalla por separado" in report["content_explanation"]
    assert "no está confirmada como completa" in report["content_explanation"]
    assert "No se pudo completar" in report["recommendation"]


@pytest.mark.django_db
def test_user_gets_detailed_interpretation_even_when_ai_fails(client):
    user = get_user_model().objects.create_user(username="reader")
    item = Submission.objects.create(
        owner=user,
        kind="eml",
        filename="mail.eml",
        status="done",
        verdict="suspicious",
        details={
            "email_headers": {
                "received_count": 3,
                "attachment_count": 1,
                "truncated": True,
                "declared_authentication": {"spf": ["pass"], "dkim": ["fail"], "dmarc": []},
            },
            "iocs": {"urls": ["https://private.example/path"]},
            "coverage": {"local_complete": False},
            "providers": {"ai": {"status": "quota_exceeded"}},
        },
    )
    client.force_login(user)
    html = client.get(f"/results/{item.pk}/").content.decode()
    for title in (
        "Autorización del servidor de envío (SPF)",
        "Firma digital del correo (DKIM)",
        "Coherencia del dominio del remitente (DMARC)",
        "Enlaces, contenido y archivos adjuntos",
    ):
        assert title in html
    assert "Satisfactorio según el correo (PASS)" in html
    assert "No superado según el correo (FAIL)" in html
    assert "No hay resultado registrado" in html
    assert "3 etapas de entrega" in html and "fuera del límite" in html
    assert "Se identificó un archivo adjunto" in html
    assert "Evita interactuar" in html
    assert "private.example" not in html and "quota_exceeded" not in html
    assert "Se verificó" not in html and "se comprobó la validez" not in html


def test_attachment_count_is_observed_in_new_scans():
    message = EmailMessage()
    message["From"] = "sender@example.org"
    message.set_content("Hello")
    message.add_attachment(b"Read me", maintype="text", subtype="plain", filename="note.txt")
    scanner = Inspector()
    scanner.inspect(message.as_bytes(), "mail.eml", "eml")
    assert scanner.email_headers["attachment_count"] == 1
    assert scanner.result()["details"]["email_headers"]["attachment_count"] == 1


def test_concise_summary_uses_observed_domains_and_public_routing_ips():
    from analysis.email_language import concise_evidence

    methods = [explain_method(name, ["pass"]) for name in ("spf", "dkim", "dmarc")]
    routing = concise_evidence(
        {
            "selected": {
                "From": ["Alice <alice@example.org>"],
                "Return-Path": ["<bounce@example.org>"],
                "Received": [
                    "from mail.example.org ([8.8.8.8]) by relay; today",
                    "from internal ([10.0.0.1])",
                ],
                "DKIM-Signature": [{"d": "example.org"}],
            }
        },
        methods,
    )
    assert "8.8.8.8" in routing and "10.0.0.1" not in routing
    assert "No se comprobó que pertenezcan" in routing
    assert "coincide exactamente" in methods[0]["summary"]
    assert "mismo dominio" in methods[1]["summary"]
    assert "El correo declara PASS" in methods[2]["summary"]
    assert "alice@" not in str(methods)


def test_different_signer_is_not_called_fraud_and_conflicting_results_are_preserved():
    from analysis.email_language import concise_evidence

    methods = [explain_method(name, ["pass", "fail"]) for name in ("spf", "dkim", "dmarc")]
    concise_evidence(
        {
            "selected": {
                "From": ["alice@example.org"],
                "Return-Path": ["bounce@mailer.example.net"],
                "DKIM-Signature": [{"d": "mailer.example.net"}],
            }
        },
        methods,
    )
    assert "no implica fraude" in methods[0]["summary"]
    assert "no demuestra suplantación" in methods[1]["summary"]
    assert "PASS, FAIL" in methods[2]["summary"]
    assert "cumple las reglas" not in methods[2]["summary"]


def test_missing_or_ambiguous_sender_does_not_invent_domain_matches():
    from analysis.email_language import concise_evidence

    methods = [explain_method(name, []) for name in ("spf", "dkim", "dmarc")]
    routing = concise_evidence({"selected": {"From": ["a@example.org", "b@other.org"]}}, methods)
    assert "no pudo determinarse" in routing
    assert all("No hay resultado registrado" in method["summary"] for method in methods)
    assert "coincide exactamente" not in str(methods)
