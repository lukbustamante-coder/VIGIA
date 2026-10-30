import pytest
from django.contrib.auth import get_user_model

from analysis.models import Submission
from analysis.presentation import email_explanation, result_summary
from analysis.recommendations import SUPPORT_EMAIL, guidance_for


@pytest.mark.parametrize("kind", ["url", "file", "eml"])
@pytest.mark.parametrize("verdict", ["malicious", "suspicious", "no_indicators", "inconclusive"])
def test_guidance_uses_module_specific_reporting_channels(kind, verdict):
    item = Submission(kind=kind, status="done", verdict=verdict)
    guidance = guidance_for(item)
    assert guidance["action"] and guidance["detail"]
    assert "equipo de seguridad" not in guidance["text"]
    if kind == "file":
        assert "Ciberseguridad de UTEM" in guidance["text"]
        assert guidance["email"] == ""
    else:
        assert guidance["email"] == SUPPORT_EMAIL
        assert "soporte" in guidance["text"].lower()
        if kind == "eml":
            assert "Ciberseguridad de UTEM" in guidance["text"]
    if verdict == "malicious":
        assert guidance["action"].startswith("No abras")
    if verdict == "no_indicators":
        assert "garantiza" in result_summary(item, False)["message"]
        assert "dudas" in guidance["detail"]


@pytest.mark.parametrize("kind", ["url", "file", "eml"])
@pytest.mark.parametrize("status", ["queued", "running", "waiting_vt", "polling_vt"])
def test_pending_analysis_does_not_offer_final_guidance_from_stale_verdict(kind, status):
    item = Submission(kind=kind, status=status, verdict="no_indicators")
    assert "Espera" in guidance_for(item)["action"]
    assert "todavía no hay un resultado final" in guidance_for(item)["text"]
    assert guidance_for(item)["email"] == ""
    assert result_summary(item, False)["pending"]


def test_failed_analysis_cannot_suggest_proceeding_based_on_old_clean_value():
    item = Submission(kind="url", status="failed", verdict="no_indicators")
    assert "Evita abrir esta URL" in guidance_for(item)["action"]
    assert "No hay información suficiente" in guidance_for(item)["detail"]
    item.verdict = "malicious"
    assert "No abras esta URL" in guidance_for(item)["action"]


@pytest.mark.django_db
@pytest.mark.parametrize("kind", ["url", "file", "eml"])
def test_result_displays_one_bold_guidance_and_only_authorized_support_address(client, kind):
    user = get_user_model().objects.create_user(username="guidance-reader")
    item = Submission.objects.create(
        owner=user,
        kind=kind,
        filename="prueba",
        status="done",
        verdict="malicious",
        target_url="https://private.example/?token=secret" if kind == "url" else "",
    )
    client.force_login(user)
    html = client.get(f"/results/{item.pk}/").content.decode()
    assert html.count('id="guidance-heading"') == 1
    assert "<strong>No abras" in html
    assert "contacta a tu equipo de seguridad" not in html
    if kind == "file":
        assert "Reporta el archivo al equipo de Ciberseguridad de UTEM" in html
        guidance_html = html.split('id="guidance-heading"', 1)[1].split("</section>", 1)[0]
        assert 'href="mailto:' not in guidance_html
    else:
        assert f'href="mailto:{SUPPORT_EMAIL}"' in html
        assert "mailto:soporte.sisei@utem.cl?" not in html
    assert "private.example" not in html and "token=secret" not in html


def test_cached_ai_advice_is_replaced_by_current_institutional_email_guidance():
    old = {
        "summary": "Resumen de ejemplo.",
        "routing": "Ruta observada.",
        "authentication": "Autenticación declarada.",
        "recommendation": "Abre el mensaje y responde con datos personales.",
    }
    item = Submission(
        kind="eml",
        status="done",
        verdict="malicious",
        details={"providers": {"ai": {"status": "ok", "version": 1, "user_report": old}}},
    )
    email = email_explanation(item)
    current = guidance_for(item)["text"]
    assert email["recommendation"] == email["report"]["recommendation"] == current
    assert (
        "No abras" in current and "Ciberseguridad de UTEM" in current and SUPPORT_EMAIL in current
    )
    assert old["recommendation"] == "Abre el mensaje y responde con datos personales."
