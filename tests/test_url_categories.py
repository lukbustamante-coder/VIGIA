import json
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest
from django.contrib.auth import get_user_model

from analysis.models import Submission
from analysis.presentation import url_categorization
from analysis.scanner import poll_virustotal
from analysis.url_categories import bounded_categories, public_categories
from analysis.url_inspection import analyze_url


@pytest.mark.parametrize(
    "raw,label",
    [
        ("pornography", "Contenido para adultos / pornografía"),
        ("Adult/Mature Content", "Contenido para adultos / pornografía"),
        ("Education/Reference", "Educación"),
        ("education", "Educación"),
        ("News and Media", "Noticias y medios"),
        ("Social Networking", "Redes sociales"),
        ("shopping", "Comercio y compras"),
        ("gambling", "Apuestas"),
        ("information technology", "Tecnología"),
        ("government", "Gobierno e instituciones públicas"),
        ("health", "Salud"),
        ("finance", "Finanzas"),
    ],
)
def test_categories_translate_only_recognized_labels(raw, label):
    assert public_categories({"service": raw}) == {"status": "available", "labels": [label]}


def test_disagreement_is_preserved_and_sex_education_is_not_pornography():
    result = public_categories({"A": "education", "B": "pornography", "C": "education"})
    assert len(result["labels"]) == 2
    assert "Educación" in result["labels"]
    assert public_categories({"A": "sex education"}) == {"status": "unrecognized", "labels": []}


@pytest.mark.parametrize("value", [None, [], "education", {}, {"x": ["education"]}])
def test_missing_or_malformed_categories_are_not_invented(value):
    assert public_categories(value) == {"status": "unavailable", "labels": []}


def test_raw_labels_are_bounded_and_never_used_as_public_text():
    data = {"unsafe": "<script>https://secret.example</script>"}
    assert public_categories(data) == {"status": "unrecognized", "labels": []}
    assert len(bounded_categories({str(i): "x" * 1000 for i in range(40)})) == 20
    assert len(bounded_categories({"a": "x" * 1000})["a"]) == 200


def vt_response(categories, stats):
    result = Mock(status_code=200)
    result.json.return_value = {
        "data": {"attributes": {"categories": categories, "last_analysis_stats": stats}}
    }
    return result


@pytest.mark.parametrize(
    "categories,stats,verdict",
    [
        ({"A": "pornography"}, {"undetected": 60}, "no_indicators"),
        ({"A": "education"}, {"malicious": 2}, "malicious"),
        ({"A": "education"}, {}, "inconclusive"),
        ({"A": "education"}, {"undetected": "invalid"}, "inconclusive"),
    ],
)
def test_categories_do_not_change_verdict_and_survive_missing_engine_results(
    monkeypatch, categories, stats, verdict
):
    monkeypatch.setenv("VT_API_KEY", "test")
    with patch(
        "analysis.url_inspection.requests.get", return_value=vt_response(categories, stats)
    ) as get:
        result = analyze_url("https://example.org/")
    assert get.call_count == 1
    assert result["verdict"] == verdict
    assert result["details"]["providers"]["virustotal"]["categories"] == categories


@pytest.mark.parametrize(
    "category_status,categories",
    [("ok", {"A": "education"}), ("quota_exceeded", {}), ("timeout", {})],
)
def test_polling_enriches_category_once_without_replacing_final_statistics(
    category_status, categories
):
    details = {
        "module": "url",
        "local_assessment": {"malicious": False, "suspicious": False, "incomplete": False},
        "iocs": {"urls": ["https://example.org/"]},
        "providers": {"virustotal": {"status": "queued", "analysis_id": "url-category-123"}},
    }
    with (
        patch(
            "analysis.scanner.fetch_analysis",
            return_value={"status": "ok", "stats": {"malicious": 2, "suspicious": 0}},
        ),
        patch(
            "analysis.url_inspection.lookup_url",
            return_value={
                "status": category_status,
                "categories": categories,
                "stats": {"malicious": 0},
            },
        ) as lookup,
    ):
        result = poll_virustotal(details)
    lookup.assert_called_once_with("https://example.org/", scan_consent=False)
    assert result["verdict"] == "malicious"
    vt = result["details"]["providers"]["virustotal"]
    assert vt["stats"]["malicious"] == 2 and vt["categories"] == categories


def test_category_is_not_fetched_again_while_analysis_is_pending():
    details = {
        "module": "url",
        "local_assessment": {"malicious": False, "suspicious": False, "incomplete": False},
        "iocs": {"urls": ["https://example.org/"]},
        "providers": {"virustotal": {"analysis_id": "url-123"}},
    }
    with (
        patch("analysis.scanner.fetch_analysis", return_value={"status": "in-progress"}),
        patch("analysis.url_inspection.lookup_url") as lookup,
    ):
        poll_virustotal(details)
    lookup.assert_not_called()


@pytest.mark.django_db
def test_owner_sees_fixed_category_labels_and_admin_sees_escaped_sources(client):
    owner = get_user_model().objects.create_user(username="category-owner")
    item = Submission.objects.create(
        owner=owner,
        kind="url",
        status="done",
        verdict="no_indicators",
        filename="URL · example.org",
        target_url="https://example.org/?token=secret",
        details={
            "providers": {
                "virustotal": {
                    "status": "ok",
                    "stats": {"undetected": 60},
                    "categories": {
                        "Service A": "education",
                        "<script>Service B</script>": "https://secret.example",
                    },
                }
            },
        },
    )
    client.force_login(owner)
    url = f"/results/{item.pk}/"
    payload = client.get(url + "?format=json").json()
    assert payload["url_category"] == {"status": "available", "labels": ["Educación"]}
    assert "details" not in payload and "secret" not in json.dumps(payload)
    html = client.get(url).content.decode()
    assert "Educación" in html and "Service A" not in html and "secret.example" not in html
    session = client.session
    session["roles"] = ["vigia-admin"]
    session.save()
    html = client.get(url).content.decode()
    assert "Service A" in html and "&lt;script&gt;Service B" in html
    assert "<script>Service B" not in html


def test_pending_and_legacy_reports_have_no_invented_category():
    assert url_categorization(SimpleNamespace(kind="url", status="waiting_vt")) == {
        "status": "pending",
        "labels": [],
    }
    assert url_categorization(SimpleNamespace(kind="url", status="done", details={})) == {
        "status": "unavailable",
        "labels": [],
    }
