from unittest.mock import patch

import pytest
from django.contrib.auth import get_user_model
from django.urls import reverse

from analysis.breaches import source_checks


@pytest.mark.parametrize(
    "status,completed,tone",
    [
        ("found", 1, "danger"),
        ("no_records", 1, "success"),
        ("quota_exceeded", 0, "warning"),
        ("timeout", 0, "warning"),
        ("access_denied", 0, "neutral"),
        ("invalid_response", 0, "neutral"),
        ("unavailable", 0, "neutral"),
        ("unknown_status", 0, "neutral"),
    ],
)
def test_only_selected_source_has_an_automatic_outcome(status, completed, tone):
    report = source_checks("xposedornot", {"status": status, "breaches": []})
    rows = {row["id"]: row for row in report["rows"]}
    assert report["completed"] == completed and report["total"] == 5
    assert rows["xposedornot"]["tone"] == tone
    assert rows["hibp"]["state"] == rows["hpi"]["state"] == rows["fsecure"]["state"] == "manual"
    assert rows["malwarebytes"]["state"] == "external_verification"
    assert all(row["tone"] != "success" for key, row in rows.items() if key != "xposedornot")


def test_initial_state_never_claims_a_completed_check_and_hibp_stays_separate():
    initial = source_checks("xposedornot")
    assert initial["completed"] == 0 and not initial["has_result"]
    assert initial["rows"][0]["state"] == "not_checked"
    paid = source_checks("hibp", {"status": "no_records"})
    assert paid["rows"][0]["state"] == "manual"
    assert paid["rows"][1]["state"] == "no_records"
    assert paid["completed"] == 1


@pytest.mark.django_db
def test_lookup_renders_five_source_rows_without_inventing_external_results(client, settings):
    settings.DEBUG = True
    settings.SECURE_SSL_REDIRECT = False
    settings.BREACH_PROVIDER = "xposedornot"
    user = get_user_model().objects.create_user(username="source-table-reader")
    client.force_login(user)
    raw_result = {
        "status": "found",
        "breaches": [{"title": "ExampleIncident", "date": "", "data_classes": []}],
    }
    with (
        patch("analysis.views.lookup_xposedornot", return_value=raw_result) as lookup,
        patch("analysis.views.lookup_account") as paid,
    ):
        response = client.post(
            reverse("breach_lookup"),
            {
                "email": "private@example.org",
                "consent": "on",
                "malwarebytes_status": "no_records",
                "code": "123456",
            },
        )
    assert response.status_code == 200
    lookup.assert_called_once_with("private@example.org")
    paid.assert_not_called()
    html = response.content.decode()
    assert html.count('class="breach-source-row"') == 5
    assert 'data-source="xposedornot" data-check-state="found"' in html
    assert 'data-source="malwarebytes" data-check-state="external_verification"' in html
    assert "1 de 5 con resultado automático" in html
    assert "VIGIA no ha solicitado ni validado un código" in html
    assert "123456" not in html
    assert 'name="code"' not in html
    assert "malwarebytes.com/digital-footprint?" not in html
    assert 'rel="noopener noreferrer"' in html


@pytest.mark.django_db
def test_get_shows_sources_without_sending_queries_or_triggering_verification(client, settings):
    settings.DEBUG = True
    settings.SECURE_SSL_REDIRECT = False
    settings.BREACH_PROVIDER = "xposedornot"
    user = get_user_model().objects.create_user(username="source-table-preview")
    client.force_login(user)
    with (
        patch("analysis.breaches.requests.get") as get,
        patch("analysis.breaches.requests.post") as post,
    ):
        response = client.get(reverse("breach_lookup"))
    assert response.status_code == 200
    get.assert_not_called()
    post.assert_not_called()
    report = response.context["source_checks"]
    assert report["completed"] == 0 and not report["has_result"]
    assert len(report["rows"]) == 5
