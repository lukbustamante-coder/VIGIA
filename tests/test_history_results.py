from html.parser import HTMLParser

import pytest
from django.contrib.auth import get_user_model
from django.urls import reverse

from analysis.models import Submission


class HistoryLinks(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links = {}
        self.active = None
        self.text = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "a" and "history-result" in attrs.get("class", "").split():
            self.active = {"href": attrs["href"], "class": attrs["class"], "text": ""}

    def handle_endtag(self, tag):
        if tag == "a" and self.active:
            self.links[self.active["href"]] = self.active
            self.active = None

    def handle_data(self, value):
        self.text.append(value)
        if self.active:
            self.active["text"] += value


@pytest.mark.parametrize(
    "status,verdict,expected",
    [
        ("running", "no_indicators", "pending"),
        ("waiting_vt", "no_indicators", "pending"),
        ("failed", "pending", "inconclusive"),
        ("failed", "no_indicators", "inconclusive"),
        ("failed", "malicious", "malicious"),
        ("failed", "suspicious", "suspicious"),
        ("done", "unknown", "inconclusive"),
    ],
)
def test_history_never_shows_a_clean_result_before_completion(status, verdict, expected):
    badge = Submission(status=status, verdict=verdict).result_badge
    assert badge["tone"] == expected


@pytest.mark.django_db
@pytest.mark.parametrize(
    "module,route", [("eml", "email_analysis"), ("file", "file_analysis"), ("url", "url_analysis")]
)
def test_history_has_translated_states_and_verdict_links_to_owned_details(client, module, route):
    owner = get_user_model().objects.create_user(username="history-owner")
    client.force_login(owner)
    cases = [
        ("done", "malicious", "Malicioso", "malicious"),
        ("done", "suspicious", "Sospechoso", "suspicious"),
        ("done", "no_indicators", "Sin indicios detectados", "no_indicators"),
        ("done", "inconclusive", "No concluyente", "inconclusive"),
        ("queued", "pending", "Pendiente", "pending"),
        ("running", "pending", "Pendiente", "pending"),
        ("waiting_vt", "pending", "Pendiente", "pending"),
        ("polling_vt", "pending", "Pendiente", "pending"),
        ("failed", "pending", "No concluyente", "inconclusive"),
    ]
    items = [
        Submission.objects.create(
            owner=owner, kind=module, filename=f"example-{index}", status=status, verdict=verdict
        )
        for index, (status, verdict, _label, _tone) in enumerate(cases)
    ]
    parser = HistoryLinks()
    response = client.get(reverse(route))
    assert response.status_code == 200
    parser.feed(response.content.decode())
    assert len(parser.links) == len(cases)
    visible = " ".join(parser.text)
    for translation in (
        "Listo",
        "En cola",
        "Analizando",
        "Esperando a VirusTotal",
        "Consultando VirusTotal",
        "No completado",
    ):
        assert translation in visible
    assert "Ver resultado" not in visible
    assert "done" not in visible
    for item, (_status, _verdict, label, tone) in zip(items, cases):
        target = reverse("result", args=[item.pk])
        assert label in parser.links[target]["text"]
        assert f"history-result--{tone}" in parser.links[target]["class"].split()
        assert client.get(target).status_code == 200
