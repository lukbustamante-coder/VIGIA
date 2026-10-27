import pytest
from django.contrib.auth import get_user_model
from django.core.files.uploadedfile import SimpleUploadedFile
from django.urls import reverse

from analysis.models import Submission

pytestmark = pytest.mark.django_db


@pytest.mark.parametrize("module,url_name", [("eml", "email_analysis"), ("file", "file_analysis")])
@pytest.mark.parametrize("admin", [False, True])
def test_module_history_preserves_owner_and_module_boundaries(
    client, settings, module, url_name, admin
):
    settings.OIDC_ADMIN_ROLE = "vigia-admin"
    owner = get_user_model().objects.create_user(username="owner")
    other = get_user_model().objects.create_user(username="other")
    items = {
        (user.username, kind): Submission.objects.create(
            owner=user,
            kind=kind,
            filename=f"{user.username}-{kind}.{'eml' if kind == 'eml' else 'txt'}",
        )
        for user in (owner, other)
        for kind in ("eml", "file")
    }
    client.force_login(owner)
    session = client.session
    session["roles"] = ["vigia-admin"] if admin else []
    session.save()
    response = client.get(reverse(url_name))
    assert response.status_code == 200
    assert set(response.context["submissions"]) == {
        item
        for (username, kind), item in items.items()
        if kind == module and (admin or username == "owner")
    }
    form = response.context["form"]
    assert form.fields["kind"].widget.is_hidden
    assert form.initial["kind"] == module
    accept = form.fields["file"].widget.attrs["accept"].split(",")
    assert (".eml" in accept) == (module == "eml")
    assert (".pdf" in accept) == (module == "file")
    assert b'aria-current="page"' in response.content
    assert b"IOC" not in response.content


def test_result_returns_to_its_module(client):
    owner = get_user_model().objects.create_user(username="owner")
    client.force_login(owner)
    for kind, route in [("eml", "email_analysis"), ("file", "file_analysis")]:
        item = Submission.objects.create(owner=owner, kind=kind, filename="sample")
        response = client.get(reverse("result", args=[item.id]))
        assert response.context["module"] == kind
        assert f'class="back-link" href="{reverse(route)}"' in response.content.decode()


def test_module_selection_does_not_bypass_server_format_validation(client):
    owner = get_user_model().objects.create_user(username="owner")
    client.force_login(owner)
    response = client.post(
        reverse("upload"),
        {
            "kind": "file",
            "file": SimpleUploadedFile("mail.eml", b"From: sender@example.org\n\nNotice"),
        },
    )
    assert response.status_code == 400
    assert response.context["module"] == "file"
    assert Submission.objects.count() == 0
