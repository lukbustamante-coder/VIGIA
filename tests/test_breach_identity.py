import time
from unittest.mock import patch

import pytest
from django.contrib.auth import get_user_model
from django.urls import reverse

from analysis.models import AuditEvent

pytestmark = pytest.mark.django_db


@pytest.fixture
def account(client, settings):
    settings.SECURE_SSL_REDIRECT = False
    settings.BREACH_PROVIDER = "xposedornot"
    user = get_user_model().objects.create_user(username="identity-reader", email="db@example.org")
    client.force_login(user)
    session = client.session
    session["oidc_email"] = "owner@example.org"
    session.save()
    return client


def test_email_is_prefilled_and_disabled_and_get_cannot_override_it(account):
    with patch("analysis.views.lookup_xposedornot") as lookup:
        result = account.get(reverse("breach_lookup"), {"email": "victim@example.org"})
    assert result.context["form"]["email"].value() == "owner@example.org"
    assert result.context["form"].fields["email"].disabled
    assert "victim@example.org" not in result.content.decode()
    assert "db@example.org" not in result.content.decode()
    lookup.assert_not_called()


@pytest.mark.parametrize("roles", [[], ["vigia-admin"]])
@pytest.mark.parametrize("other", ["victim@example.org", "", "not-an-email"])
def test_forged_post_is_blocked_even_for_admins(account, roles, other):
    session = account.session
    session["roles"] = roles
    session.save()
    with patch("analysis.views.lookup_xposedornot") as lookup:
        result = account.post(reverse("breach_lookup"), {"email": other, "consent": "on"})
    assert result.status_code == 400
    lookup.assert_not_called()
    assert not AuditEvent.objects.filter(action="breach_lookup_xon").exists()


def test_disabled_field_need_not_be_submitted_and_only_sso_address_is_sent(account):
    with patch(
        "analysis.views.lookup_xposedornot", return_value={"status": "no_records"}
    ) as lookup:
        result = account.post(reverse("breach_lookup"), {"consent": "on"})
    assert result.status_code == 200
    lookup.assert_called_once_with("owner@example.org")


@pytest.mark.parametrize("email", [None, "", "bad", ["owner@example.org"]])
def test_missing_or_invalid_session_address_blocks_queries_without_db_fallback(account, email):
    session = account.session
    session["oidc_email"] = email
    session.save()
    with patch("analysis.views.lookup_xposedornot") as lookup:
        page = account.get(reverse("breach_lookup"))
        result = account.post(
            reverse("breach_lookup"), {"email": "db@example.org", "consent": "on"}
        )
    assert "No recibimos un correo verificado" in page.content.decode()
    assert 'name="email"' not in page.content.decode()
    assert result.status_code == 400
    lookup.assert_not_called()


@pytest.mark.parametrize(
    "email,verified,expected",
    [
        ("owner@example.org", True, "owner@example.org"),
        ("owner@example.org", False, ""),
        ("owner@example.org", None, ""),
        ("owner@example.org", "true", ""),
        ("bad", True, ""),
        (["owner@example.org"], True, ""),
        (None, True, ""),
    ],
)
def test_login_binds_only_verified_claim_and_replaces_stale_address(
    client, settings, email, verified, expected
):
    settings.SECURE_SSL_REDIRECT = False
    settings.OIDC_ISSUER = "https://sso.example.org/realms/company"
    settings.OIDC_CLIENT_ID = "vigia"
    claims = {
        "iss": settings.OIDC_ISSUER,
        "sub": "email-owner",
        "exp": int(time.time()) + 300,
        "email": email,
        "email_verified": verified,
        "preferred_username": "untrusted-fallback@example.org",
    }
    session = client.session
    session["oidc_email"] = "stale@example.org"
    session.save()
    with patch("analysis.auth.oidc_client") as provider:
        provider.return_value.authorize_access_token.return_value = {"userinfo": claims}
        result = client.get(reverse("callback"))
    assert result.status_code == 302
    assert client.session["oidc_email"] == expected
