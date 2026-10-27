import time
from unittest.mock import patch

import pytest
from django.contrib.auth import get_user_model

from analysis.auth import sync_profile

pytestmark = pytest.mark.django_db


@pytest.mark.parametrize(
    "profile,expected",
    [
        ({"given_name": " Ana  María ", "family_name": "Pérez Soto"}, "Ana María Pérez Soto"),
        ({"name": "Ana Pérez"}, "Ana Pérez"),
        ({"preferred_username": "aperez"}, "aperez"),
        ({"name": ["invalid"], "given_name": None, "family_name": 123}, ""),
        ({}, ""),
    ],
)
def test_optional_profile_fields_are_normalized_and_refresh_existing_user(profile, expected):
    user = get_user_model().objects.create_user(username="stable-identity", first_name="Old")
    identity = user.username
    assert sync_profile(user, profile) == expected
    user.refresh_from_db()
    assert user.username == identity
    assert len(user.first_name) <= 150 and len(user.last_name) <= 150
    if not expected:
        assert not user.get_full_name()


def test_profile_is_display_text_and_does_not_grant_roles(client, settings):
    settings.SECURE_SSL_REDIRECT = False
    settings.OIDC_ISSUER = "https://sso.example.org/realms/company"
    settings.OIDC_CLIENT_ID = "vigia"
    claims = {
        "iss": settings.OIDC_ISSUER,
        "sub": "profile-user",
        "exp": int(time.time()) + 300,
        "name": '<script>alert("admin")</script>',
        "preferred_username": "vigia-admin",
    }
    with patch("analysis.auth.oidc_client") as provider:
        provider.return_value.authorize_access_token.return_value = {"userinfo": claims}
        assert client.get("/auth/callback/").status_code == 302
    response = client.get("/")
    assert b"&lt;script&gt;" in response.content
    assert b'<script>alert("admin")</script>' not in response.content
    assert client.session["roles"] == []
    assert not get_user_model().objects.get().is_staff


def test_profile_long_values_fit_user_fields():
    user = get_user_model().objects.create_user(username="long-profile")
    sync_profile(user, {"given_name": "a" * 300, "family_name": "b" * 300})
    user.refresh_from_db()
    assert len(user.first_name) == len(user.last_name) == 150
