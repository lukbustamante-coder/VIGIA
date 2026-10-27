import re
from urllib.parse import urlsplit

from django.conf import settings


class SecurityHeadersMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        form_sources = "'self'"
        try:
            issuer = urlsplit(settings.OIDC_ISSUER)
        except ValueError:
            issuer = urlsplit("")
        # Chromium checks form-action across the POST logout -> Keycloak redirect.
        # Permit only the configured IdP origin, never a wildcard or request parameter.
        if (
            issuer.scheme in ({"http", "https"} if settings.DEBUG else {"https"})
            and issuer.netloc
            and re.fullmatch(r"[A-Za-z0-9.\-:\[\]]+", issuer.netloc)
        ):
            form_sources += f" {issuer.scheme}://{issuer.netloc}"
        response["Content-Security-Policy"] = (
            "default-src 'none'; style-src 'self'; img-src 'self'; script-src 'self'; connect-src 'self'; "
            f"form-action {form_sources}; base-uri 'none'; frame-ancestors 'none'"
        )
        response["X-Frame-Options"] = "DENY"
        response["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response["Cache-Control"] = "no-store"
        return response
