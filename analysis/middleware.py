class SecurityHeadersMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        response["Content-Security-Policy"] = (
            "default-src 'none'; style-src 'self'; img-src 'self'; "
            "form-action 'self'; base-uri 'none'; frame-ancestors 'none'"
        )
        response["X-Frame-Options"] = "DENY"
        response["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response["Cache-Control"] = "no-store"
        return response
