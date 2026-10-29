import os
from pathlib import Path

from django.core.exceptions import ImproperlyConfigured

BASE_DIR = Path(__file__).resolve().parent.parent
DEBUG = os.getenv("VIGIA_DEBUG", "false").lower() == "true"
SECRET_KEY = os.getenv("VIGIA_SECRET_KEY", "")
if not SECRET_KEY:
    raise ImproperlyConfigured("Configura VIGIA_SECRET_KEY con un valor aleatorio secreto.")
ALLOWED_HOSTS = os.getenv("VIGIA_ALLOWED_HOSTS", "localhost,127.0.0.1,testserver").split(",")
INSTALLED_APPS = [
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.staticfiles",
    "analysis",
]
MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "whitenoise.middleware.WhiteNoiseMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "analysis.middleware.SecurityHeadersMiddleware",
]
ROOT_URLCONF = "vigia.urls"
TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
            ]
        },
    }
]
WSGI_APPLICATION = "vigia.wsgi.application"
if os.getenv("PGHOST"):
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.postgresql",
            "HOST": os.environ["PGHOST"],
            "NAME": os.environ["PGDATABASE"],
            "USER": os.environ["PGUSER"],
            "PASSWORD": os.environ["PGPASSWORD"],
            "PORT": os.getenv("PGPORT", "5432"),
            "CONN_MAX_AGE": 60,
            "OPTIONS": {"sslmode": os.getenv("PGSSLMODE", "verify-full")},
        }
    }
else:
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.sqlite3",
            "NAME": BASE_DIR / "var" / "db.sqlite3",
            "OPTIONS": {"timeout": 20},
        }
    }
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
LANGUAGE_CODE = "es"
TIME_ZONE = "UTC"
USE_TZ = True
STATIC_URL = "static/"
STATIC_ROOT = BASE_DIR / "staticfiles"
LOGIN_URL = "/auth/login/"
# Cookies are scoped to hosts, not ports: avoid collisions with other Django apps on localhost.
SESSION_COOKIE_NAME = "vigia_sessionid"
CSRF_COOKIE_NAME = "vigia_csrftoken"
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = "Lax"
SESSION_COOKIE_SECURE = not DEBUG
CSRF_COOKIE_SECURE = not DEBUG
SESSION_COOKIE_AGE = 1800
SESSION_EXPIRE_AT_BROWSER_CLOSE = True
SECURE_SSL_REDIRECT = not DEBUG
SECURE_HSTS_SECONDS = 31536000 if not DEBUG else 0
SECURE_HSTS_INCLUDE_SUBDOMAINS = not DEBUG
SECURE_HSTS_PRELOAD = not DEBUG
SECURE_CONTENT_TYPE_NOSNIFF = True
# Form POSTs under no-referrer can carry Origin: null and fail Django's CSRF check.
# Preserve the origin for same-site forms without sending a referrer to other sites.
SECURE_REFERRER_POLICY = "same-origin"
X_FRAME_OPTIONS = "DENY"
CSRF_TRUSTED_ORIGINS = list(filter(None, os.getenv("VIGIA_CSRF_ORIGINS", "").split(",")))
# Enable only behind a trusted reverse proxy that overwrites X-Forwarded-Proto.
if os.getenv("VIGIA_TRUST_PROXY", "false").lower() == "true":
    SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
DATA_UPLOAD_MAX_MEMORY_SIZE = 21 * 1024 * 1024
FILE_UPLOAD_MAX_MEMORY_SIZE = 0
DATA_UPLOAD_MAX_NUMBER_FILES = 1
DATA_UPLOAD_MAX_NUMBER_FIELDS = 5
PRIVATE_STORAGE = Path(os.getenv("VIGIA_STORAGE", str(BASE_DIR / "var" / "uploads")))
MAX_UPLOAD_BYTES = 20 * 1024 * 1024
OIDC_ISSUER = os.getenv("OIDC_ISSUER", "").rstrip("/")
OIDC_CLIENT_ID = os.getenv("OIDC_CLIENT_ID", "vigia")
OIDC_CLIENT_SECRET = os.getenv("OIDC_CLIENT_SECRET", "")
OIDC_REDIRECT_URI = os.getenv("OIDC_REDIRECT_URI", "http://localhost:8000/auth/callback/")
# Empty derives the fixed logout callback from OIDC_REDIRECT_URI's origin.
OIDC_POST_LOGOUT_REDIRECT_URI = os.getenv("OIDC_POST_LOGOUT_REDIRECT_URI", "")
OIDC_ADMIN_ROLE = os.getenv("OIDC_ADMIN_ROLE", "vigia-admin")
VT_API_KEY = os.getenv("VT_API_KEY", "")
VT_ALLOW_SAMPLE_UPLOAD = os.getenv("VT_ALLOW_SAMPLE_UPLOAD", "false").lower() == "true"
VT_ALLOW_URL_SUBMISSION = os.getenv("VT_ALLOW_URL_SUBMISSION", "false").lower() == "true"
VT_ALLOW_EMAIL_RESOURCES = os.getenv("VT_ALLOW_EMAIL_RESOURCES", "false").lower() == "true"
HIBP_ENABLED = os.getenv("HIBP_ENABLED", "false").lower() == "true"
HIBP_API_KEY = os.getenv("HIBP_API_KEY", "").strip()
BREACH_PROVIDER = os.getenv("BREACH_PROVIDER", "hibp" if HIBP_ENABLED else "xposedornot").lower()
AI_API_KEY = os.getenv("AI_API_KEY", "")
AI_MODEL = os.getenv("AI_MODEL", "gpt-4.1-mini")
AI_PROVIDER = os.getenv("AI_PROVIDER", "openai")
AI_ALLOW_HEADER_UPLOAD = os.getenv("AI_ALLOW_HEADER_UPLOAD", "false").lower() == "true"
MXTOOLBOX_ENABLED = os.getenv("MXTOOLBOX_ENABLED", "false").lower() == "true"
MXTOOLBOX_API_KEY = os.getenv("MXTOOLBOX_API_KEY", "")

FILE_UPLOAD_HANDLERS = [
    "analysis.upload_handlers.BoundedUploadHandler",
    "django.core.files.uploadhandler.TemporaryFileUploadHandler",
]
