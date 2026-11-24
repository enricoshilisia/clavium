"""
Django settings for clavium_control — the Clavium control plane.

This process never sees a master password or a decrypted vault. It
authenticates accounts and devices, and stores/moves encrypted blobs it
cannot itself open. See PLAN.md §"Security model" for why that boundary is
the whole point.
"""

import os
from pathlib import Path

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")

SECRET_KEY = os.environ["DJANGO_SECRET_KEY"]
DEBUG = os.environ.get("DJANGO_DEBUG", "false").lower() == "true"
ALLOWED_HOSTS = [h for h in os.environ.get("DJANGO_ALLOWED_HOSTS", "").split(",") if h] or ["localhost", "127.0.0.1"]
CSRF_TRUSTED_ORIGINS = [o for o in os.environ.get("DJANGO_CSRF_TRUSTED_ORIGINS", "").split(",") if o]

# Caddy terminates TLS and proxies plain HTTP to gunicorn — without this,
# Django would think every request arrived over plain HTTP and mark
# cookies accordingly.
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
SECURE_SSL_REDIRECT = not DEBUG
SESSION_COOKIE_SECURE = not DEBUG
CSRF_COOKIE_SECURE = not DEBUG
SECURE_HSTS_SECONDS = 2592000 if not DEBUG else 0  # 30 days

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "corsheaders",
    "rest_framework",
    "accounts",
    "orgs",
    "vaults",
    "sync",
    "scim",
    "console",
    "link",
    "entra",
    "teams",
    "shares",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "corsheaders.middleware.CorsMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

# This API authenticates with a per-device bearer token, never a cookie —
# CORS's usual job (stopping another site's browser-side script from
# riding a signed-in session) doesn't apply the same way here, since a
# malicious page can't produce a valid device token just by getting a
# request to fire. Opened wide so the desktop app's webview (whose origin
# is tauri://localhost or similar, not this API's own) can call it.
CORS_ALLOW_ALL_ORIGINS = True

ROOT_URLCONF = "clavium_control.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "clavium_control.wsgi.application"

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": os.environ.get("POSTGRES_DB", "clavium"),
        "USER": os.environ.get("POSTGRES_USER", "clavium"),
        "PASSWORD": os.environ["POSTGRES_PASSWORD"],
        "HOST": os.environ.get("POSTGRES_HOST", "127.0.0.1"),
        "PORT": os.environ.get("POSTGRES_PORT", "5544"),
    }
}

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

AUTH_USER_MODEL = "accounts.Account"

# Argon2 first: the same KDF family the vault's own security core uses
# (RFC 9106), and the stronger default against an offline attacker if this
# database were ever to leak — Django falls back down the list for any
# password hashed under an older scheme, so this is safe to change later.
PASSWORD_HASHERS = [
    "django.contrib.auth.hashers.Argon2PasswordHasher",
    "django.contrib.auth.hashers.PBKDF2PasswordHasher",
]

AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator", "OPTIONS": {"min_length": 10}},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": [
        "accounts.authentication.DeviceTokenAuthentication",
    ],
    "DEFAULT_PERMISSION_CLASSES": [
        "rest_framework.permissions.IsAuthenticated",
    ],
    # Unauthenticated endpoints (register, sign-in) are limited per client
    # IP to slow down password guessing; everything else per account.
    "DEFAULT_THROTTLE_CLASSES": [
        "rest_framework.throttling.ScopedRateThrottle",
        "rest_framework.throttling.UserRateThrottle",
    ],
    "DEFAULT_THROTTLE_RATES": {
        "auth": os.environ.get("CLAVIUM_AUTH_RATE", "10/min"),
        "user": os.environ.get("CLAVIUM_USER_RATE", "600/min"),
        # Public share-link endpoints, per IP.
        "share": os.environ.get("CLAVIUM_SHARE_RATE", "30/min"),
    },
    # Caddy is the only proxy in front of gunicorn.
    "NUM_PROXIES": 1,
}

# Throttle counters must be shared across gunicorn workers, so a
# per-process memory cache would multiply every limit by the worker count.
CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.db.DatabaseCache",
        "LOCATION": "clavium_cache",
    }
}

LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True

STATIC_URL = "static/"
STATIC_ROOT = BASE_DIR / "staticfiles"

# Email verification ships switched off. See accounts/email_verification.py:
# "off" (default), "optional" (send emails, do not block), "required"
# (unverified accounts cannot sign in a new device or the console).
CLAVIUM_EMAIL_VERIFICATION = os.environ.get("CLAVIUM_EMAIL_VERIFICATION", "off").strip().lower()
# Base for links in emails, e.g. https://clavium-api.example.com. Falls
# back to the address the request came in on.
CLAVIUM_PUBLIC_URL = os.environ.get("CLAVIUM_PUBLIC_URL", "")

# Outgoing mail. With no EMAIL_HOST set, messages are printed to the
# server log instead of sent, which is safe while verification is off.
EMAIL_HOST = os.environ.get("EMAIL_HOST", "")
EMAIL_BACKEND = os.environ.get(
    "EMAIL_BACKEND",
    "django.core.mail.backends.smtp.EmailBackend" if EMAIL_HOST else "django.core.mail.backends.console.EmailBackend",
)
EMAIL_PORT = int(os.environ.get("EMAIL_PORT", "587"))
EMAIL_HOST_USER = os.environ.get("EMAIL_HOST_USER", "")
EMAIL_HOST_PASSWORD = os.environ.get("EMAIL_HOST_PASSWORD", "")
EMAIL_USE_TLS = os.environ.get("EMAIL_USE_TLS", "true").lower() == "true"
EMAIL_USE_SSL = os.environ.get("EMAIL_USE_SSL", "false").lower() == "true"
EMAIL_TIMEOUT = int(os.environ.get("EMAIL_TIMEOUT", "15"))
DEFAULT_FROM_EMAIL = os.environ.get("DEFAULT_FROM_EMAIL", "Clavium <no-reply@clavium.local>")

# Microsoft 365 directory sync. A multi-tenant Entra app registration with
# application permissions User.Read.All and GroupMember.Read.All. See
# docs/microsoft-365.md. Without these the console hides the feature.
CLAVIUM_MS_CLIENT_ID = os.environ.get("CLAVIUM_MS_CLIENT_ID", "")
CLAVIUM_MS_CLIENT_SECRET = os.environ.get("CLAVIUM_MS_CLIENT_SECRET", "")
CLAVIUM_MS_AUTHORITY = os.environ.get("CLAVIUM_MS_AUTHORITY", "https://login.microsoftonline.com").rstrip("/")
CLAVIUM_MS_GRAPH = os.environ.get("CLAVIUM_MS_GRAPH", "https://graph.microsoft.com").rstrip("/")
