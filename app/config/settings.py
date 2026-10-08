"""posta — Django settings. Secrets come from a .env file (never commit it)."""
import os
from pathlib import Path

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR.parent / ".env")


def env(name, default=""):
    return os.environ.get(name, default)


SECRET_KEY = env("DJANGO_SECRET_KEY")
if not SECRET_KEY:
    if env("TEST_SQLITE") == "1":
        SECRET_KEY = "insecure-key-for-tests-only"
    else:
        raise RuntimeError("DJANGO_SECRET_KEY is not set (see .env.example)")
DEBUG = env("DJANGO_DEBUG", "0") == "1"
ALLOWED_HOSTS = [h.strip() for h in env("DJANGO_ALLOWED_HOSTS", "localhost,127.0.0.1").split(",") if h.strip()]

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "rest_framework",
    "accounts",
    "hosting",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "config.urls"
TEMPLATES = [{
    "BACKEND": "django.template.backends.django.DjangoTemplates",
    "DIRS": [BASE_DIR / "templates"],
    "APP_DIRS": True,
    "OPTIONS": {"context_processors": [
        "django.template.context_processors.request",
        "django.contrib.auth.context_processors.auth",
        "django.contrib.messages.context_processors.messages",
    ]},
}]
WSGI_APPLICATION = "config.wsgi.application"

DATABASES = {"default": {
    "ENGINE": "django.db.backends.postgresql",
    "NAME": env("DB_NAME", "posta"), "USER": env("DB_USER", "posta"), "PASSWORD": env("DB_PASSWORD"),
    "HOST": env("DB_HOST", "127.0.0.1"), "PORT": env("DB_PORT", "5432"),
    "CONN_MAX_AGE": 60,
}}

AUTH_USER_MODEL = "accounts.User"
AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator", "OPTIONS": {"min_length": 10}},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

LANGUAGE_CODE = "en"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True
STATIC_URL = "/app/static/"
STATIC_ROOT = BASE_DIR.parent / "var" / "static"
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

# Caddy arkasında
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
CSRF_TRUSTED_ORIGINS = [env("PUBLIC_BASE_URL", "http://localhost:8000")]
SESSION_COOKIE_SECURE = not DEBUG
CSRF_COOKIE_SECURE = not DEBUG
SESSION_COOKIE_AGE = 7 * 24 * 3600
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = "Lax"
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = "DENY"
LOGIN_URL = "/app/login/"

REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": [
        "hosting.auth.ApiKeyAuthentication",
        "rest_framework.authentication.SessionAuthentication",
    ],
    "DEFAULT_PERMISSION_CLASSES": ["rest_framework.permissions.IsAuthenticated"],
    "DEFAULT_THROTTLE_CLASSES": ["rest_framework.throttling.UserRateThrottle", "rest_framework.throttling.AnonRateThrottle"],
    "DEFAULT_THROTTLE_RATES": {"user": "120/min", "anon": "20/min"},
    "DEFAULT_RENDERER_CLASSES": ["rest_framework.renderers.JSONRenderer"],
    "EXCEPTION_HANDLER": "hosting.api.exception_handler",
}

# E-posta (doğrulama + parola sıfırlama): varsayılan konsol. Canlı: .env'de EMAIL_BACKEND=django.core.mail.backends.smtp.EmailBackend
# + EMAIL_HOST/PORT/HOST_USER/HOST_PASSWORD (noreply kimliği; ana kutulardan AYRI). Port 587 → STARTTLS, 465 → SSL.
EMAIL_BACKEND = env("EMAIL_BACKEND", "django.core.mail.backends.console.EmailBackend")
EMAIL_HOST = env("EMAIL_HOST", "127.0.0.1")
EMAIL_PORT = int(env("EMAIL_PORT", "587"))
EMAIL_HOST_USER = env("EMAIL_HOST_USER", "")
EMAIL_HOST_PASSWORD = env("EMAIL_HOST_PASSWORD", "")
EMAIL_USE_TLS = EMAIL_PORT == 587
EMAIL_USE_SSL = EMAIL_PORT == 465
EMAIL_TIMEOUT = 15
DEFAULT_FROM_EMAIL = env("DEFAULT_FROM_EMAIL", "posta <noreply@example.com>")

# Message-ID alan adı: Django make_msgid socket.getfqdn() kullanır → sunucuda "localhost"
# → rspamd MID_RHS_NOT_FQDN (spam sinyali). FQDN'i sabitle (HeyvAnka'daki fix'in aynısı).
from django.core.mail.utils import DNS_NAME as _DNS_NAME  # noqa: E402
_DNS_NAME._fqdn = "preved.co"
PUBLIC_BASE_URL = env("PUBLIC_BASE_URL", "http://localhost:8000")

# Posta arka ucu: dryrun (varsayılan, hiçbir şey açmaz) | mailcow
MAIL_BACKEND = env("MAIL_BACKEND", "dryrun")
MAILCOW_API_URL = env("MAILCOW_API_URL", "https://127.0.0.1:18443/api/v1")
MAILCOW_API_KEY = env("MAILCOW_API_KEY", "")
# Kendi alan adlarımız müşteri olarak eklenemez
RESERVED_DOMAINS = ["heyvaql.com", "preved.co", "mailcow.local", "localhost"]
# Rezerve kuralının istisnaları (uçtan uca test için kendi alt alan adımız; virgülle). Boş = istisna yok.
RESERVED_DOMAIN_EXCEPTIONS = [d.strip().lower() for d in env("RESERVED_DOMAIN_EXCEPTIONS", "").split(",") if d.strip()]
# Doğrulama için DNS beklentileri
MX_TARGET = env("MX_TARGET", "mail.example.com")
SPF_INCLUDE_IP = env("SPF_INCLUDE_IP", "")          # gerçek çıkış IP'si (spf.posta.preved.co TXT'sinde yaşar)
SPF_INCLUDE = env("SPF_INCLUDE", "spf.posta.preved.co")          # müşteriye verilen: include:… → IP değişince müşteri DNS'i değişmez
VERIFY_TXT_PREFIX = "_posta-verify"

LOGGING = {  # uygulama logu IP/e-posta içermez (KVKK minimizasyon); erişim logu Caddy'de
    "version": 1, "disable_existing_loggers": False,
    "handlers": {"console": {"class": "logging.StreamHandler"}},
    "root": {"handlers": ["console"], "level": "INFO"},
}

# Testler için hızlı yerel DB (üretimde kullanılmaz): TEST_SQLITE=1
if env("TEST_SQLITE") == "1":
    DATABASES = {"default": {"ENGINE": "django.db.backends.sqlite3", "NAME": ":memory:"}}
    PASSWORD_HASHERS = ["django.contrib.auth.hashers.MD5PasswordHasher"]   # yalnız testler: hızlı
    # 2026-10-07 olayı: .env'de MAIL_BACKEND=mailcow iken testler GERÇEK Mailcow'a "acme.dev" yazdı. Testte canlı arka uç ASLA.
    MAIL_BACKEND, MAILCOW_API_KEY = "dryrun", ""
    EMAIL_BACKEND = "django.core.mail.backends.locmem.EmailBackend"
    RESERVED_DOMAIN_EXCEPTIONS = []
