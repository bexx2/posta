"""Kayıt, e-posta doğrulama, giriş. Hata mesajları kullanıcı sayımına (enumeration) izin vermez."""
from django.conf import settings
from django.contrib.auth import authenticate
from django.contrib.auth.password_validation import validate_password
from django.core import signing
from django.core.exceptions import ValidationError
from django.core.mail import send_mail
from django.db import transaction
from django.utils import timezone

from .models import TermsAcceptance, User

VERIFY_SALT = "posta.verify-email"
VERIFY_MAX_AGE = 3 * 24 * 3600
TERMS_VERSION = "2026-10-08"          # == scripts/build-legal.py VERSION (test denetler); sürümlü sayfa: /terms/<VERSION>
RESET_SALT = "posta.reset-password"
RESET_MAX_AGE = 3600
REQUIRED_DOCS = ("terms", "aup")            # onay kutusu yalnız bunlar için (avukat 2026-10-08 §2.2)
SHOWN_DOCS = ("privacy_shown",)              # aydınlatma onaylanmaz, gösterildiği kaydedilir (KVKK m.10 ispat)


class RegistrationError(Exception):
    def __init__(self, code, message):
        super().__init__(message)
        self.code, self.message = code, message


def make_verify_token(user: User) -> str:
    return signing.dumps({"uid": user.pk, "em": user.email}, salt=VERIFY_SALT)


def read_verify_token(token: str):
    try:
        data = signing.loads(token, salt=VERIFY_SALT, max_age=VERIFY_MAX_AGE)
    except signing.BadSignature:
        return None
    return User.objects.filter(pk=data.get("uid"), email=data.get("em")).first()


def send_verification(user: User) -> None:
    base = settings.PUBLIC_BASE_URL
    link = f"{base}/app/verify/{make_verify_token(user)}/"
    send_mail(
        "Confirm your email for posta",
        f"Open this link within 3 days to confirm your email address:\n\n{link}\n\n"
        f"You accepted our Terms of Service and Acceptable Use Policy, version {TERMS_VERSION}:\n"
        f"{base}/terms/{TERMS_VERSION}\n{base}/aup/{TERMS_VERSION}\n"
        f"Privacy notice: {base}/privacy\n"
        f"Türkçe (esas metin): {base}/tr/terms/{TERMS_VERSION}\n\n"
        "If you did not sign up, ignore this message.",
        settings.DEFAULT_FROM_EMAIL, [user.email], fail_silently=False,
    )


@transaction.atomic
def register(email: str, password: str, accepted_version: str):
    email = (email or "").strip().lower()
    if not email or "@" not in email or len(email) > 254:
        raise RegistrationError("invalid_email", "Enter a valid email address.")
    if accepted_version != TERMS_VERSION:
        raise RegistrationError("terms_required", "You must accept the current terms of service and acceptable use policy.")
    try:
        validate_password(password)
    except ValidationError as e:
        raise RegistrationError("weak_password", " ".join(e.messages))
    existing = User.objects.filter(email=email).first()
    if existing is not None:
        if existing.is_email_verified:
            return None  # çağıran taraf aynı yanıtı verir (kullanıcı sayımı yok); mevcut hesaba mail GİTMEZ
        # Doğrulanmamış kayıt (bağlantı süresi dolmuş olabilir): parola yenilenir, kabul yeniden kaydedilir, doğrulama maili
        # yeniden gider. Adresin sahibi doğrulayınca hesap kendi parolasıyla açılır; eski (yabancı) parola geçersizleşir.
        existing.set_password(password)
        existing.save(update_fields=["password"])
        _record_acceptance(existing, accepted_version)
        return existing
    user = User.objects.create_user(email=email, password=password)
    _record_acceptance(user, accepted_version)
    return user


def _record_acceptance(user: User, version: str) -> None:
    TermsAcceptance.objects.filter(user=user).delete()
    TermsAcceptance.objects.bulk_create([TermsAcceptance(user=user, document=d, version=version) for d in REQUIRED_DOCS + SHOWN_DOCS])


def confirm_email(token: str):
    user = read_verify_token(token)
    if not user:
        return None
    if not user.email_verified_at:
        user.email_verified_at = timezone.now()
        user.save(update_fields=["email_verified_at"])
    return user


def login_user(request, email: str, password: str):
    user = authenticate(request, username=(email or "").strip().lower(), password=password)
    if not user or not user.is_active:
        raise RegistrationError("invalid_credentials", "Email or password is incorrect.")
    if not user.is_email_verified:
        raise RegistrationError("email_not_verified", "Confirm your email address first.")
    return user


# ---------- parola sıfırlama ----------
def make_reset_token(user: User) -> str:
    # parola karmasının bir parçası belirtece girer: parola değişince belirteç ölür (tek kullanımlık)
    return signing.dumps({"uid": user.pk, "pw": user.password[-12:]}, salt=RESET_SALT)


def read_reset_token(token: str):
    try:
        data = signing.loads(token, salt=RESET_SALT, max_age=RESET_MAX_AGE)
    except signing.BadSignature:
        return None
    user = User.objects.filter(pk=data.get("uid"), is_active=True).first()
    return user if user and user.password[-12:] == data.get("pw") else None


def request_password_reset(email: str) -> None:
    """Hesap varsa mail gider; yoksa sessizce çıkar (çağıran her durumda aynı yanıtı verir)."""
    user = User.objects.filter(email=(email or "").strip().lower(), is_active=True).first()
    if not user or not user.is_email_verified:
        return
    link = f"{settings.PUBLIC_BASE_URL}/app/reset/{make_reset_token(user)}/"
    send_mail(
        "Reset your posta password",
        f"Open this link within 1 hour to choose a new password:\n\n{link}\n\n"
        "If you did not ask for this, ignore this message; your password stays the same.",
        settings.DEFAULT_FROM_EMAIL, [user.email], fail_silently=False,
    )


def reset_password(token: str, password: str):
    user = read_reset_token(token)
    if not user:
        raise RegistrationError("invalid_token", "This reset link is invalid or has expired.")
    try:
        validate_password(password, user)
    except ValidationError as e:
        raise RegistrationError("weak_password", " ".join(e.messages))
    user.set_password(password)
    user.save(update_fields=["password"])
    return user
