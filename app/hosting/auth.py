import hashlib
import hmac
import secrets
from datetime import timedelta

from django.utils import timezone
from rest_framework import authentication, exceptions

from .models import ApiKey

KEY_PREFIX = "pk_live_"


def generate_key():
    """(tam_anahtar, prefix, hash). Tam anahtar yalnız oluşturma yanıtında bir kez gösterilir."""
    prefix = secrets.token_hex(4)                       # 8 hex
    secret = secrets.token_urlsafe(32)
    full = f"{KEY_PREFIX}{prefix}_{secret}"
    return full, prefix, hash_key(full)


def hash_key(full: str) -> str:
    return hashlib.sha256(full.encode()).hexdigest()


class ApiKeyAuthentication(authentication.BaseAuthentication):
    keyword = "Bearer"

    def authenticate_header(self, request):
        # Bu yoksa DRF kimliksiz/geçersiz istekte 403 döner; 401 dönmesi için şart. fail2ban `/v1/* 401` kuralı buna dayanır.
        return 'Bearer realm="posta"'

    def authenticate(self, request):
        h = authentication.get_authorization_header(request).decode("latin-1")
        if not h.startswith(f"{self.keyword} {KEY_PREFIX}"):
            return None                                   # oturum/başka şema denesin
        full = h[len(self.keyword) + 1:].strip()
        try:
            prefix = full[len(KEY_PREFIX):].split("_", 1)[0]
            key = ApiKey.objects.select_related("owner").get(prefix=prefix, revoked_at__isnull=True)
        except (ApiKey.DoesNotExist, IndexError):
            raise exceptions.AuthenticationFailed("Invalid API key.")
        if not hmac.compare_digest(key.key_hash, hash_key(full)):
            raise exceptions.AuthenticationFailed("Invalid API key.")
        user = key.owner
        if not user.is_active or not user.is_email_verified:
            raise exceptions.AuthenticationFailed("Account is not active.")
        now = timezone.now()
        if not key.last_used_at or now - key.last_used_at > timedelta(minutes=1):
            ApiKey.objects.filter(pk=key.pk).update(last_used_at=now)   # her istekte yazma (yük) yok
        return user, key
