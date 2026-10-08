import re
import secrets

import idna
from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models
from django.utils import timezone

LABEL_RE = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")


def normalize_domain(raw: str) -> str:
    """Küçük harf + IDNA (punycode). Geçersizse ValidationError."""
    d = (raw or "").strip().lower().rstrip(".")
    if not d or len(d) > 253 or "@" in d or "/" in d or " " in d:
        raise ValidationError("Enter a domain name such as example.com.")
    try:
        d = idna.encode(d, uts46=True).decode("ascii")
    except idna.IDNAError:
        raise ValidationError("This domain name is not valid.")
    labels = d.split(".")
    if len(labels) < 2 or not all(LABEL_RE.match(l) for l in labels) or labels[-1].isdigit():
        raise ValidationError("Enter a domain name such as example.com.")
    if d not in settings.RESERVED_DOMAIN_EXCEPTIONS and any(d == r or d.endswith("." + r) for r in settings.RESERVED_DOMAINS):
        raise ValidationError("This domain is operated by posta itself and cannot be added as a customer domain. Use a domain you own that is not already hosted here.")
    return d


class Plan(models.Model):
    slug = models.SlugField(unique=True)
    name = models.CharField(max_length=64)
    max_domains = models.PositiveIntegerField()
    max_mailboxes_per_domain = models.PositiveIntegerField()
    mailbox_quota_mb = models.PositiveIntegerField()
    daily_send_limit = models.PositiveIntegerField()
    price_try_monthly = models.PositiveIntegerField(null=True, blank=True)  # None = ücretsiz
    is_default = models.BooleanField(default=False)

    def __str__(self):
        return self.slug


class Membership(models.Model):
    ACTIVE, SUSPENDED = "active", "suspended"
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="membership")
    plan = models.ForeignKey(Plan, on_delete=models.PROTECT)
    status = models.CharField(max_length=12, default=ACTIVE, choices=[(ACTIVE, "active"), (SUSPENDED, "suspended")])
    since = models.DateTimeField(default=timezone.now)


class Domain(models.Model):
    PENDING, VERIFIED, SUSPENDED = "pending", "verified", "suspended"
    owner = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="domains")
    name = models.CharField(max_length=253, unique=True)
    status = models.CharField(max_length=12, default=PENDING,
                              choices=[(PENDING, "pending"), (VERIFIED, "verified"), (SUSPENDED, "suspended")])
    verification_token = models.CharField(max_length=64, blank=True, editable=False)
    verified_at = models.DateTimeField(null=True, blank=True)
    last_check_at = models.DateTimeField(null=True, blank=True)
    last_check = models.JSONField(default=dict, blank=True)
    dkim_selector = models.CharField(max_length=32, default="posta")
    dkim_txt = models.TextField(blank=True)
    created_at = models.DateTimeField(default=timezone.now)

    def save(self, *a, **kw):
        if not self.verification_token:
            self.verification_token = secrets.token_hex(16)
        super().save(*a, **kw)

    @property
    def txt_record(self):
        return {"name": f"{settings.VERIFY_TXT_PREFIX}.{self.name}", "type": "TXT", "value": f"posta-verify={self.verification_token}"}


class Mailbox(models.Model):
    ACTIVE, SUSPENDED = "active", "suspended"
    domain = models.ForeignKey(Domain, on_delete=models.CASCADE, related_name="mailboxes")
    local_part = models.CharField(max_length=64)
    address = models.CharField(max_length=320, unique=True)
    quota_mb = models.PositiveIntegerField()
    status = models.CharField(max_length=12, default=ACTIVE, choices=[(ACTIVE, "active"), (SUSPENDED, "suspended")])
    created_at = models.DateTimeField(default=timezone.now)


class ApiKey(models.Model):
    SCOPES = ("domains:read", "domains:write", "mailboxes:read", "mailboxes:write")
    owner = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="api_keys")
    name = models.CharField(max_length=64)
    prefix = models.CharField(max_length=8, unique=True)
    key_hash = models.CharField(max_length=64)          # sha256(tam anahtar); anahtarın kendisi ASLA saklanmaz
    scopes = models.CharField(max_length=200)
    created_at = models.DateTimeField(default=timezone.now)
    last_used_at = models.DateTimeField(null=True, blank=True)
    revoked_at = models.DateTimeField(null=True, blank=True)

    def has_scope(self, scope: str) -> bool:
        return scope in self.scopes.split(",")


class AuditLog(models.Model):
    """Kim ne zaman ne yaptı. IP yok; makam talebi/uyum için eylem kaydı."""
    actor = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL, related_name="+")
    actor_label = models.CharField(max_length=254, blank=True)   # kullanıcı silinse de eylem okunur kalır
    action = models.CharField(max_length=48, db_index=True)
    object_type = models.CharField(max_length=24)
    object_ref = models.CharField(max_length=320)
    meta = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(default=timezone.now, db_index=True)


class UpgradeRequest(models.Model):
    """Ücretsiz planın ötesi (fazla kutu/alan adı) için talep. Ödeme alınmaz: fiyat müşteriye yazılı bildirilir, onay sonrası açılır."""
    MAILBOXES, DOMAINS = "mailboxes", "domains"
    OPEN, ANSWERED, CLOSED = "open", "answered", "closed"
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="upgrade_requests")
    kind = models.CharField(max_length=12, choices=[(MAILBOXES, "mailboxes"), (DOMAINS, "domains")])
    quantity = models.PositiveIntegerField()
    note = models.CharField(max_length=500, blank=True)
    status = models.CharField(max_length=10, default=OPEN, choices=[(OPEN, "open"), (ANSWERED, "answered"), (CLOSED, "closed")])
    created_at = models.DateTimeField(default=timezone.now)
