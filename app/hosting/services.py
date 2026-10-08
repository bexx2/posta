"""İş mantığı: limitler, alan adı doğrulama (DNS), kutu açma/silme, denetim kaydı."""
import logging
import re

import dns.exception
import dns.resolver
from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import transaction
from django.utils import timezone

from .backends import get_backend
from .backends.base import BackendError
from .models import ApiKey, AuditLog, Domain, Mailbox, Membership, normalize_domain

log = logging.getLogger(__name__)
LOCAL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9._+-]{0,62}[a-z0-9])?$")
RESERVED_LOCALS = {"postmaster", "abuse", "hostmaster", "webmaster", "root", "admin", "administrator", "noreply", "no-reply", "mailer-daemon"}


class ServiceError(Exception):
    def __init__(self, code, message, http=400):
        super().__init__(message)
        self.code, self.message, self.http = code, message, http


def audit(user, action, object_type, object_ref, **meta):
    AuditLog.objects.create(actor=user, actor_label=getattr(user, "email", "") or "system", action=action,
                            object_type=object_type, object_ref=object_ref, meta=meta)


def membership(user) -> Membership:
    m = getattr(user, "membership", None)
    if not m:
        raise ServiceError("no_membership", "Your account has no plan yet. Contact support.", 403)
    if m.status != Membership.ACTIVE:
        raise ServiceError("account_suspended", "Your account is suspended.", 403)
    return m


# ---------- alan adı ----------
def add_domain(user, raw_name: str) -> Domain:
    plan = membership(user).plan
    try:
        name = normalize_domain(raw_name)
    except ValidationError as e:
        raise ServiceError("invalid_domain", e.messages[0])
    if Domain.objects.filter(owner=user).exclude(status=Domain.SUSPENDED).count() >= plan.max_domains:
        raise ServiceError("plan_limit", f"Your plan allows {plan.max_domains} domain(s).", 403)
    if Domain.objects.filter(name=name).exists():
        raise ServiceError("domain_taken", "This domain is already registered on posta.", 409)
    d = Domain.objects.create(owner=user, name=name)
    audit(user, "domain.add", "domain", name)
    return d


def _resolve(name, rtype):
    r = dns.resolver.Resolver()
    r.lifetime = 5.0
    try:
        return [a.to_text().strip('"') for a in r.resolve(name, rtype)]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout):
        return []


def check_dns(domain: Domain) -> dict:
    """Ayrı ayrı sonuç döner. verified = sahiplik TXT + MX. SPF/DMARC/DKIM bilgilendirici (gönderim itibarı için gerekli)."""
    txt = _resolve(domain.txt_record["name"], "TXT")
    mx = [m.split()[-1].rstrip(".").lower() for m in _resolve(domain.name, "MX")]
    spf = [t for t in _resolve(domain.name, "TXT") if t.lower().startswith("v=spf1")]
    dmarc = [t for t in _resolve(f"_dmarc.{domain.name}", "TXT") if t.lower().startswith("v=dmarc1")]
    dkim = _resolve(f"{domain.dkim_selector}._domainkey.{domain.name}", "TXT") if domain.dkim_txt else []
    return {
        "ownership_txt": domain.txt_record["value"] in txt,
        "mx": settings.MX_TARGET.lower() in mx,
        "spf": any(f"include:{settings.SPF_INCLUDE}" in t.split() or f"ip4:{settings.SPF_INCLUDE_IP}" in t.split() for t in spf),
        "dmarc": bool(dmarc),
        "dkim": bool(dkim),
    }


@transaction.atomic
def verify_domain(user, domain: Domain) -> Domain:
    if domain.owner_id != user.id:
        raise ServiceError("not_found", "Domain not found.", 404)
    res = check_dns(domain)
    domain.last_check, domain.last_check_at = res, timezone.now()
    if res["ownership_txt"] and res["mx"]:
        if domain.status != Domain.SUSPENDED:
            domain.status = Domain.VERIFIED
        if domain.status == Domain.VERIFIED and not domain.verified_at:
            domain.verified_at = timezone.now()
            plan = membership(user).plan
            be = get_backend()
            try:
                be.add_domain(domain.name, plan.max_mailboxes_per_domain, plan.mailbox_quota_mb)
                domain.dkim_selector, domain.dkim_txt = be.dkim(domain.name, domain.dkim_selector)
            except BackendError as e:
                log.error("backend add_domain failed: %s", e)
                raise ServiceError("backend_error", "Could not prepare the domain right now. Try again shortly.", 503)
            audit(user, "domain.verify", "domain", domain.name)
    domain.save()
    return domain


def delete_domain(user, domain: Domain):
    if domain.owner_id != user.id:
        raise ServiceError("not_found", "Domain not found.", 404)
    be = get_backend()
    try:
        for m in domain.mailboxes.all():
            be.delete_mailbox(m.address)
        if domain.verified_at:
            be.delete_domain(domain.name)
    except BackendError as e:
        log.error("backend delete failed: %s", e)
        raise ServiceError("backend_error", "Could not delete right now. Try again shortly.", 503)
    name = domain.name
    domain.delete()
    audit(user, "domain.delete", "domain", name)


# ---------- kutu ----------
@transaction.atomic
def create_mailbox(user, domain: Domain, local_part: str, password: str) -> Mailbox:
    from django.contrib.auth.password_validation import validate_password
    m = membership(user)
    if domain.owner_id != user.id:
        raise ServiceError("not_found", "Domain not found.", 404)
    if domain.status != Domain.VERIFIED:
        raise ServiceError("domain_not_verified", "Verify the domain first.", 403)
    lp = (local_part or "").strip().lower()
    if not LOCAL_RE.match(lp) or ".." in lp or lp in RESERVED_LOCALS:
        raise ServiceError("invalid_local_part", "Choose a different mailbox name.")
    try:
        validate_password(password)
    except ValidationError as e:
        raise ServiceError("weak_password", " ".join(e.messages))
    if domain.mailboxes.count() >= m.plan.max_mailboxes_per_domain:
        raise ServiceError("plan_limit", f"Your plan allows {m.plan.max_mailboxes_per_domain} mailbox(es) per domain.", 403)
    address = f"{lp}@{domain.name}"
    if Mailbox.objects.filter(address=address).exists():
        raise ServiceError("mailbox_exists", "This mailbox already exists.", 409)
    try:
        get_backend().add_mailbox(address, password, m.plan.mailbox_quota_mb, m.plan.daily_send_limit)
    except BackendError as e:
        log.error("backend add_mailbox failed: %s", e)
        raise ServiceError("backend_error", "Could not create the mailbox right now. Try again shortly.", 503)
    mb = Mailbox.objects.create(domain=domain, local_part=lp, address=address, quota_mb=m.plan.mailbox_quota_mb)
    audit(user, "mailbox.create", "mailbox", address)
    return mb


def delete_mailbox(user, mb: Mailbox):
    if mb.domain.owner_id != user.id:
        raise ServiceError("not_found", "Mailbox not found.", 404)
    try:
        get_backend().delete_mailbox(mb.address)
    except BackendError as e:
        log.error("backend delete_mailbox failed: %s", e)
        raise ServiceError("backend_error", "Could not delete right now. Try again shortly.", 503)
    addr = mb.address
    mb.delete()
    audit(user, "mailbox.delete", "mailbox", addr)


# ---------- API anahtarı ----------
def create_api_key(user, name: str, scopes):
    from .auth import generate_key
    membership(user)
    bad = [s for s in scopes if s not in ApiKey.SCOPES]
    if bad or not scopes:
        raise ServiceError("invalid_scopes", f"Scopes must be a non-empty subset of: {', '.join(ApiKey.SCOPES)}")
    if ApiKey.objects.filter(owner=user, revoked_at__isnull=True).count() >= 10:
        raise ServiceError("plan_limit", "You can have at most 10 active API keys.", 403)
    full, prefix, h = generate_key()
    key = ApiKey.objects.create(owner=user, name=(name or "key")[:64], prefix=prefix, key_hash=h, scopes=",".join(scopes))
    audit(user, "apikey.create", "apikey", prefix, scopes=list(scopes))
    return key, full


def revoke_api_key(user, key: ApiKey):
    if key.owner_id != user.id:
        raise ServiceError("not_found", "API key not found.", 404)
    key.revoked_at = timezone.now()
    key.save(update_fields=["revoked_at"])
    audit(user, "apikey.revoke", "apikey", key.prefix)


# ---------- ücretli talep ----------
def request_upgrade(user, kind: str, quantity, note: str = ""):
    from .models import UpgradeRequest
    membership(user)
    if kind not in (UpgradeRequest.MAILBOXES, UpgradeRequest.DOMAINS):
        raise ServiceError("invalid_request", "Choose what you need more of.")
    try:
        qty = int(quantity)
    except (TypeError, ValueError):
        qty = 0
    if not 1 <= qty <= 100:
        raise ServiceError("invalid_quantity", "Enter a number between 1 and 100.")
    if UpgradeRequest.objects.filter(user=user, status=UpgradeRequest.OPEN).count() >= 3:
        raise ServiceError("too_many_requests", "You already have open requests. We will reply to them first.", 429)
    req = UpgradeRequest.objects.create(user=user, kind=kind, quantity=qty, note=(note or "").strip()[:500])
    audit(user, "upgrade.request", "upgrade", str(req.pk), kind=kind, quantity=qty)
    return req
