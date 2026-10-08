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


# ---------- Pro plan satın alma (iyzico) ----------
PRO_SLUG = "pro"
PRO_DAYS = 365


def pro_plan():
    from .models import Plan
    return Plan.objects.filter(slug=PRO_SLUG, price_usd_yearly__isnull=False).first()


def activate_pro(order):
    """Ödenmiş siparişi uygular: plan=pro, süre +365 gün (aktif Pro varsa bitişine eklenir), Mailcow alan adı limitleri yükselir. Idempotent çağıran: Order.status."""
    from datetime import timedelta
    from django.utils import timezone
    m = membership(order.user)
    base = m.paid_until if (m.paid_until and m.paid_until > timezone.now() and m.plan_id == order.plan_id) else timezone.now()
    m.plan, m.paid_until = order.plan, base + timedelta(days=PRO_DAYS)
    m.save(update_fields=["plan", "paid_until"])
    errs = []
    for d in Domain.objects.filter(owner=order.user).exclude(status=Domain.SUSPENDED):
        try:
            get_backend().set_domain_limits(d.name, order.plan.max_mailboxes_per_domain, order.plan.mailbox_quota_mb)
        except Exception as e:      # ödeme alındı; limit yükseltme hatası siparişi bozmaz, operatöre bildirilir
            errs.append(f"{d.name}: {e}")
    for mb in Mailbox.objects.filter(domain__owner=order.user, plan_suspended_at__isnull=False):
        try:
            get_backend().set_suspended(mb.address, False)
            mb.status, mb.plan_suspended_at = Mailbox.ACTIVE, None
            mb.save(update_fields=["status", "plan_suspended_at"])
        except Exception as e:
            errs.append(f"{mb.address}: {e}")
    m.lifecycle = {}
    m.save(update_fields=["lifecycle"])
    audit(order.user, "plan.pro_activated", "order", str(order.id), until=m.paid_until.isoformat(), errors=errs)
    return errs


def finish_order(order, detail):
    """iyzico retrieve cevabını siparişe uygular (çağıran transaction.atomic + select_for_update ile kilitler). Dönüş: True=ödendi.
    paymentStatus SUCCESS ama imza/tutar/para birimi/sipariş tutmuyorsa FAILED DEĞİL **review**: para alınmış olabilir, insan bakar (operatöre alarm)."""
    from decimal import Decimal, InvalidOperation
    from . import iyzico
    status = str(detail.get("paymentStatus") or "")
    order.iyzico_payment_id = str(detail.get("paymentId") or "")[:64]
    try:
        consistent = (iyzico.verify_retrieve(detail) and detail.get("currency") == order.currency
                      and detail.get("conversationId") == order.conversation_id and Decimal(str(detail.get("paidPrice"))) == order.amount_usd)
    except (InvalidOperation, TypeError):
        consistent = False
    if status == "SUCCESS" and consistent:
        order.status, order.paid_at = order.PAID, timezone.now()
        order.save(update_fields=["status", "iyzico_payment_id", "paid_at"])
        return True
    if status == "SUCCESS":
        order.status, order.error = order.REVIEW, "SUCCESS but verification mismatch"
    else:
        order.status, order.error = order.FAILED, str(detail.get("errorMessage") or status or "payment not confirmed")[:256]
    order.save(update_fields=["status", "iyzico_payment_id", "error"])
    return False


def notify_operator(subject, body):
    from .signals import _notify
    _notify(subject, body)


def send_receipt(order):
    """Ödeme sonrası makbuz/sözleşme örneği (avukat taslağı 3.5): kalıcı veri saklayıcısı olarak e-postanın İÇİNE yazılır."""
    from datetime import timedelta
    from django.core.mail import send_mail
    from django.conf import settings as st
    until = order.user.membership.paid_until
    d14 = (order.paid_at + timedelta(days=14)).strftime("%Y-%m-%d")
    body = f"""Thank you. Your posta Pro plan is active.
- Plan: Pro - 1 domain, up to 10 mailboxes (500 MB and 50 outgoing messages a day each), 1 year
- Start: {order.paid_at:%Y-%m-%d} - Ends: {until:%Y-%m-%d} - No automatic renewal
- Paid: USD {order.amount_usd} in total (no tax added on top), by card via iyzico - Order #{order.id}
- Seller: HEYVANKA YAZILIM, Demirtas Mah. 77034 Sk. No: 11/A, Toroslar / Mersin, Turkiye - +90 850 840 43 37 - merhaba@preved.co
- You accepted: Sales terms {order.sales_version} https://posta.preved.co/sales/{order.sales_version} and Terms {order.terms_version} https://posta.preved.co/terms/{order.terms_version}
- Refund: full refund if you ask within 14 days (until {d14}) - reply to this email. Consumers can cancel any time after that and get back the unused part.
- Complaints and disputes: merhaba@preved.co; consumers may also apply to the consumer arbitration committee or, after mediation, the consumer court (Turkiye).
We will email your invoice within 7 days.

-----

Tesekkurler. posta Pro planin aktif.
- Plan: Pro - 1 alan adi, en fazla 10 posta kutusu (her biri 500 MB ve gunde 50 giden ileti), 1 yil
- Baslangic: {order.paid_at:%Y-%m-%d} - Bitis: {until:%Y-%m-%d} - Otomatik yenileme yok
- Odenen: toplam {order.amount_usd} ABD dolari (uzerine vergi eklenmedi), iyzico ile kartla - Siparis no: {order.id}
- Satici: HEYVANKA YAZILIM, Demirtas Mah. 77034 Sk. No: 11/A, Toroslar / Mersin - 0850 840 43 37 - merhaba@preved.co
- Kabul ettigin metinler: Satis kosullari {order.sales_version} https://posta.preved.co/tr/sales/{order.sales_version} ve Kosullar {order.terms_version} https://posta.preved.co/tr/terms/{order.terms_version}
- Iade: 14 gun icinde ({d14} tarihine kadar) istersen paranin tamamini iade ederiz; bu e-postayi yanitla. Tuketiciysen sonrasinda da istedigin an iptal edip kullanilmayan kismi geri alabilirsin.
- Sikayet ve uyusmazlik: merhaba@preved.co; tuketiciysen tuketici hakem heyetine ya da arabuluculuktan sonra tuketici mahkemesine de basvurabilirsin.
Faturani 7 gun icinde e-postayla gonderecegiz.
"""
    send_mail(f"posta Pro: payment received - order #{order.id}", body, st.DEFAULT_FROM_EMAIL, [order.user.email], fail_silently=True)


def downgrade_to_free(user, reason="expired"):
    """Pro bitti/iade: ücretsiz plana indir; fazla kutular (en eski kalır) askıya alınır, geri dönüş mümkün (plan_suspended_at). Silme burada YOK."""
    from .models import Plan
    free = Plan.objects.filter(is_default=True).first()
    m = membership(user)
    m.plan, m.paid_until = free, None
    m.save(update_fields=["plan", "paid_until"])
    keep = None
    errs = []
    for d in Domain.objects.filter(owner=user).exclude(status=Domain.SUSPENDED):
        boxes = list(d.mailboxes.order_by("id"))
        for mb in boxes[free.max_mailboxes_per_domain:]:
            try:
                get_backend().set_suspended(mb.address, True)
            except Exception as e:
                errs.append(f"{mb.address}: {e}")
            mb.status, mb.plan_suspended_at = Mailbox.SUSPENDED, timezone.now()
            mb.save(update_fields=["status", "plan_suspended_at"])
        try:
            get_backend().set_domain_limits(d.name, max(free.max_mailboxes_per_domain, len(boxes)), free.mailbox_quota_mb)
        except Exception as e:
            errs.append(f"{d.name}: {e}")
    audit(user, f"plan.{reason}", "membership", str(m.id), errors=errs)
    return errs
