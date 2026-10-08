"""Web paneli (/app/). İş mantığı services'te; burada yalnız form ↔ servis köprüsü. Sunucu tarafı render, JS yok."""
from django.conf import settings
from django.contrib import messages
from django.contrib.auth import login, logout
from django.contrib.auth.decorators import login_required
from django.core.cache import cache
from django.http import Http404
from django.views.decorators.csrf import csrf_exempt
from django.db import transaction
from decimal import Decimal
import uuid
from django.shortcuts import redirect, render
from django.views.decorators.http import require_POST

from accounts import services as acc
from . import services
from . import iyzico
from .models import ApiKey, Domain, Mailbox, Order, UpgradeRequest

CONNECT = {"host": settings.MX_TARGET, "imap_port": 993, "smtp_port": 587}


def _ip(request):
    return request.META.get("HTTP_X_REAL_IP") or request.META.get("REMOTE_ADDR", "")


def _throttled(request, bucket, limit, window=900):
    """Basit sayaç (süreç başına). Kaba kuvvet/yığın kayıt yavaşlatma; asıl kapı Caddy rate_limit + fail2ban."""
    key = f"th:{bucket}:{_ip(request)}"
    n = cache.get(key, 0)
    if n >= limit:
        return True
    cache.set(key, n + 1, window)
    return False


def _fail(request, exc):
    messages.error(request, exc.message)


# ---------- giriş / kayıt ----------
def register_view(request):
    if request.user.is_authenticated:
        return redirect("panel-home")
    if request.method == "POST":
        if _throttled(request, "register", 10):
            messages.error(request, "Too many attempts. Try again later.")
        elif request.POST.get("password") != request.POST.get("password2"):
            messages.error(request, "The two passwords do not match.")
        else:
            accepted = acc.TERMS_VERSION if request.POST.get("accept") == "on" else ""
            try:
                user = acc.register(request.POST.get("email", ""), request.POST.get("password", ""), accepted)
                if user:
                    acc.send_verification(user)
                return render(request, "panel/check_email.html")     # kayıtlı olsa da olmasa da aynı yanıt
            except acc.RegistrationError as e:
                messages.error(request, e.message)
    return render(request, "panel/register.html", {"terms_version": acc.TERMS_VERSION})


def login_view(request):
    if request.user.is_authenticated:
        return redirect("panel-home")
    if request.method == "POST":
        if _throttled(request, "login", 10):
            messages.error(request, "Too many attempts. Try again in a few minutes.")
        else:
            try:
                user = acc.login_user(request, request.POST.get("email", ""), request.POST.get("password", ""))
                login(request, user)
                return redirect("panel-home")
            except acc.RegistrationError as e:
                messages.error(request, e.message)
                # 401: tarayıcı için fark yok; Caddy access logunda başarısız giriş görünür → fail2ban (caddy-posta-auth) sayar.
                return render(request, "panel/login.html", status=401)
    return render(request, "panel/login.html")


def forgot_view(request):
    if request.method == "POST":
        if _throttled(request, "forgot", 5):
            messages.error(request, "Too many attempts. Try again later.")
        else:
            acc.request_password_reset(request.POST.get("email", ""))
            return render(request, "panel/forgot_sent.html")           # hesap olsa da olmasa da aynı yanıt
    return render(request, "panel/forgot.html")


def reset_view(request, token):
    if not acc.read_reset_token(token):
        return render(request, "panel/reset.html", {"bad": True}, status=400)
    if request.method == "POST":
        if request.POST.get("password") != request.POST.get("password2"):
            messages.error(request, "The two passwords do not match.")
        elif _throttled(request, "reset", 10):
            messages.error(request, "Too many attempts. Try again later.")
        else:
            try:
                acc.reset_password(token, request.POST.get("password", ""))
                messages.success(request, "Password changed. Sign in with the new one.")
                return redirect("panel-login")
            except acc.RegistrationError as e:
                messages.error(request, e.message)
    return render(request, "panel/reset.html")


@require_POST
def logout_view(request):
    logout(request)
    return redirect("panel-login")


def verify_view(request, token):
    user = acc.confirm_email(token)
    return render(request, "panel/verified.html", {"ok": bool(user)}, status=200 if user else 400)


# ---------- panel ----------
def _plan(request):
    try:
        return services.membership(request.user).plan
    except services.ServiceError as e:
        messages.error(request, e.message)
        return None


@login_required
def home(request):
    plan = _plan(request)
    if plan is None:
        return render(request, "panel/blocked.html")
    domains = list(Domain.objects.filter(owner=request.user).prefetch_related("mailboxes").order_by("id"))
    n_boxes = sum(d.mailboxes.count() for d in domains)
    return render(request, "panel/home.html", {
        "plan": plan, "domains": domains, "n_boxes": n_boxes,
        "can_add_domain": len([d for d in domains if d.status != Domain.SUSPENDED]) < plan.max_domains,
        "open_requests": UpgradeRequest.objects.filter(user=request.user, status=UpgradeRequest.OPEN).count(),
    })


@login_required
@require_POST
def domain_add(request):
    try:
        d = services.add_domain(request.user, request.POST.get("name", ""))
        return redirect("panel-domain", pk=d.pk)
    except services.ServiceError as e:
        _fail(request, e)
        return redirect("panel-home")


def _own_domain(request, pk):
    d = Domain.objects.filter(pk=pk, owner=request.user).first()
    if not d:
        raise Http404
    return d


def _dns_rows(d):
    """Her satır: kayıt + son kontrol sonucu (ok: True/False; kontrol yapılmadıysa None) + yanlışsa ipucu."""
    chk = d.last_check or {}
    rows = [{"key": "ownership_txt", "label": "Ownership", "type": "TXT", "name": d.txt_record["name"], "value": d.txt_record["value"], "required": True,
             "hint": "Not found yet. Add this exact TXT record. Some DNS panels want the name without your domain."},
            {"key": "mx", "label": "Mail routing", "type": "MX", "name": d.name, "value": f"10 {settings.MX_TARGET}.", "required": True,
             "hint": f"Our server is not in your MX records. Remove old MX records (for example from a previous email provider) so only {settings.MX_TARGET} is left."},
            {"key": "spf", "label": "SPF", "type": "TXT", "name": d.name, "value": f"v=spf1 include:{settings.SPF_INCLUDE} ~all", "required": False,
             "hint": "Your domain can have only one SPF record. If you already have one, add our include: part into it instead of creating a second."},
            {"key": "dmarc", "label": "DMARC", "type": "TXT", "name": f"_dmarc.{d.name}", "value": "v=DMARC1; p=none", "required": False, "hint": ""}]
    if d.dkim_txt:
        rows.append({"key": "dkim", "label": "DKIM", "type": "TXT", "name": f"{d.dkim_selector}._domainkey.{d.name}", "value": d.dkim_txt, "required": False, "hint": ""})
    for r in rows:
        r["ok"] = chk.get(r["key"]) if chk else None
    return rows


@login_required
def domain_detail(request, pk):
    d = _own_domain(request, pk)
    plan = _plan(request)
    if plan is None:
        return render(request, "panel/blocked.html")
    n = d.mailboxes.count()
    rows = _dns_rows(d)
    return render(request, "panel/domain.html", {
        "d": d, "rows": rows, "check": d.last_check or {}, "plan": plan,
        "req_total": sum(1 for r in rows if r["required"]), "req_ok": sum(1 for r in rows if r["required"] and r["ok"]),
        "boxes": d.mailboxes.order_by("id"), "at_limit": n >= plan.max_mailboxes_per_domain,
        "connect": CONNECT, "verified": d.status == Domain.VERIFIED,
    })


@login_required
@require_POST
def domain_verify(request, pk):
    d = _own_domain(request, pk)
    if _throttled(request, f"verify{request.user.pk}", 30, 3600):
        messages.error(request, "Too many checks. Wait a few minutes. DNS changes can take time to spread.")
        return redirect("panel-domain", pk=pk)
    try:
        d = services.verify_domain(request.user, d)
        messages.success(request, "Domain verified. You can create your mailbox now.") if d.status == Domain.VERIFIED \
            else messages.info(request, "Not verified yet. The checklist shows what is missing. DNS changes can take up to a few hours.")
    except services.ServiceError as e:
        _fail(request, e)
    return redirect("panel-domain", pk=pk)


@login_required
@require_POST
def domain_delete(request, pk):
    d = _own_domain(request, pk)
    if request.POST.get("confirm", "").strip().lower() != d.name:
        messages.error(request, "Type the domain name to confirm. Deleting removes its mailboxes and their mail.")
        return redirect("panel-domain", pk=pk)
    try:
        services.delete_domain(request.user, d)
        messages.success(request, "Domain and its mailboxes deleted.")
        return redirect("panel-home")
    except services.ServiceError as e:
        _fail(request, e)
        return redirect("panel-domain", pk=pk)


@login_required
@require_POST
def mailbox_create(request, pk):
    d = _own_domain(request, pk)
    try:
        mb = services.create_mailbox(request.user, d, request.POST.get("local", ""), request.POST.get("password", ""))
        messages.success(request, f"Mailbox {mb.address} is ready.")
    except services.ServiceError as e:
        _fail(request, e)
    return redirect("panel-domain", pk=pk)


@login_required
@require_POST
def mailbox_delete(request, pk):
    mb = Mailbox.objects.filter(pk=pk, domain__owner=request.user).select_related("domain").first()
    if not mb:
        raise Http404
    did, addr = mb.domain_id, mb.address
    if request.POST.get("confirm", "").strip().lower() != addr:
        messages.error(request, "Type the full address to confirm. Deleting removes the mailbox and its mail.")
        return redirect("panel-domain", pk=did)
    try:
        services.delete_mailbox(request.user, mb)
        messages.success(request, f"{addr} deleted.")
    except services.ServiceError as e:
        _fail(request, e)
    return redirect("panel-domain", pk=did)


# ---------- API anahtarları ----------
@login_required
def keys(request):
    return render(request, "panel/keys.html", {
        "keys": ApiKey.objects.filter(owner=request.user, revoked_at__isnull=True).order_by("-id"),
        "scopes": ApiKey.SCOPES, "base": settings.PUBLIC_BASE_URL})


@login_required
@require_POST
def key_create(request):
    try:
        key, full = services.create_api_key(request.user, request.POST.get("name", ""), request.POST.getlist("scopes"))
    except services.ServiceError as e:
        _fail(request, e)
        return redirect("panel-keys")
    return render(request, "panel/key_created.html", {"key": key, "full": full, "base": settings.PUBLIC_BASE_URL})   # yalnız bir kez gösterilir


@login_required
@require_POST
def key_revoke(request, pk):
    key = ApiKey.objects.filter(pk=pk, owner=request.user).first()
    if not key:
        raise Http404
    services.revoke_api_key(request.user, key)
    messages.success(request, f"Key {key.prefix}… revoked.")
    return redirect("panel-keys")


# ---------- ücretli talep ----------
@login_required
def upgrade(request):
    if request.method == "POST":
        try:
            services.request_upgrade(request.user, request.POST.get("kind", ""), request.POST.get("quantity"), request.POST.get("note", ""))
            messages.success(request, "Request received. We will write to you with the price. Nothing is charged until you approve it.")
            return redirect("panel-upgrade")
        except services.ServiceError as e:
            _fail(request, e)
    return render(request, "panel/upgrade.html", {
        "plan": _plan(request), "reqs": UpgradeRequest.objects.filter(user=request.user).order_by("-id")[:10],
        "kind": request.GET.get("kind", "mailboxes")})


# ---------- Pro plan satın alma ----------
def _payments_ready():
    return settings.PAYMENTS_ENABLED and iyzico.configured() and services.pro_plan() is not None


@login_required
def billing(request):
    plan, pro = _plan(request), services.pro_plan()
    if plan is None:
        return render(request, "panel/blocked.html")
    if request.method == "POST":
        if not _payments_ready():
            messages.error(request, "Online payment is not open yet. Use \"More capacity\" and we will send you a written offer.")
            return redirect("panel-upgrade")
        f = request.POST
        name, country, address = f.get("name", "").strip(), f.get("country", "").strip(), f.get("address", "").strip()
        if _throttled(request, "billing", 10):
            messages.error(request, "Too many attempts. Try again later.")
        elif not (name and country and address):
            messages.error(request, "Full name, country and billing address are required for the invoice.")
        elif f.get("buyer_type") not in ("business", "consumer"):
            messages.error(request, "Please tell us whether you are buying for business or as a consumer.")
        elif f.get("accept") != "on":
            messages.error(request, "Please confirm that you have read and accept the sales terms.")
        else:
            order = Order.objects.create(
                user=request.user, plan=pro, amount_usd=Decimal(pro.price_usd_yearly), conversation_id="posta-" + uuid.uuid4().hex,
                buyer_name=name[:240], buyer_country=country[:80], buyer_address=address[:300],
                buyer_tax_id=f.get("tax_id", "").strip()[:40], terms_version=acc.TERMS_VERSION, sales_version=acc.TERMS_VERSION,
                buyer_type=f["buyer_type"], accept_ip=(_ip(request) or None))
            first, _, last = name.partition(" ")
            payload = iyzico.build_payload(
                conversation_id=order.conversation_id, basket_id=f"pro-{order.id}", price=order.amount_usd, currency=order.currency,
                callback_url=settings.IYZICO_CALLBACK_URL, item_name="posta Pro (1 year)",
                buyer={"id": f"u{request.user.id}", "name": first, "surname": last or first, "email": request.user.email,
                       "address": address, "country": country, "city": country, "ip": _ip(request)})
            try:
                data = iyzico.initialize(payload)
                if not iyzico.verify_initialize(data) or not data.get("paymentPageUrl"):
                    raise iyzico.IyzicoError("bad initialize response", "bad_signature")
                order.iyzico_token = data.get("token", "")
                order.save(update_fields=["iyzico_token"])
                return redirect(data["paymentPageUrl"])
            except iyzico.IyzicoError as e:
                order.status, order.error = Order.FAILED, str(e)[:256]
                order.save(update_fields=["status", "error"])
                messages.error(request, "We could not start the payment. Nothing was charged. Try again or write to merhaba@preved.co.")
    result = request.GET.get("r")
    if result == "ok":
        messages.success(request, "Payment received. Your Pro plan is active.")
    elif result == "failed":
        messages.error(request, "The payment was not completed. Nothing was charged.")
    from .models import Membership
    m = Membership.objects.filter(user=request.user).first()
    return render(request, "panel/billing.html", {
        "plan": plan, "pro": pro, "ready": _payments_ready(), "membership": m, "sales_version": acc.TERMS_VERSION,
        "is_pro": bool(pro and plan.pk == pro.pk), "orders": Order.objects.filter(user=request.user, status=Order.PAID).order_by("-id")[:10]})


@csrf_exempt
def billing_callback(request):
    """iyzico buraya (çoğunlukla çapraz-site POST, oturum çerezi gelmeyebilir) token ile döner. Doğruluk kaynağı: imzalı retrieve."""
    token = request.POST.get("token") or request.GET.get("token") or ""
    if not token:
        return redirect("/app/billing/?r=failed")
    try:
        detail = iyzico.retrieve(token)
    except iyzico.IyzicoError:
        return redirect("/app/billing/?r=failed")
    ok, errs, order = False, [], None
    with transaction.atomic():
        order = Order.objects.select_for_update().filter(iyzico_token=token).first()
        if not order:
            return redirect("/app/billing/?r=failed")
        if order.status != Order.PENDING:
            return redirect("/app/billing/?r=" + ("ok" if order.status == Order.PAID else "failed"))
        ok = services.finish_order(order, detail)
        if ok:
            errs = services.activate_pro(order)
    if ok:
        services.notify_operator(f"ÖDEME ALINDI: {order.user.email}", f"Pro (1 yıl) ${order.amount_usd} — sipariş #{order.id}, iyzico paymentId {order.iyzico_payment_id}, {order.buyer_type}. "
                f"Fatura bilgisi: {order.buyer_name}, {order.buyer_country}, {order.buyer_address}, vergi no: {order.buyer_tax_id or '-'}. E-Arşiv faturasını 7 gün içinde kes."
                + (f" UYARI: Mailcow limit hatası: {errs}" if errs else ""))
        services.send_receipt(order)
    elif order and order.status == Order.REVIEW:
        services.notify_operator(f"⚠ ÖDEME İNCELEME GEREKİR: sipariş #{order.id}", f"{order.user.email}: iyzico SUCCESS döndü ama doğrulama tutmadı (imza/tutar/para birimi). "
                f"Para alınmış olabilir. iyzico panelinde paymentId {order.iyzico_payment_id} kontrol et; doğruysa: manage.py confirm_order {order.id}")
    return redirect("/app/billing/?r=" + ("ok" if ok else "failed"))
