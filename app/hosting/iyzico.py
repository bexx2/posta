"""iyzico Checkout Form istemcisi (IYZWSv2). HeyvAql'deki payments/services/iyzico_gateway.py'nin posta'ya uyarlanmış kırpılmış hâli.

Kart bilgisi posta'ya hiç girmez (PCI iyzico'da). Ödemenin doğruluk kaynağı: bizim TLS ile, imzalı çektiğimiz retrieve cevabı.
Resmî SDK kullanılmaz: sınıf düzeyinde header paylaşımı eşzamanlı isteklerde birbirini ezer.
"""
import base64
import hashlib
import hmac
import json
import random
import string
from decimal import Decimal

import requests
from django.conf import settings

PATH_CF_INIT = "/payment/iyzipos/checkoutform/initialize/auth/ecom"
PATH_CF_DETAIL = "/payment/iyzipos/checkoutform/auth/ecom/detail"
TIMEOUT = 20


class IyzicoError(RuntimeError):
    def __init__(self, message, code="", raw=None):
        super().__init__(message)
        self.code, self.raw = code, raw or {}


def _cfg(name, default=""):
    v = getattr(settings, name, None)
    return str(v) if v not in (None, "") else default


def configured():
    return bool(_cfg("IYZICO_API_KEY") and _cfg("IYZICO_SECRET_KEY"))


def fmt_price(value):
    d = value if isinstance(value, Decimal) else Decimal(str(value))
    s = f"{d:.2f}".rstrip("0")
    return s + "0" if s.endswith(".") else s


def normalize_price(value):
    s = "" if value is None else str(value)
    return s.rstrip("0").rstrip(".") if "." in s else s


def _auth(path, rnd, body):
    sig = hmac.new(_cfg("IYZICO_SECRET_KEY").encode(), (rnd + path.split("?")[0] + body).encode(), hashlib.sha256).hexdigest()
    raw = f"apiKey:{_cfg('IYZICO_API_KEY')}&randomKey:{rnd}&signature:{sig}"
    return "IYZWSv2 " + base64.b64encode(raw.encode()).decode()


def _request(path, body):
    if not configured():
        raise IyzicoError("iyzico credentials missing", "missing_credentials")
    body_str = json.dumps(body)
    rnd = "".join(random.SystemRandom().choice(string.ascii_letters + string.digits) for _ in range(8))
    headers = {"Accept": "application/json", "Content-type": "application/json", "x-iyzi-client-version": "posta-iyzico-1.0",
               "x-iyzi-rnd": rnd, "Authorization": _auth(path, rnd, body_str)}
    try:
        r = requests.post(_cfg("IYZICO_BASE_URL", "https://api.iyzipay.com").rstrip("/") + path,
                          data=body_str.encode(), headers=headers, timeout=TIMEOUT)
        data = r.json()
    except (requests.RequestException, ValueError) as exc:
        raise IyzicoError(f"iyzico unreachable or bad response: {exc}", "transport") from exc
    if not isinstance(data, dict) or data.get("status") != "success":
        d = data if isinstance(data, dict) else {}
        raise IyzicoError(d.get("errorMessage") or d.get("errorCode") or "iyzico error", str(d.get("errorCode") or ""), d)
    return data


def _verify(params, signature):
    secret = _cfg("IYZICO_SECRET_KEY")
    if not signature or not secret:
        return False
    calc = hmac.new(secret.encode(), ":".join("" if p is None else str(p) for p in params).encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(calc, str(signature))


def verify_retrieve(d):
    return _verify([d.get("paymentStatus", ""), d.get("paymentId", ""), d.get("currency", ""), d.get("basketId", ""),
                    d.get("conversationId", ""), normalize_price(d.get("paidPrice", "")), normalize_price(d.get("price", "")),
                    d.get("token", "")], d.get("signature", ""))


def verify_initialize(d):
    return _verify([d.get("conversationId", ""), d.get("token", "")], d.get("signature", ""))


def initialize(payload):
    return _request(PATH_CF_INIT, payload)


def retrieve(token, conversation_id=""):
    body = {"locale": "en", "token": token}
    if conversation_id:
        body["conversationId"] = conversation_id
    return _request(PATH_CF_DETAIL, body)


def _c(v, fallback, limit=200):
    s = ("" if v is None else str(v)).strip()
    return (s or fallback)[:limit]


def build_payload(*, conversation_id, basket_id, price, currency, callback_url, buyer, item_name):
    """Tek kalemli dijital (VIRTUAL) sepet, tek çekim. identityNumber/gsm: yabancı müşteride yok → iyzico'nun kabul ettiği yer tutucu."""
    p = fmt_price(price)
    addr, city, country = _c(buyer.get("address"), "Not provided", 240), _c(buyer.get("city"), "N/A", 80), _c(buyer.get("country"), "N/A", 80)
    contact = _c(f"{buyer.get('name', '')} {buyer.get('surname', '')}", "posta customer", 120)
    return {
        "locale": "en", "conversationId": conversation_id, "price": p, "paidPrice": p, "currency": currency,
        "basketId": basket_id, "paymentGroup": "PRODUCT", "callbackUrl": callback_url, "enabledInstallments": [1],
        "buyer": {"id": _c(buyer.get("id"), "guest", 64), "name": _c(buyer.get("name"), "posta", 120),
                  "surname": _c(buyer.get("surname"), "customer", 120), "identityNumber": _c(buyer.get("identity_number"), "11111111111", 11),
                  "email": _c(buyer.get("email"), "noreply@preved.co", 120), "gsmNumber": "+905000000000",
                  "registrationAddress": addr, "city": city, "country": country, "ip": _c(buyer.get("ip"), "85.34.78.112", 45)},
        "billingAddress": {"contactName": contact, "city": city, "country": country, "address": addr},
        "shippingAddress": {"contactName": contact, "city": city, "country": country, "address": addr},
        "basketItems": [{"id": basket_id, "name": _c(item_name, "posta Pro", 120), "category1": "SaaS", "itemType": "VIRTUAL", "price": p}],
    }
