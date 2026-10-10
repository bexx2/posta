import hashlib
import hmac
import time


def verify_webhook(secret: str, signature_header: str, raw_body: bytes, tolerance: int = 300) -> bool:
    """Checks the Posta-Signature header (t=<unix>,v1=<hex>) of a webhook request. Use the RAW request body."""
    try:
        parts = dict(p.split("=", 1) for p in signature_header.split(","))
        ts = int(parts["t"])
    except (ValueError, KeyError, AttributeError):
        return False
    if abs(time.time() - ts) > tolerance:
        return False
    expected = hmac.new(secret.encode(), parts["t"].encode() + b"." + raw_body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, parts.get("v1", ""))
