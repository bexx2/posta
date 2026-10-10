"""Mailcow API sarmalayıcısı (loopback, kendinden imzalı sertifika). Gerçek sunucuya dokunur — MAIL_BACKEND=mailcow ile açılır."""
import requests
import urllib3

from .base import BackendError, MailBackend

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)  # yalnız 127.0.0.1 hop'u


class MailcowBackend(MailBackend):
    def __init__(self, url: str, key: str):
        if not key:
            raise BackendError("MAILCOW_API_KEY ayarlı değil")
        self.url, self.key = url.rstrip("/"), key

    def _call(self, method, path, payload=None):
        r = requests.request(method, f"{self.url}/{path}", json=payload, timeout=20, verify=False,
                             headers={"X-API-Key": self.key})
        try:
            data = r.json()
        except ValueError:
            raise BackendError(f"mailcow {path}: HTTP {r.status_code}")
        if r.status_code >= 400 or (isinstance(data, list) and data and isinstance(data[0], dict) and data[0].get("type") in ("danger", "error")):
            raise BackendError(f"mailcow {path}: {str(data)[:200]}")
        return data

    def add_domain(self, domain, max_mailboxes, quota_mb):
        self._call("POST", "add/domain", {
            "domain": domain, "description": "posta customer", "active": "1", "aliases": "0", "mailboxes": str(max_mailboxes),
            "defquota": str(quota_mb), "maxquota": str(quota_mb), "quota": str(quota_mb * max_mailboxes),
            "restart_sogo": "0", "relay_all_recipients": "0"})

    def delete_domain(self, domain):
        self._call("POST", "delete/domain", [domain])

    def dkim(self, domain, selector):
        """Mailcow add/domain çoğu kurulumda DKIM'i otomatik üretir (seçici "dkim") ve add/dkim'de istenen seçiciyi
        yoksayabilir. Bu yüzden Mailcow'un BİLDİRDİĞİ seçici döner; panel DNS satırı ona göre yazılır (2026-10-07 E2E bulgusu)."""
        def _get():
            data = self._call("GET", f"get/dkim/{domain}")
            if isinstance(data, dict) and data.get("dkim_txt"):
                return (data.get("dkim_selector") or selector), data["dkim_txt"]
            return None
        got = None
        try:
            got = _get()
        except BackendError:
            got = None
        if not got:
            self._call("POST", "add/dkim", {"domains": domain, "dkim_selector": selector, "key_size": "2048"})
            got = _get()
        if not got:
            raise BackendError(f"mailcow dkim {domain}: anahtar üretilemedi")
        return got

    def add_mailbox(self, address, password, quota_mb, send_per_day):
        local, domain = address.split("@", 1)
        self._call("POST", "add/mailbox", {
            "local_part": local, "domain": domain, "name": local, "password": password, "password2": password,
            "quota": str(quota_mb), "active": "1", "force_pw_update": "0", "tls_enforce_in": "1", "tls_enforce_out": "1"})
        # mailcow: gönderim sınırı kutu başına GÜNLÜK (plan metni "N a day" ile birebir; 2026-10-08'e kadar //24 saatlikti → çelişkiydi)
        self._call("POST", "edit/mailbox", {"items": [address], "attr": {"rl_value": str(send_per_day), "rl_frame": "d"}})

    def delete_mailbox(self, address):
        self._call("POST", "delete/mailbox", [address])

    def set_suspended(self, address, suspended):
        self._call("POST", "edit/mailbox", {"items": [address], "attr": {"active": "0" if suspended else "1"}})

    def set_domain_limits(self, domain, max_mailboxes, quota_mb):
        self._call("POST", "edit/domain", {"items": [domain], "attr": {
            "mailboxes": str(max_mailboxes), "defquota": str(quota_mb), "maxquota": str(quota_mb), "quota": str(quota_mb * max_mailboxes)}})

    def submit(self, address, msg):
        """API'den gönderim (#7). Kalıcı kimlik bilgisi SAKLANMAZ: kutuya yalnız SMTP'ye izinli tek kullanımlık uygulama parolası
        açılır, ileti kutunun kendi adıyla 587'den gönderilir, parola hemen silinir. Mailcow'un kutu başına günlük limiti (rl_frame=d)
        SMTP ve API gönderimlerini birlikte sayar; IMAP'e erişimi olmadığı için bu parola postaları okuyamaz."""
        import secrets
        import smtplib
        import ssl
        from django.conf import settings
        name, pw = f"posta-api-{secrets.token_hex(6)}", secrets.token_urlsafe(24)
        self._call("POST", "add/app-passwd", {"username": address, "app_name": name, "app_passwd": pw, "app_passwd2": pw,
                                              "active": "1", "protocols": ["smtp_access"]})
        try:
            with smtplib.SMTP(settings.SMTP_SUBMIT_HOST, 587, timeout=30) as s:
                s.starttls(context=ssl.create_default_context())
                s.login(address, pw)
                return s.send_message(msg)
        finally:
            try:
                ids = [a["id"] for a in (self._call("GET", f"get/app-passwd/all/{address}") or []) if isinstance(a, dict) and a.get("name") == name]
                if ids:
                    self._call("POST", "delete/app-passwd", ids)
            except BackendError:
                pass   # silinemezse yalnız SMTP yetkili, adı belli; posta_status/temizlik görür

    def message_counts(self):
        data = self._call("GET", "get/mailbox/all") or []
        return {m["username"]: int(m.get("messages") or 0) for m in data if isinstance(m, dict) and m.get("username")}
