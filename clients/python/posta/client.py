"""Thin wrapper over the posta REST API (https://posta.preved.co/openapi.json)."""
import os

import requests

DEFAULT_BASE_URL = "https://posta.preved.co/v1"


class PostaError(Exception):
    """An API error. `code` is stable (e.g. "plan_limit", "daily_limit"), `message` is for humans."""
    def __init__(self, status: int, code: str, message: str):
        super().__init__(f"{status} {code}: {message}")
        self.status, self.code, self.message = status, code, message


class _Resource:
    def __init__(self, client):
        self._c = client


class Domains(_Resource):
    def list(self):
        return self._c._req("GET", "/domains")

    def create(self, name: str):
        """Returns the domain with the DNS records to publish (ownership TXT and MX)."""
        return self._c._req("POST", "/domains", {"name": name})

    def get(self, domain_id: int):
        return self._c._req("GET", f"/domains/{domain_id}")

    def verify(self, domain_id: int):
        """Checks DNS now. We also check automatically every 15 minutes."""
        return self._c._req("POST", f"/domains/{domain_id}/verify")

    def delete(self, domain_id: int):
        return self._c._req("DELETE", f"/domains/{domain_id}")


class Mailboxes(_Resource):
    def list(self):
        return self._c._req("GET", "/mailboxes")

    def create(self, domain_id: int, local_part: str, password: str):
        """You choose the password; it is the IMAP/SMTP password. We can't show it later."""
        return self._c._req("POST", "/mailboxes", {"domain_id": domain_id, "local_part": local_part, "password": password})

    def delete(self, mailbox_id: int):
        return self._c._req("DELETE", f"/mailboxes/{mailbox_id}")

    def send(self, mailbox_id: int, to, subject: str, text: str = "", html: str = "", reply_to: str = ""):
        """Sends one message as the mailbox (needs the mail:send scope). `to`: one address or up to 10."""
        body = {"to": to, "subject": subject}
        body.update({k: v for k, v in (("text", text), ("html", html), ("reply_to", reply_to)) if v})
        return self._c._req("POST", f"/mailboxes/{mailbox_id}/send", body)

    def set_webhook(self, mailbox_id: int, url: str):
        """Returns {"url", "active", "secret"}. Keep the secret: use it with posta.verify_webhook()."""
        return self._c._req("PUT", f"/mailboxes/{mailbox_id}/webhook", {"url": url})

    def get_webhook(self, mailbox_id: int):
        return self._c._req("GET", f"/mailboxes/{mailbox_id}/webhook")

    def delete_webhook(self, mailbox_id: int):
        return self._c._req("DELETE", f"/mailboxes/{mailbox_id}/webhook")


class Posta:
    """Posta(api_key="pk_live_...") or set POSTA_KEY. Create keys in the dashboard."""
    def __init__(self, api_key: str = None, base_url: str = None, timeout: float = 30, session=None):
        self.api_key = api_key or os.environ.get("POSTA_KEY", "")
        if not self.api_key:
            raise ValueError("Pass api_key or set POSTA_KEY.")
        self.base_url = (base_url or os.environ.get("POSTA_BASE_URL") or DEFAULT_BASE_URL).rstrip("/")
        self.timeout = timeout
        self._s = session or requests.Session()
        self.domains, self.mailboxes = Domains(self), Mailboxes(self)

    def usage(self):
        return self._req("GET", "/usage")

    def _req(self, method, path, json=None):
        r = self._s.request(method, self.base_url + path, json=json, timeout=self.timeout,
                            headers={"Authorization": f"Bearer {self.api_key}", "User-Agent": "posta-python/0.1"})
        if r.status_code == 204:
            return None
        try:
            data = r.json()
        except ValueError:
            data = None
        if r.status_code >= 400:
            err = (data or {}).get("error") or {} if isinstance(data, dict) else {}
            raise PostaError(r.status_code, err.get("code", "http_error"), err.get("message", r.text[:200]))
        return data
