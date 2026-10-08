from .base import MailBackend


class DryRunBackend(MailBackend):
    """Hiçbir şey açmaz; yalnız yaptığı işleri kaydeder (testler + güvenli varsayılan)."""
    _inst = None

    @classmethod
    def instance(cls):
        if cls._inst is None:
            cls._inst = cls()
        return cls._inst

    def __init__(self):
        self.ops = []

    def reset(self):
        self.ops.clear()

    def add_domain(self, domain, max_mailboxes, quota_mb):
        self.ops.append(("add_domain", domain, max_mailboxes, quota_mb))

    def delete_domain(self, domain):
        self.ops.append(("delete_domain", domain))

    def dkim(self, domain, selector):
        self.ops.append(("dkim", domain, selector))
        return selector, "v=DKIM1;k=rsa;p=DRYRUN"

    def add_mailbox(self, address, password, quota_mb, send_per_day):
        self.ops.append(("add_mailbox", address, quota_mb, send_per_day))   # parola kaydedilmez

    def delete_mailbox(self, address):
        self.ops.append(("delete_mailbox", address))

    def set_suspended(self, address, suspended):
        self.ops.append(("set_suspended", address, suspended))

    def set_domain_limits(self, domain, max_mailboxes, quota_mb):
        self.ops.append(("set_domain_limits", domain, max_mailboxes, quota_mb))
