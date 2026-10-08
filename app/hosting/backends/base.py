class BackendError(Exception):
    pass


class MailBackend:
    """Posta sunucusu arayüzü. Mailcow API'si ve anahtarı yalnız burada yaşar; dışarı ASLA açılmaz."""
    def add_domain(self, domain: str, max_mailboxes: int, quota_mb: int) -> None: raise NotImplementedError
    def delete_domain(self, domain: str) -> None: raise NotImplementedError
    def dkim(self, domain: str, selector: str) -> tuple: raise NotImplementedError   # (gerçek seçici, TXT değeri) — arka uç istenen seçiciyi yoksayabilir
    def add_mailbox(self, address: str, password: str, quota_mb: int, send_per_day: int) -> None: raise NotImplementedError
    def delete_mailbox(self, address: str) -> None: raise NotImplementedError
    def set_suspended(self, address: str, suspended: bool) -> None: raise NotImplementedError
