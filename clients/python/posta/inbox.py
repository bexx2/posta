"""Read (and send) mail with the mailbox password over IMAP/SMTP. Runs on your side; posta never sees what you read."""
import email
import imaplib
import smtplib
import ssl
import time
from dataclasses import dataclass, field
from email.message import EmailMessage
from email.policy import default as _policy
from email.utils import parsedate_to_datetime

DEFAULT_HOST = "mail.posta.preved.co"


@dataclass
class Message:
    uid: int
    from_: str
    to: str
    subject: str
    date: object
    message_id: str
    text: str = ""
    html: str = ""
    headers: dict = field(default_factory=dict, repr=False)


def _parse(uid: int, raw: bytes) -> Message:
    m = email.message_from_bytes(raw, policy=_policy)
    text = m.get_body(preferencelist=("plain",))
    html = m.get_body(preferencelist=("html",))
    try:
        date = parsedate_to_datetime(m["Date"]) if m["Date"] else None
    except (TypeError, ValueError):
        date = None
    return Message(uid=uid, from_=str(m["From"] or ""), to=str(m["To"] or ""), subject=str(m["Subject"] or ""), date=date,
                   message_id=str(m["Message-ID"] or ""), text=text.get_content() if text else "", html=html.get_content() if html else "",
                   headers={k: str(v) for k, v in m.items()})


class Inbox:
    """with Inbox("agent@example.com", password) as box: msg = box.wait_for(subject_contains="code")

    The mailbox is opened read-only: reading does not mark messages as seen or delete anything."""
    def __init__(self, address: str, password: str, host: str = DEFAULT_HOST, imap_port: int = 993, smtp_port: int = 587, timeout: float = 30):
        self.address, self._pw, self.host = address, password, host
        self.imap_port, self.smtp_port, self.timeout = imap_port, smtp_port, timeout
        self._imap = None

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, *exc):
        self.close()

    def connect(self):
        if self._imap is None:
            self._imap = imaplib.IMAP4_SSL(self.host, self.imap_port, ssl_context=ssl.create_default_context(), timeout=self.timeout)
            self._imap.login(self.address, self._pw)
        return self

    def close(self):
        if self._imap is not None:
            try:
                self._imap.logout()
            finally:
                self._imap = None

    def _select(self):
        self.connect()
        typ, data = self._imap.select("INBOX", readonly=True)
        if typ != "OK":
            raise RuntimeError(f"cannot open INBOX: {data}")

    def _uids(self, criteria="ALL"):
        typ, data = self._imap.uid("SEARCH", None, criteria)
        return [int(x) for x in (data[0] or b"").split()] if typ == "OK" else []

    def get(self, uid: int) -> Message:
        self._select()
        typ, data = self._imap.uid("FETCH", str(uid), "(BODY.PEEK[])")
        raw = next((d[1] for d in data if isinstance(d, tuple)), None) if typ == "OK" else None
        if raw is None:
            raise KeyError(f"no message with uid {uid}")
        return _parse(uid, raw)

    def latest(self, n: int = 10, unseen_only: bool = False) -> list:
        """Newest first."""
        self._select()
        uids = self._uids("UNSEEN" if unseen_only else "ALL")[-n:]
        return [self.get(u) for u in reversed(uids)]

    def wait_for(self, subject_contains: str = None, from_contains: str = None, timeout: float = 120, poll: float = 5) -> Message:
        """Waits for a NEW message (arriving after this call) that matches; returns it or raises TimeoutError."""
        self._select()
        seen = max(self._uids() or [0])
        deadline = time.monotonic() + timeout
        while True:
            self._select()                                   # re-select refreshes the mailbox view
            for uid in [u for u in self._uids() if u > seen]:
                msg = self.get(uid)
                seen = max(seen, uid)
                if subject_contains and subject_contains.lower() not in msg.subject.lower():
                    continue
                if from_contains and from_contains.lower() not in msg.from_.lower():
                    continue
                return msg
            if time.monotonic() >= deadline:
                raise TimeoutError("no matching message arrived in time")
            time.sleep(poll)

    def send(self, to, subject: str, text: str = "", html: str = "", reply_to: str = "") -> str:
        """Sends over SMTP as this mailbox (same daily limit as the API). Returns the Message-ID."""
        msg = EmailMessage()
        msg["From"], msg["To"], msg["Subject"] = self.address, to if isinstance(to, str) else ", ".join(to), subject
        msg["Message-ID"] = email.utils.make_msgid(domain=self.address.split("@", 1)[1])
        msg["Date"] = email.utils.formatdate(localtime=False)
        if reply_to:
            msg["Reply-To"] = reply_to
        msg.set_content(text or "This message has an HTML version.")
        if html:
            msg.add_alternative(html, subtype="html")
        with smtplib.SMTP(self.host, self.smtp_port, timeout=self.timeout) as s:
            s.starttls(context=ssl.create_default_context())
            s.login(self.address, self._pw)
            s.send_message(msg)
        return msg["Message-ID"]
