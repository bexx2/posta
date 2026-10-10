import time
import unittest
from unittest import mock

from posta import Inbox, Posta, PostaError, verify_webhook
from posta.webhook import hmac, hashlib


def resp(status, data=None):
    r = mock.Mock(status_code=status, text="")
    r.json.return_value = data
    return r


class Client(unittest.TestCase):
    def setUp(self):
        self.s = mock.Mock()
        self.p = Posta("pk_live_x", session=self.s)

    def test_sends_bearer_and_parses(self):
        self.s.request.return_value = resp(201, {"id": 1, "address": "a@x.dev"})
        self.assertEqual(self.p.mailboxes.create(3, "a", "pw-long-enough")["id"], 1)
        method, url = self.s.request.call_args[0]
        self.assertEqual((method, url), ("POST", "https://posta.preved.co/v1/mailboxes"))
        self.assertEqual(self.s.request.call_args[1]["headers"]["Authorization"], "Bearer pk_live_x")

    def test_error_has_stable_code(self):
        self.s.request.return_value = resp(429, {"error": {"code": "daily_limit", "message": "Daily sending limit reached"}})
        with self.assertRaises(PostaError) as e:
            self.p.mailboxes.send(1, "y@z.dev", "s", text="t")
        self.assertEqual((e.exception.status, e.exception.code), (429, "daily_limit"))

    def test_send_omits_empty_fields(self):
        self.s.request.return_value = resp(202, {"accepted": ["y@z.dev"]})
        self.p.mailboxes.send(1, "y@z.dev", "s", text="t")
        self.assertEqual(self.s.request.call_args[1]["json"], {"to": "y@z.dev", "subject": "s", "text": "t"})

    def test_requires_key(self):
        with mock.patch.dict("os.environ", {}, clear=True), self.assertRaises(ValueError):
            Posta()


class Webhook(unittest.TestCase):
    def test_verify(self):
        body, t = b'{"event":"message.received"}', str(int(time.time()))
        sig = hmac.new(b"s3", t.encode() + b"." + body, hashlib.sha256).hexdigest()
        self.assertTrue(verify_webhook("s3", f"t={t},v1={sig}", body))
        self.assertFalse(verify_webhook("s3", f"t={t},v1={sig}", body + b" "))
        self.assertFalse(verify_webhook("s3", f"t={int(t) - 3600},v1={sig}", body))
        self.assertFalse(verify_webhook("s3", "garbage", body))


RAW = (b"From: Bot <bot@service.example>\r\nTo: agent@x.dev\r\nSubject: Your verification code\r\n"
       b"Date: Sat, 11 Oct 2026 10:00:00 +0000\r\nMessage-ID: <1@service.example>\r\n\r\nCode: 482913\r\n")


class FakeIMAP:
    def __init__(self, uids):
        self.uids, self.selects = list(uids), []

    def login(self, u, p): return "OK", [b""]
    def logout(self): return "BYE", [b""]
    def select(self, box, readonly=False):
        self.selects.append(readonly)
        return "OK", [b"1"]
    def uid(self, cmd, *args):
        if cmd == "SEARCH":
            return "OK", [" ".join(map(str, self.uids)).encode()]
        if cmd == "FETCH":
            assert "PEEK" in args[1]                     # never marks as seen
            return "OK", [(b"1 (UID x BODY[] {n}", RAW), b")"]


class InboxTest(unittest.TestCase):
    def test_wait_for_ignores_old_mail_and_matches_new(self):
        fake = FakeIMAP([1, 2])
        calls = {"n": 0}
        def search_grows(cmd, *a):
            if cmd == "SEARCH":
                calls["n"] += 1
                if calls["n"] > 1:
                    fake.uids = [1, 2, 3]
            return FakeIMAP.uid(fake, cmd, *a)
        fake.uid = search_grows
        with mock.patch("imaplib.IMAP4_SSL", return_value=fake):
            with Inbox("agent@x.dev", "pw") as box:
                msg = box.wait_for(subject_contains="verification", timeout=5, poll=0)
        self.assertEqual((msg.uid, msg.text.strip()), (3, "Code: 482913"))
        self.assertTrue(all(fake.selects))                    # always read-only

    def test_wait_for_times_out(self):
        with mock.patch("imaplib.IMAP4_SSL", return_value=FakeIMAP([1])):
            with Inbox("agent@x.dev", "pw") as box, self.assertRaises(TimeoutError):
                box.wait_for(timeout=0, poll=0)


if __name__ == "__main__":
    unittest.main()
