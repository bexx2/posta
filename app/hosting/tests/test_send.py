import smtplib
from unittest import mock

from django.utils import timezone
from rest_framework.test import APIClient, APITestCase

from accounts.models import User
from hosting import services
from hosting.backends.dryrun import DryRunBackend
from hosting.backends.mailcow import MailcowBackend
from hosting.models import AuditLog, Domain, Mailbox

PW = "a-long-enough-pass-9"


class SendEndpoint(APITestCase):
    """POST /v1/mailboxes/{id}/send (#7)."""
    def setUp(self):
        DryRunBackend.instance().reset()
        self.user = User.objects.create_user(email="dev@example.com", password=PW, email_verified_at=timezone.now())
        self.d = Domain.objects.create(owner=self.user, name="acme.dev", status=Domain.VERIFIED)
        self.mb = Mailbox.objects.create(domain=self.d, local_part="agent", address="agent@acme.dev", quota_mb=500)
        self.c = APIClient()
        _, full = services.create_api_key(self.user, "k", ["mail:send"])
        self.c.credentials(HTTP_AUTHORIZATION=f"Bearer {full}")
        self.url = f"/v1/mailboxes/{self.mb.pk}/send"

    def test_sends_as_the_mailbox(self):
        r = self.c.post(self.url, {"to": "you@example.net", "subject": "Hi", "text": "hello"}, format="json")
        self.assertEqual(r.status_code, 202, r.content)
        self.assertEqual(r.json()["accepted"], ["you@example.net"])
        self.assertTrue(r.json()["message_id"].endswith("@acme.dev>"))
        with mock.patch.object(DryRunBackend, "submit", return_value={}) as sub:
            self.c.post(self.url, {"to": "you@example.net", "subject": "Hi", "text": "x"}, format="json")
        self.assertTrue(sub.call_args[0][1]["Date"])                    # Date başlığı şart
        self.assertIn(("submit", "agent@acme.dev", "you@example.net", "Hi"), DryRunBackend.instance().ops)
        self.assertTrue(AuditLog.objects.filter(action="mail.send", object_ref="agent@acme.dev").exists())

    def test_scope_required(self):
        _, full = services.create_api_key(self.user, "ro", ["mailboxes:read"])
        c = APIClient()
        c.credentials(HTTP_AUTHORIZATION=f"Bearer {full}")
        self.assertEqual(c.post(self.url, {"to": "you@example.net", "subject": "Hi", "text": "x"}, format="json").status_code, 403)

    def test_validation(self):
        for body, code in [({"to": "nope", "subject": "Hi", "text": "x"}, "invalid_recipients"),
                           ({"to": [f"u{i}@example.net" for i in range(11)], "subject": "Hi", "text": "x"}, "invalid_recipients"),
                           ({"to": "you@example.net", "subject": "", "text": "x"}, "invalid_message"),
                           ({"to": "you@example.net", "subject": "Hi"}, "invalid_message")]:
            r = self.c.post(self.url, body, format="json")
            self.assertEqual(r.json()["error"]["code"], code, body)

    def test_header_injection_in_subject_is_flattened(self):
        self.c.post(self.url, {"to": "you@example.net", "subject": "Hi\r\nBcc: victim@example.org", "text": "x"}, format="json")
        sent = [o for o in DryRunBackend.instance().ops if o[0] == "submit"][-1]
        self.assertNotIn("\n", sent[3])

    def test_other_users_mailbox_is_404(self):
        other = User.objects.create_user(email="o@example.com", password=PW, email_verified_at=timezone.now())
        d2 = Domain.objects.create(owner=other, name="other.dev", status=Domain.VERIFIED)
        mb2 = Mailbox.objects.create(domain=d2, local_part="x", address="x@other.dev", quota_mb=500)
        r = self.c.post(f"/v1/mailboxes/{mb2.pk}/send", {"to": "you@example.net", "subject": "Hi", "text": "x"}, format="json")
        self.assertEqual(r.status_code, 404)

    def test_suspended_mailbox_cannot_send(self):
        Mailbox.objects.filter(pk=self.mb.pk).update(status=Mailbox.SUSPENDED)
        r = self.c.post(self.url, {"to": "you@example.net", "subject": "Hi", "text": "x"}, format="json")
        self.assertEqual(r.json()["error"]["code"], "mailbox_suspended")

    def test_daily_limit_maps_to_429(self):
        err = smtplib.SMTPDataError(451, b"4.7.1 Ratelimit exceeded")
        with mock.patch.object(DryRunBackend, "submit", side_effect=err):
            r = self.c.post(self.url, {"to": "you@example.net", "subject": "Hi", "text": "x"}, format="json")
        self.assertEqual((r.status_code, r.json()["error"]["code"]), (429, "daily_limit"))


class MailcowSubmitCleansUp(APITestCase):
    def test_app_password_is_smtp_only_and_deleted_even_on_failure(self):
        be = MailcowBackend("https://127.0.0.1/api/v1", "k")
        calls = []
        def fake_call(method, path, payload=None):
            calls.append((method, path, payload))
            if path.startswith("get/app-passwd"):
                name = next(c[2]["app_name"] for c in calls if c[1] == "add/app-passwd")
                return [{"id": 7, "name": name}, {"id": 8, "name": "customer-own"}]
            return [{"type": "success"}]
        with mock.patch.object(be, "_call", side_effect=fake_call), mock.patch("smtplib.SMTP", side_effect=OSError("down")):
            with self.assertRaises(OSError):
                be.submit("agent@acme.dev", object())
        add = next(c for c in calls if c[1] == "add/app-passwd")
        self.assertEqual(add[2]["protocols"], ["smtp_access"])
        self.assertIn(("POST", "delete/app-passwd", [7]), calls)      # yalnız kendi geçici parolası; müşterinin parolasına dokunmaz


class MailcowSendLimit(APITestCase):
    def test_limit_uses_rl_mbox_and_is_read_back(self):
        """🐞 2026-10-11: edit/mailbox rl_* alanlarını sessizce yoksayıyordu → hiçbir kutuda sınır yoktu."""
        be = MailcowBackend("https://127.0.0.1/api/v1", "k")
        calls = []
        def fake(method, path, payload=None):
            calls.append((method, path, payload))
            return {"value": "50", "frame": "d"} if path.startswith("get/rl-mbox") else [{"type": "success"}]
        with mock.patch.object(be, "_call", side_effect=fake):
            be.add_mailbox("agent@acme.dev", "pw", 500, 50)
        self.assertIn(("POST", "edit/rl-mbox", {"items": ["agent@acme.dev"], "attr": {"rl_value": "50", "rl_frame": "d"}}), calls)
        self.assertFalse(any(c[1] == "edit/mailbox" and "rl_value" in str(c[2]) for c in calls))

    def test_limit_not_applied_is_an_error(self):
        be = MailcowBackend("https://127.0.0.1/api/v1", "k")
        with mock.patch.object(be, "_call", side_effect=lambda m, p, d=None: [] if p.startswith("get/rl-mbox") else [{"type": "success"}]):
            with self.assertRaises(Exception):
                be.set_send_limit("agent@acme.dev", 50)
