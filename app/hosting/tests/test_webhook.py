import json
import socket
from io import StringIO
from unittest import mock

from django.core import mail
from django.core.management import call_command
from django.test import override_settings
from django.utils import timezone
from rest_framework.test import APIClient, APITestCase

from accounts.models import User
from hosting import services
from hosting.backends.dryrun import DryRunBackend
from hosting.models import Domain, Mailbox

PW = "a-long-enough-pass-9"
PUBLIC = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))]


def resolves_to(ip):
    return mock.patch("socket.getaddrinfo", return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 443))])


@override_settings(EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend")
class Webhook(APITestCase):
    def setUp(self):
        self.be = DryRunBackend.instance()
        self.be.reset()
        self.user = User.objects.create_user(email="dev@example.com", password=PW, email_verified_at=timezone.now())
        d = Domain.objects.create(owner=self.user, name="acme.dev", status=Domain.VERIFIED)
        self.mb = Mailbox.objects.create(domain=d, local_part="agent", address="agent@acme.dev", quota_mb=500)
        self.c = APIClient()
        _, full = services.create_api_key(self.user, "k", ["mailboxes:read", "mailboxes:write"])
        self.c.credentials(HTTP_AUTHORIZATION=f"Bearer {full}")
        self.url = f"/v1/mailboxes/{self.mb.pk}/webhook"
        self.be.counts["agent@acme.dev"] = 3

    def put(self, url="https://hooks.example.net/in"):
        with resolves_to("93.184.216.34"):
            return self.c.put(self.url, {"url": url}, format="json")

    def watch(self, status=200):
        posted, self.pools = [], []
        def fake_pool(host, **kw):
            self.pools.append((host, kw))
            p = mock.Mock()
            def urlopen(method, path, body=None, headers=None, **k):
                posted.append((path, body, headers))
                return mock.Mock(status=status)
            p.urlopen.side_effect = urlopen
            return p
        with resolves_to("93.184.216.34"), mock.patch("urllib3.HTTPSConnectionPool", side_effect=fake_pool):
            call_command("webhook_watch", stdout=StringIO(), stderr=StringIO())
        self.mb.refresh_from_db()
        return posted

    def test_ssrf_guard(self):
        for ip in ("127.0.0.1", "10.0.0.5", "169.254.169.254", "172.22.1.1", "::1"):
            with mock.patch("socket.getaddrinfo", return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 443))]):
                r = self.c.put(self.url, {"url": "https://evil.example/x"}, format="json")
            self.assertEqual(r.json()["error"]["code"], "invalid_webhook_url", ip)
        r = self.c.put(self.url, {"url": "http://hooks.example.net/in"}, format="json")
        self.assertEqual(r.json()["error"]["code"], "invalid_webhook_url")

    def test_existing_mail_is_not_reported_new_mail_is_signed(self):
        r = self.put()
        self.assertEqual(r.status_code, 200)
        secret = r.json()["secret"]
        self.assertEqual(self.watch(), [])                       # 3 eski ileti bildirilmez
        self.be.counts["agent@acme.dev"] = 5
        posted = self.watch()
        self.assertEqual(len(posted), 1)
        url, body, headers = posted[0]
        p = json.loads(body)
        self.assertEqual((p["event"], p["mailbox"], p["new_messages"]), ("message.received", "agent@acme.dev", 2))
        self.assertNotIn("subject", p)                          # içerik yok
        t, v1 = [x.split("=", 1)[1] for x in headers["Posta-Signature"].split(",")]
        self.assertEqual(v1, services.webhook_signature(secret, t, body))
        self.assertNotIn("secret", self.c.get(self.url).json())

    def test_failed_delivery_retries_then_disables_and_tells_owner(self):
        self.put()
        self.be.counts["agent@acme.dev"] = 4
        self.watch(status=500)
        self.assertEqual((self.mb.webhook_pending, self.mb.webhook_fails), (1, 1))
        Mailbox.objects.filter(pk=self.mb.pk).update(webhook_fails=services.WEBHOOK_DISABLE_AFTER - 1)
        self.watch(status=500)
        self.assertIsNotNone(self.mb.webhook_disabled_at)
        self.assertTrue(any("turned off" in m.subject for m in mail.outbox))
        self.assertEqual(self.watch(), [])                      # kapalı: artık denenmez

    def test_connection_is_pinned_to_the_checked_ip(self):
        self.put()
        self.be.counts["agent@acme.dev"] = 4
        path, _, headers = self.watch()[0]
        host, kw = self.pools[0]
        self.assertEqual(host, "93.184.216.34")                                  # DNS tekrar çözülmez (rebinding)
        self.assertEqual((kw["server_hostname"], kw["assert_hostname"]), ("hooks.example.net", "hooks.example.net"))
        self.assertEqual((path, headers["Host"]), ("/in", "hooks.example.net"))

    def test_deleted_mail_lowers_baseline(self):
        self.put()
        self.be.counts["agent@acme.dev"] = 1
        self.assertEqual(self.watch(), [])
        self.be.counts["agent@acme.dev"] = 2
        self.assertEqual(json.loads(self.watch()[0][1])["new_messages"], 1)

    def test_delete_webhook(self):
        self.put()
        self.assertEqual(self.c.delete(self.url).status_code, 204)
        self.assertIsNone(self.c.get(self.url).json()["url"])
