from datetime import timedelta
from io import StringIO
from unittest import mock

from django.conf import settings
from django.core import mail
from django.core.management import call_command
from django.test import TestCase, override_settings
from django.utils import timezone

from accounts.models import User
from hosting.backends.dryrun import DryRunBackend
from hosting.models import Domain

MAILCFG = dict(EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend", NOTIFY_EMAIL="ops@example.net")


def fake(records):
    return lambda name, rtype: records.get((name, rtype), [])


@override_settings(**MAILCFG)
class DnsWatch(TestCase):
    def setUp(self):
        DryRunBackend.instance().reset()
        self.u = User.objects.create_user(email="d@example.com", password="x-long-enough-pass-1", email_verified_at=timezone.now())
        self.d = Domain.objects.create(owner=self.u, name="acme.dev", created_at=timezone.now() - timedelta(hours=2))

    def ok(self, mx=None):
        return {("_posta-verify.acme.dev", "TXT"): [self.d.txt_record["value"]],
                ("acme.dev", "MX"): [f"10 {mx or settings.MX_TARGET}."]}

    def run_watch(self, rec, *args):
        out = StringIO()
        with self.captureOnCommitCallbacks(execute=True), mock.patch("hosting.services._resolve", fake(rec)):
            call_command("dns_watch", "--force", *args, stdout=out)
        self.d.refresh_from_db()
        return out.getvalue()

    def test_pending_auto_verifies_when_dns_ready(self):
        self.run_watch(self.ok())
        self.assertEqual(self.d.status, Domain.VERIFIED)
        self.assertEqual(self.d.watch, {})

    @override_settings(DNS_NUDGE_MAIL=False)
    def test_nudge_off_sends_no_customer_mail(self):
        out = self.run_watch({})
        self.assertIn("mail kapalı", out)
        self.assertEqual([m for m in mail.outbox if self.u.email in m.to], [])

    @override_settings(DNS_NUDGE_MAIL=True)
    def test_setup_nudge_at_most_twice(self):
        wrong = {("acme.dev", "MX"): ["10 posta.preved.co."]}
        self.run_watch(wrong)
        sent = [m for m in mail.outbox if self.u.email in m.to]
        self.assertEqual(len(sent), 1)
        self.assertIn("with “mail.” in front", sent[0].body)          # panel ipucu maile de girer
        self.assertEqual(sent[0].reply_to, ["merhaba@preved.co"])
        self.run_watch(wrong)                                           # 24 saat dolmadan ikinci yok
        self.assertEqual(len([m for m in mail.outbox if self.u.email in m.to]), 1)
        w = self.d.watch
        w["setup"]["sent"] = [(timezone.now() - timedelta(hours=25)).isoformat()]
        Domain.objects.filter(pk=self.d.pk).update(watch=w)
        self.run_watch(wrong)
        self.run_watch(wrong)
        self.assertEqual(len([m for m in mail.outbox if self.u.email in m.to]), 2)

    def test_verified_domain_losing_mx_is_flagged_and_operator_told(self):
        self.run_watch(self.ok())
        mail.outbox.clear()
        self.run_watch(self.ok(mx="route1.mx.cloudflare.net"))
        self.assertEqual(self.d.status, Domain.VERIFIED)                 # kutular bozulmaz, yalnız işaretlenir
        self.assertIn("mx_lost", self.d.watch)
        self.assertTrue(any("MX kayboldu" in m.subject for m in mail.outbox))
        page = self._page()
        self.assertContains(page, "Incoming mail is not reaching your mailboxes")
        self.assertContains(page, "route1.mx.cloudflare.net")
        self.run_watch(self.ok())                                       # düzelince kayıt temizlenir
        self.assertNotIn("mx_lost", self.d.watch)

    def test_dry_run_changes_nothing(self):
        self.run_watch(self.ok(), "--dry-run")
        self.assertEqual(self.d.status, Domain.PENDING)
        self.assertEqual(self.d.watch, {})

    def _page(self):
        from django.test import Client
        c = Client()
        c.force_login(self.u)
        return c.get(f"/app/domains/{self.d.pk}/")
