from django.conf import settings
from django.test import override_settings
from unittest import mock

from django.test import TestCase
from django.utils import timezone

from accounts.models import User
from hosting import services
from hosting.models import Domain


@override_settings(SPF_INCLUDE_IP="203.0.113.10")
class DnsChecks(TestCase):
    def setUp(self):
        u = User.objects.create_user(email="d@example.com", password="x-long-enough-pass-1", email_verified_at=timezone.now())
        self.d = Domain.objects.create(owner=u, name="acme.dev", dkim_txt="v=DKIM1;k=rsa;p=ABC")

    def fake(self, records):
        return lambda name, rtype: records.get((name, rtype), [])

    def test_all_good(self):
        rec = {("_posta-verify.acme.dev", "TXT"): [self.d.txt_record["value"]],
               ("acme.dev", "MX"): [f"10 {settings.MX_TARGET}."],
               ("acme.dev", "TXT"): ["v=spf1 ip4:203.0.113.10 -all"],
               ("_dmarc.acme.dev", "TXT"): ["v=DMARC1; p=quarantine"],
               ("posta._domainkey.acme.dev", "TXT"): ["v=DKIM1;k=rsa;p=ABC"]}
        with mock.patch("hosting.services._resolve", self.fake(rec)):
            self.assertEqual(services.check_dns(self.d), {"ownership_txt": True, "mx": True, "spf": True, "dmarc": True, "dkim": True})

    def test_wrong_token_and_wrong_mx(self):
        rec = {("_posta-verify.acme.dev", "TXT"): ["posta-verify=someone-elses-token"], ("acme.dev", "MX"): ["10 mx.google.com."]}
        with mock.patch("hosting.services._resolve", self.fake(rec)):
            r = services.check_dns(self.d)
        self.assertFalse(r["ownership_txt"])
        self.assertFalse(r["mx"])

    def test_spf_must_authorize_our_ip(self):
        rec = {("acme.dev", "TXT"): ["v=spf1 include:_spf.google.com -all"]}
        with mock.patch("hosting.services._resolve", self.fake(rec)):
            self.assertFalse(services.check_dns(self.d)["spf"])

    def test_nothing_published(self):
        with mock.patch("hosting.services._resolve", self.fake({})):
            self.assertEqual(set(services.check_dns(self.d).values()), {False})

    def test_domain_stays_pending_until_dns_ok_then_verifies_once(self):
        user = self.d.owner
        from hosting.models import Plan, Membership
        Membership.objects.get_or_create(user=user, defaults={"plan": Plan.objects.get(slug="free")})
        with mock.patch("hosting.services._resolve", self.fake({})):
            self.assertEqual(services.verify_domain(user, self.d).status, "pending")
        rec = {("_posta-verify.acme.dev", "TXT"): [self.d.txt_record["value"]], ("acme.dev", "MX"): [f"10 {settings.MX_TARGET}."]}
        with mock.patch("hosting.services._resolve", self.fake(rec)):
            self.assertEqual(services.verify_domain(user, self.d).status, "verified")
            first = self.d.verified_at
            self.assertEqual(services.verify_domain(user, self.d).verified_at, first)    # ikinci kez yeniden hazırlamaz
