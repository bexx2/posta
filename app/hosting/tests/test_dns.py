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


class DomainSquatting(TestCase):
    """2026-10-11: bekleyen talep adı kilitlemez; TXT'yi kanıtlayan ilk kişi alır, diğer bekleyenler silinir."""
    def setUp(self):
        from hosting.backends.dryrun import DryRunBackend
        DryRunBackend.instance().reset()
        self.squatter = User.objects.create_user(email="s@example.com", password="x-long-enough-pass-1", email_verified_at=timezone.now())
        self.owner = User.objects.create_user(email="o@example.com", password="x-long-enough-pass-1", email_verified_at=timezone.now())

    def _verify(self, user, d):
        rec = {(d.txt_record["name"], "TXT"): [d.txt_record["value"]], (d.name, "MX"): [f"10 {settings.MX_TARGET}."]}
        with mock.patch("hosting.services._resolve", lambda n, t: rec.get((n, t), [])):
            return services.verify_domain(user, d)

    def test_pending_claim_does_not_block_real_owner(self):
        squat = services.add_domain(self.squatter, "bigco.com")
        real = services.add_domain(self.owner, "bigco.com")             # eskiden domain_taken (409) idi
        self.assertNotEqual(squat.verification_token, real.verification_token)
        self._verify(self.owner, real)
        self.assertFalse(Domain.objects.filter(pk=squat.pk).exists())    # kaybeden bekleyen talep temizlendi
        with self.assertRaises(services.ServiceError) as e:
            services.add_domain(self.squatter, "bigco.com")
        self.assertEqual(e.exception.code, "domain_taken")

    def test_squatter_cannot_verify_with_owners_token(self):
        squat = services.add_domain(self.squatter, "bigco.com")
        real = services.add_domain(self.owner, "bigco.com")
        rec = {(real.txt_record["name"], "TXT"): [real.txt_record["value"]], ("bigco.com", "MX"): [f"10 {settings.MX_TARGET}."]}
        with mock.patch("hosting.services._resolve", lambda n, t: rec.get((n, t), [])):
            services.verify_domain(self.squatter, squat)
        squat.refresh_from_db()
        self.assertEqual(squat.status, Domain.PENDING)                   # kendi token'ı DNS'te yok

    def test_same_owner_twice_is_rejected(self):
        services.add_domain(self.owner, "bigco.com")
        with self.assertRaises(services.ServiceError) as e:
            services.add_domain(self.owner, "bigco.com")
        self.assertEqual(e.exception.code, "domain_exists")
