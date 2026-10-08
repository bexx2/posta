from unittest import mock

from django.core import mail
from django.core.cache import cache
from django.test import TestCase, override_settings
from django.utils import timezone

from accounts import services as acc
from accounts.models import User
from hosting.backends.dryrun import DryRunBackend
from hosting.models import ApiKey, Domain, Mailbox, UpgradeRequest

PW = "correct-horse-battery"


@override_settings(EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend", MAIL_BACKEND="dryrun")
class PanelFlow(TestCase):
    def setUp(self):
        cache.clear()
        DryRunBackend.instance().reset()

    def _user(self, email="a@example.com"):
        u = User.objects.create_user(email=email, password=PW)
        u.email_verified_at = timezone.now()
        u.save()
        return u

    def _login(self, email="a@example.com"):
        self.client.post("/app/login/", {"email": email, "password": PW})

    def _verified_domain(self, user, name="acme.dev"):
        d = Domain.objects.create(owner=user, name=name)
        ok = {"ownership_txt": True, "mx": True, "spf": False, "dmarc": False, "dkim": False}
        with mock.patch("hosting.services.check_dns", return_value=ok):
            self.client.post(f"/app/domains/{d.pk}/verify/")
        d.refresh_from_db()
        return d

    def test_register_verify_login(self):
        r = self.client.post("/app/register/", {"email": "n@example.com", "password": PW, "password2": PW, "accept": "on"})
        self.assertContains(r, "Check your email")
        self.assertEqual(len(mail.outbox), 1)
        r = self.client.post("/app/login/", {"email": "n@example.com", "password": PW})
        self.assertContains(r, "Confirm your email", status_code=401)                   # doğrulanmadan giriş yok
        link = [w for w in mail.outbox[0].body.split() if "/app/verify/" in w][0]
        self.assertEqual(self.client.get(link.replace("https://posta.preved.co", "")).status_code, 200)
        r = self.client.post("/app/login/", {"email": "n@example.com", "password": PW})
        self.assertEqual(r.status_code, 302)

    def test_register_needs_terms_and_matching_passwords(self):
        r = self.client.post("/app/register/", {"email": "n@example.com", "password": PW, "password2": PW})
        self.assertContains(r, "must accept")
        r = self.client.post("/app/register/", {"email": "n@example.com", "password": PW, "password2": PW + "x", "accept": "on"})
        self.assertContains(r, "do not match")
        self.assertFalse(User.objects.filter(email="n@example.com").exists())

    def test_register_same_response_for_existing_email(self):
        self._user("dup@example.com")
        r = self.client.post("/app/register/", {"email": "dup@example.com", "password": PW, "password2": PW, "accept": "on"})
        self.assertContains(r, "Check your email")
        self.assertEqual(len(mail.outbox), 0)

    def test_pages_need_login(self):
        for url in ("/app/", "/app/keys/", "/app/upgrade/"):
            self.assertEqual(self.client.get(url).status_code, 302)

    def test_free_plan_one_domain_one_mailbox_then_paid_request(self):
        u = self._user()
        self._login()
        self.assertContains(self.client.get("/app/"), "Add a domain")
        d = self._verified_domain(u)
        self.assertEqual(d.status, Domain.VERIFIED)
        r = self.client.post(f"/app/domains/{d.pk}/mailboxes/", {"local": "agent", "password": PW}, follow=True)
        self.assertContains(r, "agent@acme.dev is ready")
        self.assertEqual(Mailbox.objects.count(), 1)
        page = self.client.get(f"/app/domains/{d.pk}/")
        self.assertContains(page, "Free plan includes 1 mailbox")
        self.assertNotContains(page, 'name="local"')                    # ikinci kutu formu yok
        r = self.client.post(f"/app/domains/{d.pk}/mailboxes/", {"local": "two", "password": PW}, follow=True)   # elle zorlama
        self.assertContains(r, "allows 1 mailbox")
        self.assertEqual(Mailbox.objects.count(), 1)
        r = self.client.post("/app/domains/add/", {"name": "second.dev"}, follow=True)
        self.assertContains(r, "allows 1 domain")
        r = self.client.post("/app/upgrade/", {"kind": "mailboxes", "quantity": "5", "note": "agents"}, follow=True)
        self.assertContains(r, "Nothing is charged")
        self.assertEqual(UpgradeRequest.objects.get().quantity, 5)

    def test_upgrade_validation_and_cap(self):
        self._user()
        self._login()
        for qty in ("0", "101", "x"):
            self.client.post("/app/upgrade/", {"kind": "mailboxes", "quantity": qty})
        self.assertEqual(UpgradeRequest.objects.count(), 0)
        for _ in range(4):
            self.client.post("/app/upgrade/", {"kind": "mailboxes", "quantity": "2"})
        self.assertEqual(UpgradeRequest.objects.count(), 3)

    def test_unverified_domain_gets_no_mailbox(self):
        u = self._user()
        self._login()
        d = Domain.objects.create(owner=u, name="nope.dev")
        r = self.client.post(f"/app/domains/{d.pk}/mailboxes/", {"local": "x", "password": PW}, follow=True)
        self.assertContains(r, "Verify the domain first")
        self.assertEqual(Mailbox.objects.count(), 0)

    def test_dns_not_ready_keeps_pending(self):
        u = self._user()
        self._login()
        d = Domain.objects.create(owner=u, name="wait.dev")
        bad = {"ownership_txt": False, "mx": False, "spf": False, "dmarc": False, "dkim": False}
        with mock.patch("hosting.services.check_dns", return_value=bad):
            r = self.client.post(f"/app/domains/{d.pk}/verify/", follow=True)
        d.refresh_from_db()
        self.assertEqual(d.status, Domain.PENDING)
        self.assertContains(r, "Not verified yet")

    def test_wizard_shows_per_record_status_and_progress(self):
        u = self._user()
        self._login()
        d = Domain.objects.create(owner=u, name="half.dev")
        r = self.client.get(f"/app/domains/{d.pk}/")
        self.assertContains(r, "not checked")                            # henüz kontrol yok
        self.assertNotContains(r, "required records found")
        half = {"ownership_txt": True, "mx": False, "spf": False, "dmarc": False, "dkim": False}
        with mock.patch("hosting.services.check_dns", return_value=half):
            r = self.client.post(f"/app/domains/{d.pk}/verify/", follow=True)
        self.assertContains(r, "1 of 2 required records found")
        self.assertContains(r, "✘ missing")                              # MX eksik
        self.assertContains(r, "Remove old MX records")                  # ipucu yalnız eksik satırda
        self.assertNotContains(r, "Not found yet. Add this exact TXT")   # sahiplik bulundu, ipucu yok

    def test_other_users_objects_are_404(self):
        a, b = self._user("a@example.com"), self._user("b@example.com")
        da = self._verified_domain(a)
        self._login("b@example.com")
        self.assertEqual(self.client.get(f"/app/domains/{da.pk}/").status_code, 404)
        self.assertEqual(self.client.post(f"/app/domains/{da.pk}/verify/").status_code, 404)
        self.assertEqual(self.client.post(f"/app/domains/{da.pk}/delete/", {"confirm": da.name}).status_code, 404)

    def test_delete_requires_typed_confirmation(self):
        u = self._user()
        self._login()
        d = self._verified_domain(u)
        self.client.post(f"/app/domains/{d.pk}/delete/", {"confirm": "wrong"})
        self.assertTrue(Domain.objects.filter(pk=d.pk).exists())
        self.client.post(f"/app/domains/{d.pk}/delete/", {"confirm": d.name})
        self.assertFalse(Domain.objects.filter(pk=d.pk).exists())

    def test_api_key_shown_once_and_works(self):
        self._user()
        self._login()
        r = self.client.post("/app/keys/new/", {"name": "agent", "scopes": ["domains:read"]})
        full = r.content.decode().split("user-select:all;font-size:1rem\">")[1].split("<")[0]
        self.assertTrue(full.startswith("pk_") or len(full) > 20)
        self.assertNotContains(self.client.get("/app/keys/"), full)     # listede tam anahtar yok
        self.client.logout()
        self.assertEqual(self.client.get("/v1/domains", HTTP_AUTHORIZATION=f"Bearer {full}").status_code, 200)
        self.assertEqual(ApiKey.objects.count(), 1)

    def test_login_throttle(self):
        for _ in range(12):
            r = self.client.post("/app/login/", {"email": "x@example.com", "password": "bad"})
        self.assertContains(r, "Too many attempts")

    def test_logout_is_post_only(self):
        self._user()
        self._login()
        self.assertEqual(self.client.get("/app/logout/").status_code, 405)
        self.client.post("/app/logout/")
        self.assertEqual(self.client.get("/app/").status_code, 302)


@override_settings(EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend", MAIL_BACKEND="dryrun")
class PasswordReset(TestCase):
    def setUp(self):
        cache.clear()
        self.u = User.objects.create_user(email="r@example.com", password=PW)
        self.u.email_verified_at = timezone.now()
        self.u.save()

    def _link(self):
        return [w for w in mail.outbox[-1].body.split() if "/app/reset/" in w][0].replace("https://posta.preved.co", "")

    def test_reset_flow_and_single_use(self):
        r = self.client.post("/app/forgot/", {"email": "r@example.com"})
        self.assertContains(r, "Check your email")
        link = self._link()
        self.assertEqual(self.client.get(link).status_code, 200)
        new = "another-long-passphrase-1"
        r = self.client.post(link, {"password": new, "password2": new})
        self.assertEqual(r.status_code, 302)
        self.assertEqual(self.client.post("/app/login/", {"email": "r@example.com", "password": new}).status_code, 302)
        self.assertEqual(self.client.get(link).status_code, 400)          # tek kullanımlık

    def test_unknown_and_unverified_get_same_answer_no_mail(self):
        User.objects.create_user(email="u@example.com", password=PW)      # doğrulanmamış
        for e in ("nobody@example.com", "u@example.com"):
            self.assertContains(self.client.post("/app/forgot/", {"email": e}), "Check your email")
        self.assertEqual(len(mail.outbox), 0)

    def test_bad_token_and_weak_or_mismatched_password(self):
        self.assertEqual(self.client.get("/app/reset/garbage/").status_code, 400)
        self.client.post("/app/forgot/", {"email": "r@example.com"})
        link = self._link()
        self.assertContains(self.client.post(link, {"password": "x", "password2": "y"}), "do not match")
        self.assertContains(self.client.post(link, {"password": "short", "password2": "short"}), "too short")
        self.assertEqual(self.client.get(link).status_code, 200)          # hâlâ geçerli


from django.test import override_settings
from django.core.exceptions import ValidationError as _VE
from hosting.models import normalize_domain as _nd


class ReservedDomainTests(TestCase):
    def test_reserved_blocked_including_subdomains(self):
        for d in ("heyvaql.com", "x.preved.co"):
            with self.assertRaises(_VE):
                _nd(d)

    @override_settings(RESERVED_DOMAIN_EXCEPTIONS=["demo.preved.co"])
    def test_exception_allows_exact_name_only(self):
        self.assertEqual(_nd("Demo.preved.co"), "demo.preved.co")
        with self.assertRaises(_VE):
            _nd("other.preved.co")
