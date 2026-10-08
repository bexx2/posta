from django.core import mail
from django.test import override_settings
from rest_framework.test import APITestCase

from accounts import services
from accounts.models import TermsAcceptance, User

V = services.TERMS_VERSION
PW = "a-long-enough-pass-9"


@override_settings(EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend")
class AccountFlow(APITestCase):
    def setUp(self):
        from django.core.cache import cache
        cache.clear()                                                  # hız sınırı sayaçları testler arası sızmasın

    def reg(self, email="dev@example.com", pw=PW, ver=V):
        return self.client.post("/v1/auth/register", {"email": email, "password": pw, "accepted_version": ver}, format="json")

    def test_register_sends_mail_and_records_acceptance(self):
        r = self.reg()
        self.assertEqual(r.status_code, 202)
        self.assertEqual(len(mail.outbox), 1)
        u = User.objects.get(email="dev@example.com")
        self.assertFalse(u.is_email_verified)
        self.assertEqual(set(TermsAcceptance.objects.filter(user=u).values_list("document", flat=True)), {"terms", "aup", "privacy_shown"})   # aydınlatma onaylanmaz, gösterildiği kaydedilir
        self.assertTrue(hasattr(u, "membership"))                       # varsayılan plan atandı

    def test_same_response_for_existing_account_and_no_mail(self):
        self.reg()
        u = User.objects.get(email="dev@example.com")
        u.email_verified_at = u.date_joined
        u.save(update_fields=["email_verified_at"])
        mail.outbox.clear()
        r = self.reg()
        self.assertEqual(r.status_code, 202)
        self.assertEqual(r.json(), {"status": "check_your_email"})
        self.assertEqual(len(mail.outbox), 0)                           # doğrulanmış hesaba tekrar mail yok, kullanıcı sayımı yok

    def test_unverified_reregistration_resets_password_and_resends(self):
        self.reg(pw="attacker-chosen-pw-1")                                # biri adresi doğrulamadan kaydetmiş (ya da bağlantı süresi dolmuş)
        mail.outbox.clear()
        r = self.reg(pw=PW)
        self.assertEqual(r.status_code, 202)
        self.assertEqual(len(mail.outbox), 1)                           # doğrulama maili yeniden gider
        u = User.objects.get(email="dev@example.com")
        self.assertTrue(u.check_password(PW))                           # yeni parola geçerli, eskisi değil
        self.assertFalse(u.check_password("attacker-chosen-pw-1"))
        self.assertEqual(TermsAcceptance.objects.filter(user=u).count(), 3)   # kabul kayıtları çoğalmaz, yenilenir
        self.assertEqual(User.objects.filter(email="dev@example.com").count(), 1)

    def test_verification_mail_links_accepted_version(self):
        self.reg()
        body = mail.outbox[0].body
        self.assertIn(f"/terms/{V}", body)
        self.assertIn(f"/aup/{V}", body)
        self.assertIn(f"/tr/terms/{V}", body)
        self.assertIn("/privacy", body)

    def test_rejects_old_terms_version_and_weak_password(self):
        self.assertEqual(self.reg(ver="1999-01-01").json()["error"]["code"], "terms_required")
        self.assertEqual(self.reg(pw="short").json()["error"]["code"], "weak_password")
        self.assertEqual(self.reg(email="nope").json()["error"]["code"], "invalid_email")
        self.assertEqual(self.reg(email="jakob@jamba").json()["error"]["code"], "invalid_email")  # TLD yok

    @override_settings(NOTIFY_EMAIL="ops@example.net")
    def test_operator_notified_on_signup(self):
        with self.captureOnCommitCallbacks(execute=True):
            self.reg()
        to_ops = [m for m in mail.outbox if m.to == ["ops@example.net"]]
        self.assertEqual(len(to_ops), 1)
        self.assertIn("yeni kayıt", to_ops[0].subject)

    def test_login_requires_verified_email(self):
        self.reg()
        r = self.client.post("/v1/auth/login", {"email": "dev@example.com", "password": PW}, format="json")
        self.assertEqual((r.status_code, r.json()["error"]["code"]), (403, "email_not_verified"))
        token = services.make_verify_token(User.objects.get(email="dev@example.com"))
        self.assertEqual(self.client.post("/v1/auth/verify", {"token": token}, format="json").status_code, 200)
        r = self.client.post("/v1/auth/login", {"email": "DEV@example.com", "password": PW}, format="json")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(self.client.get("/v1/me").json()["email"], "dev@example.com")

    def test_wrong_password_and_bad_token(self):
        self.reg()
        r = self.client.post("/v1/auth/login", {"email": "dev@example.com", "password": "wrong-password-1"}, format="json")
        self.assertEqual(r.status_code, 401)
        self.assertEqual(self.client.post("/v1/auth/verify", {"token": "garbage"}, format="json").status_code, 400)

    def test_verify_token_is_bound_to_email(self):
        self.reg()
        u = User.objects.get(email="dev@example.com")
        t = services.make_verify_token(u)
        u.email = "changed@example.com"
        u.save()
        self.assertIsNone(services.read_verify_token(t))                 # e-posta değişince eski bağlantı geçersiz

    def test_me_requires_auth(self):
        self.assertIn(self.client.get("/v1/me").status_code, (401, 403))


class Throttling(APITestCase):
    def setUp(self):
        from django.core.cache import cache
        cache.clear()

    def test_register_is_rate_limited(self):
        codes = []
        for i in range(7):
            codes.append(self.client.post("/v1/auth/register", {"email": f"u{i}@example.com", "password": PW, "accepted_version": V}, format="json").status_code)
        self.assertIn(429, codes)
        self.assertEqual(codes[:5], [202] * 5)
