from unittest import mock

from django.utils import timezone
from rest_framework.test import APIClient, APITestCase

from accounts.models import User
from hosting import services
from hosting.backends.dryrun import DryRunBackend
from hosting.models import ApiKey, AuditLog, Domain, Mailbox, normalize_domain
from django.core.exceptions import ValidationError

PW = "a-long-enough-pass-9"


def make_user(email="dev@example.com"):
    return User.objects.create_user(email=email, password=PW, email_verified_at=timezone.now())


def session_client(user):
    c = APIClient()
    c.force_login(user)
    return c


class DomainNormalization(APITestCase):
    def test_normalize(self):
        self.assertEqual(normalize_domain(" Example.COM. "), "example.com")
        self.assertEqual(normalize_domain("bücher.de"), "xn--bcher-kva.de")

    def test_rejects_bad_and_reserved(self):
        for bad in ["", "localhost", "a", "foo..bar", "-x.com", "user@x.com", "x.com/path", "1.2.3.4", "heyvaql.com", "mail.preved.co", "a b.com"]:
            with self.assertRaises(ValidationError, msg=bad):
                normalize_domain(bad)


class HostingFlow(APITestCase):
    def setUp(self):
        DryRunBackend.instance().reset()
        self.user = make_user()
        self.c = session_client(self.user)

    def add_verified_domain(self, name="acme.dev"):
        d = self.c.post("/v1/domains", {"name": name}, format="json").json()
        ok = {"ownership_txt": True, "mx": True, "spf": False, "dmarc": False, "dkim": False}
        with mock.patch("hosting.services.check_dns", return_value=ok):
            return self.c.post(f"/v1/domains/{d['id']}/verify").json()

    def test_domain_add_shows_dns_instructions(self):
        r = self.c.post("/v1/domains", {"name": "Acme.dev"}, format="json")
        self.assertEqual(r.status_code, 201)
        j = r.json()
        self.assertEqual(j["name"], "acme.dev")
        self.assertEqual(j["status"], "pending")
        self.assertTrue(j["dns"]["ownership_txt"]["value"].startswith("posta-verify="))
        self.assertEqual(j["dns"]["ownership_txt"]["name"], "_posta-verify.acme.dev")

    def test_plan_limit_and_duplicates(self):
        self.c.post("/v1/domains", {"name": "one.dev"}, format="json")
        r = self.c.post("/v1/domains", {"name": "two.dev"}, format="json")
        self.assertEqual((r.status_code, r.json()["error"]["code"]), (403, "plan_limit"))
        other = session_client(make_user("other@example.com"))
        r = other.post("/v1/domains", {"name": "one.dev"}, format="json")
        self.assertEqual((r.status_code, r.json()["error"]["code"]), (409, "domain_taken"))

    def test_mailbox_needs_verified_domain(self):
        d = self.c.post("/v1/domains", {"name": "acme.dev"}, format="json").json()
        r = self.c.post("/v1/mailboxes", {"domain_id": d["id"], "local_part": "agent", "password": PW}, format="json")
        self.assertEqual((r.status_code, r.json()["error"]["code"]), (403, "domain_not_verified"))
        self.assertEqual(DryRunBackend.instance().ops, [])               # backend'e HİÇBİR şey gitmedi

    def test_verification_failure_keeps_pending(self):
        d = self.c.post("/v1/domains", {"name": "acme.dev"}, format="json").json()
        bad = {"ownership_txt": False, "mx": True, "spf": False, "dmarc": False, "dkim": False}
        with mock.patch("hosting.services.check_dns", return_value=bad):
            j = self.c.post(f"/v1/domains/{d['id']}/verify").json()
        self.assertEqual(j["status"], "pending")
        self.assertFalse(j["last_check"]["ownership_txt"])

    def test_full_flow_create_and_delete_mailbox(self):
        d = self.add_verified_domain()
        self.assertEqual(d["status"], "verified")
        self.assertEqual(d["dns"]["dkim"]["name"], "posta._domainkey.acme.dev")
        r = self.c.post("/v1/mailboxes", {"domain_id": d["id"], "local_part": "Agent", "password": PW}, format="json")
        self.assertEqual(r.status_code, 201)
        self.assertEqual(r.json()["address"], "agent@acme.dev")
        ops = [o[0] for o in DryRunBackend.instance().ops]
        self.assertEqual(ops, ["add_domain", "dkim", "add_mailbox"])
        self.assertNotIn(PW, str(DryRunBackend.instance().ops))          # parola kaydedilmez
        self.assertEqual(self.c.delete(f"/v1/mailboxes/{r.json()['id']}").status_code, 204)
        self.assertFalse(Mailbox.objects.exists())
        self.assertEqual(list(AuditLog.objects.values_list("action", flat=True)),
                         ["domain.add", "domain.verify", "mailbox.create", "mailbox.delete"])

    def test_mailbox_validation_and_limit(self):
        d = self.add_verified_domain()
        mk = lambda lp, pw=PW: self.c.post("/v1/mailboxes", {"domain_id": d["id"], "local_part": lp, "password": pw}, format="json")
        for bad in ["postmaster", "Abuse", "a..b", "-x", "x y", "a/b"]:
            self.assertEqual(mk(bad).json()["error"]["code"], "invalid_local_part", bad)
        self.assertEqual(mk("ok", "short").json()["error"]["code"], "weak_password")
        self.assertEqual(mk("a1").status_code, 201)                          # ücretsiz plan: alan adı başına 1 kutu
        self.assertEqual(mk("a4").json()["error"]["code"], "plan_limit")
        self.assertEqual(mk("a1").json()["error"]["code"], "plan_limit")     # limit önce

    def test_cannot_touch_other_users_resources(self):
        d = self.add_verified_domain()
        other = session_client(make_user("other@example.com"))
        self.assertEqual(other.get(f"/v1/domains/{d['id']}").status_code, 404)
        self.assertEqual(other.post(f"/v1/domains/{d['id']}/verify").status_code, 404)
        self.assertEqual(other.delete(f"/v1/domains/{d['id']}").status_code, 404)
        r = other.post("/v1/mailboxes", {"domain_id": d["id"], "local_part": "x", "password": PW}, format="json")
        self.assertEqual(r.status_code, 404)

    def test_delete_domain_removes_mailboxes_in_backend(self):
        d = self.add_verified_domain()
        self.c.post("/v1/mailboxes", {"domain_id": d["id"], "local_part": "a", "password": PW}, format="json")
        DryRunBackend.instance().reset()
        self.assertEqual(self.c.delete(f"/v1/domains/{d['id']}").status_code, 204)
        self.assertEqual([o[0] for o in DryRunBackend.instance().ops], ["delete_mailbox", "delete_domain"])
        self.assertFalse(Domain.objects.exists())

    def test_unauthenticated_is_rejected(self):
        self.assertIn(APIClient().get("/v1/domains").status_code, (401, 403))


class ApiKeys(APITestCase):
    def setUp(self):
        DryRunBackend.instance().reset()
        self.user = make_user()
        self.c = session_client(self.user)

    def new_key(self, scopes):
        r = self.c.post("/v1/keys", {"name": "ci", "scopes": scopes}, format="json")
        self.assertEqual(r.status_code, 201, r.content)
        return r.json()

    def bearer(self, key):
        c = APIClient()
        c.credentials(HTTP_AUTHORIZATION=f"Bearer {key}")
        return c

    def test_key_shown_once_and_only_hash_stored(self):
        k = self.new_key(["domains:read"])
        self.assertTrue(k["key"].startswith("pk_live_"))
        row = ApiKey.objects.get(pk=k["id"])
        self.assertNotIn(k["key"], (row.key_hash, row.prefix))
        self.assertEqual(len(row.key_hash), 64)
        listing = self.c.get("/v1/keys").json()
        self.assertNotIn("key", listing[0])

    def test_scopes_enforced(self):
        k = self.new_key(["domains:read"])
        b = self.bearer(k["key"])
        self.assertEqual(b.get("/v1/domains").status_code, 200)
        self.assertEqual(b.post("/v1/domains", {"name": "acme.dev"}, format="json").status_code, 403)
        self.assertEqual(b.get("/v1/mailboxes").status_code, 403)

    def test_key_cannot_manage_keys(self):
        k = self.new_key(["domains:read", "domains:write", "mailboxes:read", "mailboxes:write"])
        b = self.bearer(k["key"])
        self.assertIn(b.get("/v1/keys").status_code, (401, 403))
        self.assertIn(b.post("/v1/keys", {"name": "x", "scopes": ["domains:read"]}, format="json").status_code, (401, 403))

    def test_revoked_and_wrong_keys_rejected(self):
        k = self.new_key(["domains:read"])
        b = self.bearer(k["key"])
        self.assertEqual(b.get("/v1/domains").status_code, 200)
        self.assertEqual(self.c.delete(f"/v1/keys/{k['id']}").status_code, 204)
        self.assertIn(b.get("/v1/domains").status_code, (401, 403))
        tampered = k["key"][:-3] + ("aaa" if not k["key"].endswith("aaa") else "bbb")
        self.assertIn(self.bearer(tampered).get("/v1/domains").status_code, (401, 403))
        self.assertIn(self.bearer("pk_live_deadbeef_nope").get("/v1/domains").status_code, (401, 403))

    def test_invalid_scopes_and_limit(self):
        for bad in ([], ["root"], ["domains:read", "x"]):
            r = self.c.post("/v1/keys", {"name": "x", "scopes": bad}, format="json")
            self.assertEqual(r.json()["error"]["code"], "invalid_scopes")
        for _ in range(10):
            self.new_key(["domains:read"])
        r = self.c.post("/v1/keys", {"name": "x", "scopes": ["domains:read"]}, format="json")
        self.assertEqual(r.json()["error"]["code"], "plan_limit")

    def test_key_of_unverified_user_rejected(self):
        k = self.new_key(["domains:read"])
        User.objects.filter(pk=self.user.pk).update(email_verified_at=None)
        self.assertIn(self.bearer(k["key"]).get("/v1/domains").status_code, (401, 403))

    def test_usage_endpoint(self):
        k = self.new_key(["domains:read"])
        j = self.bearer(k["key"]).get("/v1/usage").json()
        self.assertEqual(j["plan"], "free")
        self.assertEqual(j["limits"]["mailboxes_per_domain"], 1)


class ApiUnauthenticatedStatus(__import__("rest_framework.test",fromlist=["APITestCase"]).APITestCase):
    """Kimliksiz ve geçersiz anahtar 401 (403 değil): fail2ban /v1/* 401 kuralı ve istemci davranışı buna dayanır."""
    def test_no_credentials_is_401(self):
        r = self.client.get("/v1/me")
        self.assertEqual(r.status_code, 401)
        self.assertTrue(r["WWW-Authenticate"].startswith("Bearer"))

    def test_bad_key_is_401(self):
        self.assertEqual(self.client.get("/v1/me", HTTP_AUTHORIZATION="Bearer kotu").status_code, 401)
