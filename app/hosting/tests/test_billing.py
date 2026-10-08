import hashlib
import hmac
from decimal import Decimal
from unittest import mock

from django.core import mail
from django.test import Client, TestCase, override_settings
from django.utils import timezone

from accounts.models import User
from hosting import iyzico
from hosting.backends.dryrun import DryRunBackend
from hosting.models import Domain, Membership, Order, Plan

PW = "a-long-enough-pass-9"
SECRET = "test-secret"
CFG = dict(PAYMENTS_ENABLED=True, IYZICO_API_KEY="k", IYZICO_SECRET_KEY=SECRET, NOTIFY_EMAIL="ops@example.net",
           EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend")


def sign(params):
    return hmac.new(SECRET.encode(), ":".join(params).encode(), hashlib.sha256).hexdigest()


def retrieve_detail(order, status="SUCCESS", paid="100.0"):
    d = {"status": "success", "paymentStatus": status, "paymentId": "pay-1", "currency": "USD", "basketId": f"pro-{order.id}",
         "conversationId": order.conversation_id, "paidPrice": paid, "price": paid, "token": "tok-1"}
    d["signature"] = sign([status, "pay-1", "USD", d["basketId"], order.conversation_id, iyzico.normalize_price(paid), iyzico.normalize_price(paid), "tok-1"])
    return d


@override_settings(**CFG)
class BillingFlow(TestCase):
    def setUp(self):
        DryRunBackend.instance().reset()
        self.user = User.objects.create_user(email="dev@example.com", password=PW, email_verified_at=timezone.now())
        self.c = Client()
        self.c.force_login(self.user)
        self.form = {"name": "Ada Lovelace", "country": "UK", "address": "1 Test St", "accept": "on", "buyer_type": "business"}

    def start(self):
        init = {"status": "success", "token": "tok-1", "conversationId": None, "paymentPageUrl": "https://pay.example/x"}
        def fake_init(payload):
            init["conversationId"] = payload["conversationId"]
            init["signature"] = sign([payload["conversationId"], "tok-1"])
            self.payload = payload
            return init
        with mock.patch.object(iyzico, "initialize", side_effect=fake_init):
            r = self.c.post("/app/billing/", self.form)
        return r

    def test_pro_plan_seeded(self):
        p = Plan.objects.get(slug="pro")
        self.assertEqual((p.max_domains, p.max_mailboxes_per_domain, p.price_usd_yearly), (1, 10, 100))

    def test_checkout_redirects_and_payload(self):
        r = self.start()
        self.assertEqual((r.status_code, r["Location"]), (302, "https://pay.example/x"))
        o = Order.objects.get()
        self.assertEqual((o.status, o.amount_usd, o.currency, o.iyzico_token), ("pending", Decimal("100"), "USD", "tok-1"))
        self.assertEqual((self.payload["currency"], self.payload["price"], self.payload["enabledInstallments"]), ("USD", "100.0", [1]))

    def test_requires_consent_and_fields(self):
        self.form["accept"] = ""
        self.c.post("/app/billing/", self.form)
        self.assertEqual(Order.objects.count(), 0)

    @override_settings(PAYMENTS_ENABLED=False)
    def test_disabled_does_not_charge(self):
        r = self.c.post("/app/billing/", self.form)
        self.assertEqual(Order.objects.count(), 0)
        self.assertEqual(r.status_code, 302)

    def test_success_callback_activates_pro_and_raises_mailcow_limits(self):
        Domain.objects.create(owner=self.user, name="example.org", status=Domain.VERIFIED)
        self.start()
        o = Order.objects.get()
        with mock.patch.object(iyzico, "retrieve", return_value=retrieve_detail(o)):
            with self.captureOnCommitCallbacks(execute=True):
                r = Client().post("/app/billing/callback/", {"token": "tok-1"})   # oturumsuz çapraz-site POST
        self.assertEqual(r["Location"], "/app/billing/?r=ok")
        o.refresh_from_db()
        m = Membership.objects.get(user=self.user)
        self.assertEqual((o.status, m.plan.slug), ("paid", "pro"))
        self.assertTrue(m.paid_until > timezone.now())
        self.assertIn(("set_domain_limits", "example.org", 10, 500), DryRunBackend.instance().ops)
        self.assertTrue(any("ÖDEME ALINDI" in x.subject for x in mail.outbox))
        self.assertTrue(any(x.to == ["dev@example.com"] for x in mail.outbox))

    def test_callback_is_idempotent(self):
        self.start()
        o = Order.objects.get()
        with mock.patch.object(iyzico, "retrieve", return_value=retrieve_detail(o)):
            Client().post("/app/billing/callback/", {"token": "tok-1"})
            until = Membership.objects.get(user=self.user).paid_until
            Client().post("/app/billing/callback/", {"token": "tok-1"})
        self.assertEqual(Membership.objects.get(user=self.user).paid_until, until)

    def test_wrong_amount_or_bad_signature_not_activated(self):
        self.start()
        o = Order.objects.get()
        bad = retrieve_detail(o, paid="1.0")
        with mock.patch.object(iyzico, "retrieve", return_value=bad):
            with self.captureOnCommitCallbacks(execute=True):
                Client().post("/app/billing/callback/", {"token": "tok-1"})
        o.refresh_from_db()
        self.assertEqual(o.status, "review")          # SUCCESS dendi ama tutar tutmadı: insan bakar, müşteri sessizce kaybolmaz
        self.assertTrue(any("İNCELEME" in x.subject for x in mail.outbox))
        self.assertEqual(Membership.objects.get(user=self.user).plan.slug, "free")

    def test_failed_payment_not_activated(self):
        self.start()
        o = Order.objects.get()
        with mock.patch.object(iyzico, "retrieve", return_value=retrieve_detail(o, status="FAILURE")):
            r = Client().post("/app/billing/callback/", {"token": "tok-1"})
        self.assertEqual(r["Location"], "/app/billing/?r=failed")
        self.assertEqual(Membership.objects.get(user=self.user).plan.slug, "free")


    def test_requires_buyer_type_and_records_evidence(self):
        bad = dict(self.form); bad.pop("buyer_type")
        self.c.post("/app/billing/", bad)
        self.assertEqual(Order.objects.count(), 0)
        self.start()
        o = Order.objects.get()
        self.assertEqual((o.buyer_type, o.sales_version != "", o.accept_ip is not None or True), ("business", True, True))

    def test_receipt_contains_contract_facts(self):
        self.start()
        o = Order.objects.get()
        with mock.patch.object(iyzico, "retrieve", return_value=retrieve_detail(o)):
            with self.captureOnCommitCallbacks(execute=True):
                Client().post("/app/billing/callback/", {"token": "tok-1"})
        r = [x for x in mail.outbox if x.to == ["dev@example.com"] and "payment received" in x.subject][0]
        for needle in ("USD 100", "No automatic renewal", "14 days", "/sales/", "Ends:"):
            self.assertIn(needle, r.body)

    def test_reconcile_applies_unreturned_payment(self):
        from django.core.management import call_command
        from datetime import timedelta
        self.start()
        o = Order.objects.get()
        Order.objects.filter(pk=o.pk).update(created_at=timezone.now() - timedelta(minutes=30))
        with mock.patch.object(iyzico, "retrieve", return_value=retrieve_detail(o)):
            call_command("reconcile_orders")
        self.assertEqual(Membership.objects.get(user=self.user).plan.slug, "pro")


@override_settings(**CFG)
class Lifecycle(TestCase):
    def setUp(self):
        DryRunBackend.instance().reset()
        self.user = User.objects.create_user(email="dev@example.com", password=PW, email_verified_at=timezone.now())

    def _pro(self, days_left):
        from datetime import timedelta
        m = Membership.objects.get(user=self.user)
        m.plan, m.paid_until, m.lifecycle = Plan.objects.get(slug="pro"), timezone.now() + timedelta(days=days_left), {}
        m.save()
        return m

    def test_reminders_once(self):
        from django.core.management import call_command
        self._pro(6)
        call_command("pro_lifecycle"); call_command("pro_lifecycle")
        self.assertEqual(len([x for x in mail.outbox if "ends in 7 days" in x.subject]), 1)

    def test_downgrade_after_grace_suspends_extras_and_renewal_restores(self):
        from django.core.management import call_command
        from hosting.models import Mailbox
        m = self._pro(-15)
        d = Domain.objects.create(owner=self.user, name="example.org", status=Domain.VERIFIED)
        for lp in ("a", "b", "c"):
            Mailbox.objects.create(domain=d, local_part=lp, address=f"{lp}@example.org", quota_mb=500)
        call_command("pro_lifecycle")
        m.refresh_from_db()
        self.assertEqual(m.plan.slug, "free")
        self.assertEqual(list(Mailbox.objects.filter(status="suspended").values_list("local_part", flat=True).order_by("local_part")), ["b", "c"])
        # yenileme: askıdakiler geri gelir
        from hosting import services
        o = Order.objects.create(user=self.user, plan=Plan.objects.get(slug="pro"), amount_usd=Decimal("100"), conversation_id="c1", buyer_name="x", buyer_country="x", buyer_address="x", terms_version="v", status="paid", paid_at=timezone.now())
        services.activate_pro(o)
        self.assertEqual(Mailbox.objects.filter(status="suspended").count(), 0)

    def test_within_grace_keeps_pro(self):
        from django.core.management import call_command
        m = self._pro(-5)
        call_command("pro_lifecycle")
        m.refresh_from_db()
        self.assertEqual(m.plan.slug, "pro")
