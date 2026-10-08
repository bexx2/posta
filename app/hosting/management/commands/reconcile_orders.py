"""Bekleyen siparişleri iyzico ile eşitle: müşteri ödeyip tarayıcıyı kapattıysa/callback ulaşmadıysa Pro yine de açılır. Her 10 dk (posta-billing.timer)."""
from datetime import timedelta

from django.core.management.base import BaseCommand
from django.db import transaction
from django.utils import timezone

from hosting import iyzico, services
from hosting.models import Order


class Command(BaseCommand):
    help = "pending siparişleri (>5 dk, <3 gün) iyzico'dan çek ve uygula"

    def handle(self, *a, **kw):
        now = timezone.now()
        qs = Order.objects.filter(status=Order.PENDING, created_at__lt=now - timedelta(minutes=5), created_at__gt=now - timedelta(days=3)).exclude(iyzico_token="")
        done = 0
        for o in qs:
            try:
                detail = iyzico.retrieve(o.iyzico_token)
            except iyzico.IyzicoError:
                continue     # henüz ödenmemiş/oturum süresi dolmuş: pending kalır (3 gün sonra taranmaz)
            with transaction.atomic():
                o = Order.objects.select_for_update().get(pk=o.pk)
                if o.status != Order.PENDING:
                    continue
                ok = services.finish_order(o, detail)
                errs = services.activate_pro(o) if ok else []
            if ok:
                services.notify_operator(f"ÖDEME ALINDI (eşitleme): {o.user.email}", f"Pro ${o.amount_usd} — sipariş #{o.id}. Callback ulaşmamıştı, eşitleme komutu uyguladı. Faturayı 7 gün içinde kes." + (f" UYARI: {errs}" if errs else ""))
                services.send_receipt(o)
                done += 1
            elif o.status == Order.REVIEW:
                services.notify_operator(f"⚠ ÖDEME İNCELEME GEREKİR: sipariş #{o.id}", f"{o.user.email}: iyzico SUCCESS ama doğrulama tutmadı. paymentId {o.iyzico_payment_id}. Doğruysa: manage.py confirm_order {o.id}")
        self.stdout.write(f"reconcile: {done} sipariş uygulandı")
