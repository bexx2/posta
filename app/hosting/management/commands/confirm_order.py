"""İnsan onaylı: iyzico panelinde ödemenin gerçekten alındığını doğruladıysan REVIEW siparişi uygula."""
from django.core.management.base import BaseCommand, CommandError
from django.db import transaction
from django.utils import timezone

from hosting import services
from hosting.models import Order


class Command(BaseCommand):
    help = "confirm_order <id>: review/pending siparişi ödenmiş say, Pro'yu aç"

    def add_arguments(self, p):
        p.add_argument("order_id", type=int)

    def handle(self, *a, order_id, **kw):
        with transaction.atomic():
            o = Order.objects.select_for_update().filter(pk=order_id).first()
            if not o or o.status not in (Order.REVIEW, Order.PENDING, Order.FAILED):
                raise CommandError("sipariş yok ya da zaten ödenmiş")
            o.status, o.paid_at, o.error = Order.PAID, timezone.now(), "confirmed manually"
            o.save(update_fields=["status", "paid_at", "error"])
            errs = services.activate_pro(o)
        services.send_receipt(o)
        self.stdout.write(f"order #{o.id} onaylandı; Pro {o.user.membership.paid_until:%Y-%m-%d} tarihine kadar. hatalar: {errs}")
