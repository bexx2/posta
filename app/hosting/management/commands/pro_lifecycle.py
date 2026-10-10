"""Pro yaşam döngüsü (günlük): bitiş öncesi 30 ve 7 gün hatırlatma → bitişten sonra 14 gün her şey çalışır → ücretsize indir + fazla kutuları askıya al (+ bildirim).
Askıdaki kutuların 60 gün sonra SİLİNMESİ bilerek burada YOK (geri dönüşsüz): ilk bitiş 2027-10, silme kodu en geç 2027-11'de yazılıp insan onayıyla açılmalı."""
from datetime import timedelta

from django.conf import settings
from django.core.mail import send_mail
from django.core.management.base import BaseCommand
from django.utils import timezone

from hosting import services
from hosting.models import Membership

GRACE_DAYS = 14


def _mail(user, subject, body):
    send_mail(subject, body + "\n\nposta - https://posta.preved.co - merhaba@preved.co", settings.DEFAULT_FROM_EMAIL, [user.email], fail_silently=True)


class Command(BaseCommand):
    def handle(self, *a, **kw):
        now = timezone.now()
        n = {"r30": 0, "r7": 0, "down": 0}
        for m in Membership.objects.filter(paid_until__isnull=False).select_related("user", "plan"):
            left, lc, u = m.paid_until - now, m.lifecycle or {}, m.user
            pn = m.plan.name   # Starter ya da Pro (indirmeden ÖNCE okunur)
            if left > timedelta(0):
                if left <= timedelta(days=7) and not lc.get("r7"):
                    _mail(u, f"posta {pn} ends in 7 days", f"Your posta {pn} plan ends on {m.paid_until:%Y-%m-%d}. It does not renew by itself. To keep it, pay again in the dashboard: https://posta.preved.co/app/billing/ (each payment adds one year).\n\n{pn} planin {m.paid_until:%Y-%m-%d} tarihinde bitiyor ve kendiliginden yenilenmiyor. Surdurmek icin panelden yeniden ode: https://posta.preved.co/app/billing/")
                    lc["r7"] = now.isoformat(); n["r7"] += 1
                elif left <= timedelta(days=30) and not lc.get("r30"):
                    _mail(u, f"posta {pn} ends in 30 days", f"Your posta {pn} plan ends on {m.paid_until:%Y-%m-%d}. It does not renew by itself. To keep it, pay again in the dashboard: https://posta.preved.co/app/billing/\n\n{pn} planin {m.paid_until:%Y-%m-%d} tarihinde bitiyor ve kendiliginden yenilenmiyor. Yenilemek icin: https://posta.preved.co/app/billing/")
                    lc["r30"] = now.isoformat(); n["r30"] += 1
            elif -left > timedelta(days=GRACE_DAYS) and not lc.get("down"):
                errs = services.downgrade_to_free(u, reason="expired")
                _mail(u, f"posta {pn} ended: extra mailboxes suspended", f"Your {pn} plan ended and was not renewed. Your account is now on the free plan; extra mailboxes are suspended (not deleted). If you renew before they are deleted (60 days after suspension; we email you 14 days before), they come back as they were: https://posta.preved.co/app/billing/\n\n{pn} planin bitti ve yenilenmedi. Hesabin ucretsiz plana gecti; fazla kutular askiya alindi (silinmedi). Silinmeden once (askidan 60 gun sonra; 14 gun once e-posta gondeririz) yenilersen oldugu gibi geri gelirler.")
                services.notify_operator(f"{pn} bitti: {u.email}", f"Ücretsize indirildi. Mailcow hataları: {errs}")
                m2 = Membership.objects.get(pk=m.pk)
                m2.lifecycle = {**lc, "down": now.isoformat()}
                m2.save(update_fields=["lifecycle"])
                n["down"] += 1
                continue
            if lc != (m.lifecycle or {}):
                m.lifecycle = lc
                m.save(update_fields=["lifecycle"])
        self.stdout.write(f"lifecycle: {n}")
