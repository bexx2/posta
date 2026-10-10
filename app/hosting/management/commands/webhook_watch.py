"""webhook_watch (posta-webhook.timer, her dakika): webhook'u olan kutuların ileti sayısını Mailcow'dan okur (içerik DEĞİL), artış varsa
imzalı "message.received" POST'u gönderir (#4). Sayı düşerse (müşteri sildi) taban güncellenir. Başarısız teslim sonraki koşuda yeniden
denenir; WEBHOOK_DISABLE_AFTER art arda başarısızlıktan sonra webhook kapanır ve sahibine bir kez e-posta gider."""
from django.conf import settings
from django.core.mail import send_mail
from django.core.management.base import BaseCommand
from django.utils import timezone

from hosting import services
from hosting.backends import get_backend
from hosting.backends.base import BackendError
from hosting.models import Mailbox


class Command(BaseCommand):
    help = "webhook_watch"

    def handle(self, *a, **kw):
        boxes = list(Mailbox.objects.exclude(webhook_url="").filter(webhook_disabled_at__isnull=True, status=Mailbox.ACTIVE).select_related("domain__owner"))
        if not boxes:
            return
        try:
            counts = get_backend().message_counts()
        except BackendError as e:
            self.stderr.write(f"webhook_watch: mailcow okunamadı: {e}")
            return
        stats = {"sent": 0, "failed": 0, "disabled": 0}
        for mb in boxes:
            cur = counts.get(mb.address)
            if cur is None:
                continue
            if mb.webhook_seen is None or cur < mb.webhook_seen:
                mb.webhook_seen = cur                                   # ilk ölçüm ya da silme: yalnız taban
            elif cur > mb.webhook_seen:
                mb.webhook_pending += cur - mb.webhook_seen
                mb.webhook_seen = cur
            if mb.webhook_pending:
                payload = {"event": "message.received", "mailbox": mb.address, "mailbox_id": mb.id,
                           "new_messages": mb.webhook_pending, "total_messages": cur, "sent_at": timezone.now().isoformat()}
                try:
                    ok = services.deliver_webhook(mb, payload)
                except (services.ServiceError, Exception) as e:          # ağ/SSRF/zaman aşımı: hepsi başarısız teslim
                    ok = False
                    self.stderr.write(f"{mb.address}: {type(e).__name__}")
                if ok:
                    mb.webhook_pending, mb.webhook_fails = 0, 0
                    stats["sent"] += 1
                else:
                    mb.webhook_fails += 1
                    stats["failed"] += 1
                    if mb.webhook_fails >= services.WEBHOOK_DISABLE_AFTER:
                        mb.webhook_disabled_at = timezone.now()
                        stats["disabled"] += 1
                        services.audit(None, "webhook.disabled", "mailbox", mb.address, fails=mb.webhook_fails)
                        send_mail(f"posta: webhook for {mb.address} was turned off",
                                  f"Your webhook {mb.webhook_url} for {mb.address} failed {mb.webhook_fails} times in a row (no 2xx answer), "
                                  f"so we turned it off. Your mail is safe in the mailbox. Set the webhook again (PUT /v1/mailboxes/{mb.id}/webhook) "
                                  f"when your endpoint works.\n\n-- posta", settings.DEFAULT_FROM_EMAIL, [mb.domain.owner.email], fail_silently=True)
            mb.save(update_fields=["webhook_seen", "webhook_pending", "webhook_fails", "webhook_disabled_at"])
        if any(stats.values()):
            self.stdout.write(f"webhook_watch: {stats}")
