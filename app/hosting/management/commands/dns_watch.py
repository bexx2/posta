"""dns_watch (posta-billing.timer, 10 dk): müşteri alan adlarının DNS'ini yeniden kontrol eder.
- pending  → DNS hazırsa otomatik doğrular (müşterinin "Check again"e basması gerekmez).
- verified → MX bizden çıktıysa (gelen posta artık bize gelmiyor) ya da DKIM eksikse sorun olarak işaretler (panel uyarısı + operatör).
- Hatırlatma maili: sorun başına en fazla 2 (ilk: sorun yaşı ≥ FIRST, ikinci: ilkinden ≥ SECOND sonra). settings.DNS_NUDGE_MAIL kapalıysa gönderilmez.
2026-10-10: bwranshop.com.tr 'verified' görünürken MX'i Cloudflare'e dönmüştü; walvo.digital MX'i posta.preved.co yazıp takıldı; kimse haber almadı."""
from datetime import datetime, timedelta

from django.conf import settings
from django.core.mail import EmailMessage
from django.core.management.base import BaseCommand
from django.utils import timezone

from hosting import services
from hosting.models import Domain

CHECK_EVERY = {Domain.PENDING: timedelta(minutes=15), Domain.VERIFIED: timedelta(hours=1)}
PENDING_MAX_AGE = timedelta(days=14)          # bundan eski bekleyenler yalnız günde bir kontrol edilir
# sorun → (ilk hatırlatma için sorunun yaşı, ikinci için ilkinden sonra geçen süre)
NUDGE = {"setup": (timedelta(hours=1), timedelta(hours=24)),
         "mx_lost": (timedelta(hours=2), timedelta(hours=24)),
         "dkim": (timedelta(hours=3), timedelta(hours=48))}


def issues(d):
    """Alan adının şu anki sorunları (son kontrole göre)."""
    c = d.last_check or {}
    if not c:
        return set()
    if d.status == Domain.PENDING:
        return {"setup"}
    out = set()
    if d.status == Domain.VERIFIED:
        if c.get("mx") is False:
            out.add("mx_lost")
        if d.dkim_txt and c.get("dkim") is False and d.mailboxes.exists():
            out.add("dkim")
    return out


def _body(d, kind):
    from hosting.panel import _dns_rows
    url = f"{settings.PUBLIC_BASE_URL.rstrip('/')}/app/domains/{d.pk}/"
    rows = [r for r in _dns_rows(d) if r["ok"] is False and (r["required"] or r["key"] == "dkim")]
    lines = "\n".join(f"- {r['type']} {r['name']}\n  value: {r['value']}" + (f"\n  note: {r['hint']}" if r["hint"] else "") for r in rows)
    head = {
        "setup": f"Your domain {d.name} is not connected to posta yet. These DNS records are still missing:",
        "mx_lost": f"Mail sent to {d.name} is no longer reaching your posta mailboxes. Your MX record does not point to {settings.MX_TARGET} any more:",
        "dkim": f"Mail you send from {d.name} is not signed yet, so it is more likely to land in spam. Add this DKIM record:",
    }[kind]
    tr = {
        "setup": f"{d.name} henuz posta'ya bagli degil. Yukaridaki DNS kayitlari eksik.",
        "mx_lost": f"{d.name} adresine gelen postalar artik posta kutularina ulasmiyor: MX kaydi {settings.MX_TARGET} adresini gostermiyor.",
        "dkim": f"{d.name} adresinden gonderdigin postalar imzasiz gidiyor (spam riski). Yukaridaki DKIM kaydini ekle.",
    }[kind]
    return (f"Hi,\n\n{head}\n\n{lines}\n\nAdd them at the company that manages your DNS. We check again automatically every hour, "
            f"you don't need to do anything else. Details and live status: {url}\n\nStuck? Just reply to this email and tell us "
            f"where your DNS is hosted. We will help.\n\n-- posta\n\n-----\n{tr} DNS'i yonettigin yerde ekle; her saat kendimiz kontrol ederiz. "
            f"Takildiysan bu e-postayi yanitla, yardim edelim.\n")


SUBJECT = {"setup": "Finish connecting {d}", "mx_lost": "{d}: incoming mail is not reaching posta", "dkim": "{d}: one record left so your mail is not marked as spam"}


class Command(BaseCommand):
    help = "dns_watch [--dry-run] [--force]"

    def add_arguments(self, p):
        p.add_argument("--dry-run", action="store_true", help="kontrol et, kaydetme, mail gönderme; ne olacağını yaz")
        p.add_argument("--force", action="store_true", help="zamanlamayı yok say, hepsini şimdi kontrol et")

    def handle(self, *a, dry_run=False, force=False, **kw):
        now = timezone.now()
        stats = {"checked": 0, "auto_verified": 0, "nudge": 0, "nudge_skipped": 0}
        for d in Domain.objects.exclude(status=Domain.SUSPENDED).select_related("owner"):
            every = CHECK_EVERY.get(d.status, timedelta(hours=1))
            if d.status == Domain.PENDING and now - d.created_at > PENDING_MAX_AGE:
                every = timedelta(days=1)
            if not force and d.last_check_at and now - d.last_check_at < every:
                continue
            stats["checked"] += 1
            was = d.status
            if dry_run:
                found = {}
                d.last_check = {**services.check_dns(d, found), "_found": found}
            elif d.status == Domain.PENDING:
                try:
                    services.verify_domain(d.owner, d)          # DNS hazırsa doğrular + Mailcow'da açar (sinyal operatöre bildirir)
                except services.ServiceError as e:
                    self.stderr.write(f"{d.name}: {e.message}")
                    continue
                d.refresh_from_db()
                if was == Domain.PENDING and d.status == Domain.VERIFIED:
                    stats["auto_verified"] += 1
            else:
                found = {}
                d.last_check, d.last_check_at = {**services.check_dns(d, found), "_found": found}, now
            w = dict(d.watch or {})
            cur = issues(d)
            if dry_run and was == Domain.PENDING and d.last_check.get("ownership_txt") and d.last_check.get("mx"):
                cur, stats["auto_verified"] = set(), stats["auto_verified"] + 1
            for k in list(w):                                    # düzelen sorun: kaydı sil (tekrar bozulursa baştan sayar)
                if k not in cur:
                    if k == "mx_lost" and not dry_run:
                        services.notify_operator(f"MX geri geldi: {d.name}", f"{d.owner.email}: {d.name} MX tekrar bize bakıyor.")
                    w.pop(k)
            for k in cur:
                new = k not in w
                st = w.setdefault(k, {"since": now.isoformat(), "sent": []})
                if k == "mx_lost" and new and not dry_run:
                    services.notify_operator(f"⚠ MX kayboldu: {d.name}", f"{d.owner.email}: {d.name} verified ama MX artık {settings.MX_TARGET} değil "
                                             f"({', '.join((d.last_check.get('_found') or {}).get('mx') or ['MX yok'])}). Gelen posta kutuya ulaşmıyor.")
                first, second = NUDGE[k]
                since = datetime.fromisoformat(st["since"])
                if k == "setup":
                    since = d.created_at                       # yarım kurulum: kayıttan itibaren
                due = (not st["sent"] and now - since >= first) or (len(st["sent"]) == 1 and now - datetime.fromisoformat(st["sent"][0]) >= second)
                if not due:
                    continue
                subj = SUBJECT[k].format(d=d.name)
                if dry_run or not settings.DNS_NUDGE_MAIL:
                    stats["nudge_skipped"] += 1
                    self.stdout.write(f"[{'dry-run' if dry_run else 'mail kapalı'}] {d.owner.email} · {d.name} · {k} · '{subj}'")
                    continue
                EmailMessage(subj, _body(d, k), settings.DEFAULT_FROM_EMAIL, [d.owner.email], reply_to=["merhaba@preved.co"]).send(fail_silently=True)
                st["sent"].append(now.isoformat())
                stats["nudge"] += 1
                services.audit(None, "domain.nudge", "domain", d.name, kind=k, n=len(st["sent"]))
            if not dry_run:
                d.watch = w
                d.save(update_fields=["watch", "last_check", "last_check_at"])
        self.stdout.write(f"dns_watch: {stats}")
