from django.db.models.signals import post_save
from django.dispatch import receiver

from accounts.models import User
from .models import Membership, Plan


@receiver(post_save, sender=User)
def give_default_plan(sender, instance, created, **kw):
    if created:
        plan = Plan.objects.filter(is_default=True).first()
        if plan:
            Membership.objects.get_or_create(user=instance, defaults={"plan": plan})


# ── Operatör bildirimi: yeni kayıt, domain doğrulandı, kutu oluştu ──────────────────────────
# Gönderen noreply → Mailcow sender-BCC ile Anka arşivine de düşer. Hata ASLA isteği bozmaz.
import logging

from django.conf import settings
from django.core.mail import send_mail
from django.db import transaction
from django.db.models.signals import pre_save

from .models import Domain, Mailbox

_log = logging.getLogger(__name__)


def _notify(subject, body):
    to = getattr(settings, "NOTIFY_EMAIL", "")
    if not to:
        return
    def _send():
        try:
            send_mail(f"[posta] {subject}", body, settings.DEFAULT_FROM_EMAIL, [to], fail_silently=True)
        except Exception:
            _log.exception("notify failed")
    transaction.on_commit(_send)


@receiver(post_save, sender=User)
def notify_signup(sender, instance, created, **kw):
    if created:
        _notify(f"yeni kayıt #{instance.id}", f"Yeni kayıt: {instance.email} (kullanıcı #{instance.id}), doğrulama bekliyor.")


@receiver(pre_save, sender=Domain)
def _remember_domain_status(sender, instance, **kw):
    old = Domain.objects.filter(pk=instance.pk).values_list("status", flat=True).first() if instance.pk else None
    instance._old_status = old


@receiver(post_save, sender=Domain)
def notify_domain(sender, instance, created, **kw):
    old = getattr(instance, "_old_status", None)
    if created:
        _notify(f"domain eklendi: {instance.name}", f"{instance.owner.email} alan adı ekledi: {instance.name}")
    elif instance.status == Domain.VERIFIED and old != Domain.VERIFIED:
        _notify(f"domain doğrulandı: {instance.name}", f"{instance.owner.email}: {instance.name} doğrulandı.")


@receiver(post_save, sender=Mailbox)
def notify_mailbox(sender, instance, created, **kw):
    if created:
        _notify("kutu oluşturuldu", f"{instance.domain.owner.email} bir kutu oluşturdu (alan adı: {instance.domain.name}).")


# ── Müşteriye hoş geldin + kısa veri toplama sorusu (2026-10-10, Bedran) ─────────────────────
# Her yeni kutuya otomatik gider (bize değil, kutunun KENDİSİNE). Amaç: kim/ne için/ne kadar
# hacim ihtiyacı — kapasite planlaması. Sistematik olduğu için kişisel imza (bexx) değil,
# "posta team" — her kutuya aynı mail gittiği için dürüst olan budur.
def _welcome(to_address):
    subject = "Welcome to posta — a quick question"
    body = ("Hi,\n\n"
            "Your mailbox is ready. One quick thing: it helps us plan capacity if we know a bit "
            "about how you'll use it.\n\n"
            "- What will you be using this mailbox for?\n"
            "- Roughly how many emails per day do you expect to send?\n"
            "- Do you think you'll need more than one mailbox or domain?\n\n"
            "No pressure to answer, just reply if you feel like it.\n\n"
            "- posta team\n")
    def _send():
        try:
            from django.core.mail import EmailMessage
            EmailMessage(subject, body, settings.DEFAULT_FROM_EMAIL, [to_address],
                         reply_to=["merhaba@preved.co"]).send(fail_silently=True)
        except Exception:
            _log.exception("welcome mail failed")
    transaction.on_commit(_send)


@receiver(post_save, sender=Mailbox)
def welcome_mailbox_owner(sender, instance, created, **kw):
    if created:
        _welcome(instance.address)
