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
