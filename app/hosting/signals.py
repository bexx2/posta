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
