from django.db import migrations


def seed(apps, schema_editor):
    Plan = apps.get_model("hosting", "Plan")
    Plan.objects.get_or_create(slug="free", defaults=dict(
        name="Free (early access)", max_domains=1, max_mailboxes_per_domain=3, mailbox_quota_mb=500,
        daily_send_limit=50, price_try_monthly=None, is_default=True))


class Migration(migrations.Migration):
    dependencies = [("hosting", "0001_initial")]
    operations = [migrations.RunPython(seed, migrations.RunPython.noop)]
