from django.db import migrations


def seed_starter(apps, schema_editor):
    """Starter: 1 alan adı, 5 kutu, yıllık 50 USD (2026-10-10 satışa açıldı; canlıda elle eklenmişti, burada sabitlenir)."""
    Plan = apps.get_model("hosting", "Plan")
    Plan.objects.update_or_create(slug="starter", defaults=dict(
        name="Starter", max_domains=1, max_mailboxes_per_domain=5, mailbox_quota_mb=500, daily_send_limit=50,
        price_usd_yearly=50, is_default=False))


class Migration(migrations.Migration):
    dependencies = [("hosting", "0005_billing_hardening")]
    operations = [migrations.RunPython(seed_starter, migrations.RunPython.noop)]
