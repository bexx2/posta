import django.db.models.deletion
import django.utils.timezone
from django.conf import settings
from django.db import migrations, models


def seed_pro(apps, schema_editor):
    Plan = apps.get_model("hosting", "Plan")
    Plan.objects.update_or_create(slug="pro", defaults=dict(
        name="Pro", max_domains=1, max_mailboxes_per_domain=10, mailbox_quota_mb=500,
        daily_send_limit=50, price_try_monthly=None, price_usd_yearly=100, is_default=False))


class Migration(migrations.Migration):
    dependencies = [("hosting", "0003_upgrade_request_free_plan_one_mailbox"), migrations.swappable_dependency(settings.AUTH_USER_MODEL)]
    operations = [
        migrations.AddField("plan", "price_usd_yearly", models.PositiveIntegerField(blank=True, null=True)),
        migrations.AddField("membership", "paid_until", models.DateTimeField(blank=True, null=True)),
        migrations.CreateModel(name="Order", fields=[
            ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
            ("amount_usd", models.DecimalField(decimal_places=2, max_digits=8)),
            ("currency", models.CharField(default="USD", max_length=3)),
            ("status", models.CharField(choices=[("pending", "pending"), ("paid", "paid"), ("failed", "failed")], db_index=True, default="pending", max_length=8)),
            ("conversation_id", models.CharField(max_length=64, unique=True)),
            ("iyzico_token", models.CharField(blank=True, db_index=True, max_length=128)),
            ("iyzico_payment_id", models.CharField(blank=True, max_length=64)),
            ("buyer_name", models.CharField(max_length=240)),
            ("buyer_country", models.CharField(max_length=80)),
            ("buyer_address", models.CharField(max_length=300)),
            ("buyer_tax_id", models.CharField(blank=True, max_length=40)),
            ("terms_version", models.CharField(max_length=20)),
            ("consent_at", models.DateTimeField(default=django.utils.timezone.now)),
            ("error", models.CharField(blank=True, max_length=256)),
            ("created_at", models.DateTimeField(default=django.utils.timezone.now)),
            ("paid_at", models.DateTimeField(blank=True, null=True)),
            ("plan", models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, to="hosting.plan")),
            ("user", models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name="orders", to=settings.AUTH_USER_MODEL)),
        ]),
        migrations.RunPython(seed_pro, migrations.RunPython.noop),
    ]
