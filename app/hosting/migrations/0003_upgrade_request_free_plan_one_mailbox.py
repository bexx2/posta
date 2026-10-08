import django.db.models.deletion
import django.utils.timezone
from django.conf import settings
from django.db import migrations, models


def one_free_mailbox(apps, schema_editor):
    Plan = apps.get_model("hosting", "Plan")
    Plan.objects.filter(slug="free").update(max_domains=1, max_mailboxes_per_domain=1)


class Migration(migrations.Migration):
    dependencies = [("hosting", "0002_seed_free_plan"), migrations.swappable_dependency(settings.AUTH_USER_MODEL)]
    operations = [
        migrations.CreateModel(
            name="UpgradeRequest",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("kind", models.CharField(choices=[("mailboxes", "mailboxes"), ("domains", "domains")], max_length=12)),
                ("quantity", models.PositiveIntegerField()),
                ("note", models.CharField(blank=True, max_length=500)),
                ("status", models.CharField(choices=[("open", "open"), ("answered", "answered"), ("closed", "closed")], default="open", max_length=10)),
                ("created_at", models.DateTimeField(default=django.utils.timezone.now)),
                ("user", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="upgrade_requests", to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.RunPython(one_free_mailbox, migrations.RunPython.noop),
    ]
