from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("hosting", "0004_pro_plan_orders")]
    operations = [
        migrations.AddField("membership", "lifecycle", models.JSONField(blank=True, default=dict)),
        migrations.AddField("mailbox", "plan_suspended_at", models.DateTimeField(blank=True, null=True)),
        migrations.AddField("order", "sales_version", models.CharField(blank=True, max_length=20)),
        migrations.AddField("order", "buyer_type", models.CharField(blank=True, choices=[("business", "business"), ("consumer", "consumer")], max_length=10)),
        migrations.AddField("order", "accept_ip", models.GenericIPAddressField(blank=True, null=True)),
        migrations.AlterField("order", "status", models.CharField(choices=[("pending", "pending"), ("paid", "paid"), ("failed", "failed"), ("review", "review")], db_index=True, default="pending", max_length=8)),
    ]
