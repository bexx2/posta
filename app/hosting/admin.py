from django.contrib import admin

from .models import AuditLog, Domain, Mailbox, Membership, Plan, UpgradeRequest


@admin.register(UpgradeRequest)
class UpgradeRequestAdmin(admin.ModelAdmin):
    list_display = ("created_at", "user", "kind", "quantity", "status", "note")
    list_filter = ("status", "kind")
    list_editable = ("status",)


admin.site.register(Plan)
admin.site.register(Membership)
admin.site.register(Domain)
admin.site.register(Mailbox)
admin.site.register(AuditLog)
