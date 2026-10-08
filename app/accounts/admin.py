from django.contrib import admin
from django.utils import timezone

from .models import User


@admin.register(User)
class UserAdmin(admin.ModelAdmin):
    list_display = ("email", "is_active", "email_verified_at", "date_joined")
    search_fields = ("email",)
    actions = ["mark_verified"]
    exclude = ("password",)

    @admin.action(description="Mark email as verified")
    def mark_verified(self, request, queryset):
        queryset.filter(email_verified_at__isnull=True).update(email_verified_at=timezone.now())
