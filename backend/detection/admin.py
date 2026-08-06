from django.contrib import admin

from .models import AttackLog

@admin.register(AttackLog)
class AttackLogAdmin(admin.ModelAdmin):
    list_display = ["site", "ip", "probability", "status", "created_at"]
    list_filter = ["status", "site"]
    readonly_fields = ["features", "probability", "created_at"]
