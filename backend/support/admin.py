from django.contrib import admin

from .models import SupportTicket

@admin.register(SupportTicket)
class SupportTicketAdmin(admin.ModelAdmin):
    list_display = ["id", "subject", "created_by", "status", "created_at"]
    list_filter = ["status"]
