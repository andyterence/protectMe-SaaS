from django.contrib import admin

from .models import Site

@admin.register(Site)
class SiteAdmin(admin.ModelAdmin):
    list_display = ["name", "owner", "api_key_prefix", "is_active", "created_at"]
    readonly_fields = ["api_key_hash", "api_key_prefix"]
