from rest_framework import serializers

from .models import Site


class SiteSerializer(serializers.ModelSerializer):
    class Meta:
        model = Site
        fields = ["id", "name", "api_key_prefix", "created_at", "is_active"]
