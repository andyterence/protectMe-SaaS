from rest_framework import serializers

from .models import SupportTicket


class SupportTicketSerializer(serializers.ModelSerializer):
    created_by_email = serializers.CharField(source="created_by.email", read_only=True)

    class Meta:
        model = SupportTicket
        fields = [
            "id", "site", "subject", "message", "admin_reply",
            "status", "created_by_email", "created_at", "updated_at",
        ]
        read_only_fields = ["id", "admin_reply", "status", "created_by_email", "created_at", "updated_at"]


class SupportTicketAdminUpdateSerializer(serializers.Serializer):
    """Reservee a l'Admin : seul lui peut repondre et changer le statut."""
    status = serializers.ChoiceField(choices=SupportTicket.Status.choices, required=False)
    admin_reply = serializers.CharField(required=False, allow_blank=True)
