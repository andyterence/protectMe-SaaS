from rest_framework import serializers

from .models import AttackLog, ConnectionLog


class AttackLogSerializer(serializers.ModelSerializer):
    site_name = serializers.CharField(source="site.name", read_only=True)

    class Meta:
        model = AttackLog
        fields = ["id", "site", "site_name", "ip", "features", "probability", "status", "created_at"]
        read_only_fields = ["id", "site", "site_name", "ip", "features", "probability", "created_at"]


class AttackLogReviewSerializer(serializers.Serializer):
    """Utilise uniquement pour le PATCH de requalification (confirmed / false_positive).
    C'est ce jeu de donnees requalifie, pas les logs bruts, qui alimentera
    le futur reentrainement du modele.
    """
    status = serializers.ChoiceField(choices=[AttackLog.Status.CONFIRMED, AttackLog.Status.FALSE_POSITIVE])


class ConnectionLogSerializer(serializers.ModelSerializer):
    site_name = serializers.CharField(source="site.name", read_only=True)

    class Meta:
        model = ConnectionLog
        fields = ["id", "site", "site_name", "ip", "browser_type", "protocol_type", "probability", "is_attack", "created_at"]
