import uuid

from django.conf import settings
from rest_framework.exceptions import NotFound
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.authentication import JWTAuthentication

from sites.authentication import ApiKeyAuthentication
from sites.models import Site
from sites.permissions import IsValidSite

from .ml import predict
from .models import AttackLog, ConnectionLog
from .serializers import AttackLogReviewSerializer, AttackLogSerializer, ConnectionLogSerializer

CONNECTION_LOG_PAGE_SIZE = 200


def _sites_for(user):
    """Meme regle d'isolation multi-tenant que sites/views.py : un User ne
    voit que ses propres sites, l'Admin voit tout.
    """
    return Site.objects.all() if user.role == "admin" else Site.objects.filter(owner=user)


class DetectView(APIView):
    """Endpoint appele par le middleware distribuable, jamais par le
    dashboard. Authentification par cle API uniquement.
    """
    authentication_classes = [ApiKeyAuthentication]
    permission_classes = [IsValidSite]

    def post(self, request):
        site = request.auth
        features = request.data

        proba = predict(features)
        attack_detected = proba >= settings.BLOCK_THRESHOLD
        ip = features.get("_client_ip") or "0.0.0.0"

        # Trafic COMPLET : sert a "qui se connecte", jamais au reentrainement.
        ConnectionLog.objects.create(
            site=site, ip=ip,
            browser_type=features.get("browser_type", ""),
            protocol_type=features.get("protocol_type", ""),
            probability=proba, is_attack=attack_detected,
        )

        # Stockage SELECTIF : uniquement le trafic suspect, alimente le
        # futur reentrainement une fois requalifie par un humain.
        if proba >= settings.SUSPICION_THRESHOLD:
            AttackLog.objects.create(site=site, ip=ip, features=features, probability=proba)

        return Response({
            "attack_detected": attack_detected,
            "probability": round(proba, 4),
            "request_id": str(uuid.uuid4()),
        })


class AttackLogListView(APIView):
    """Liste des attaques detectees, filtrable par site et par statut -
    l'ecran principal du dashboard ("qui a attaque ou pas").
    """
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        qs = AttackLog.objects.filter(site__in=_sites_for(request.user))

        site_id = request.query_params.get("site")
        if site_id:
            qs = qs.filter(site_id=site_id)

        status_filter = request.query_params.get("status")
        if status_filter:
            qs = qs.filter(status=status_filter)

        return Response(AttackLogSerializer(qs[:CONNECTION_LOG_PAGE_SIZE], many=True).data)


class AttackLogReviewView(APIView):
    """PATCH /api/attack-logs/{id}/review/ - requalifie un log en
    'confirmed' ou 'false_positive'. C'est ce geste humain qui transforme
    un log brut en donnee exploitable pour le futur reentrainement.
    """
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def patch(self, request, pk):
        try:
            log = AttackLog.objects.get(pk=pk, site__in=_sites_for(request.user))
        except AttackLog.DoesNotExist:
            raise NotFound("Log introuvable ou hors de votre perimetre.")

        serializer = AttackLogReviewSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        log.status = serializer.validated_data["status"]
        log.save(update_fields=["status"])
        return Response(AttackLogSerializer(log).data)


class ConnectionLogListView(APIView):
    """Liste des connexions recentes (attaques ou non) sur les sites de
    l'utilisateur - vue "qui se connecte". Limitee aux CONNECTION_LOG_PAGE_SIZE
    plus recentes : c'est une consultation, pas un export d'historique complet
    (cf. la purge automatique via cleanup_old_logs).
    """
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        qs = ConnectionLog.objects.filter(site__in=_sites_for(request.user))

        site_id = request.query_params.get("site")
        if site_id:
            qs = qs.filter(site_id=site_id)

        return Response(ConnectionLogSerializer(qs[:CONNECTION_LOG_PAGE_SIZE], many=True).data)


class SimulateView(APIView):
    """Correspond a "Lancer une simulation d'attaque" du cahier des charges.
    Rejoue une prediction a la demande, SANS jamais l'ecrire en base : une
    simulation ne doit ni polluer les statistiques reelles d'un site, ni
    fausser le futur reentrainement.
    """
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    PRESETS = {
        "normal": {
            "network_packet_size": 400, "protocol_type": "TCP", "login_attempts": 2,
            "session_duration": 100, "encryption_used": "AES", "ip_reputation_score": 0.1,
            "failed_logins": 0, "browser_type": "Chrome", "unusual_time_access": 0,
        },
        "brute_force": {
            "network_packet_size": 400, "protocol_type": "TCP", "login_attempts": 12,
            "session_duration": 40, "encryption_used": "None", "ip_reputation_score": 0.85,
            "failed_logins": 6, "browser_type": "Unknown", "unusual_time_access": 1,
        },
    }

    def post(self, request):
        preset_name = request.data.get("preset")
        features = self.PRESETS.get(preset_name) or request.data.get("features")

        if not features:
            return Response(
                {"detail": "Fournir 'preset' (normal|brute_force) ou 'features' personnalisees."},
                status=400,
            )

        proba = predict(features)
        return Response({
            "attack_detected": proba >= settings.BLOCK_THRESHOLD,
            "probability": round(proba, 4),
            "simulated": True,
        })
