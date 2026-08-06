from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.authentication import JWTAuthentication

from .models import Site
from .serializers import SiteSerializer


class SiteListCreateView(APIView):
    """Reservee au dashboard (JWT) - jamais accessible via cle API.
    Isolation multi-tenant : un User ne voit que SES sites ; l'Admin
    (Developpeur du Modele) voit tout, conformement au tableau de
    permissions du cahier des charges.
    """
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        qs = Site.objects.all() if request.user.role == "admin" else Site.objects.filter(owner=request.user)
        return Response(SiteSerializer(qs, many=True).data)

    def post(self, request):
        name = request.data.get("name")
        if not name:
            return Response({"detail": "Le champ 'name' est requis."}, status=400)

        site, raw_key = Site.create_with_key(name=name, owner=request.user)
        data = SiteSerializer(site).data
        data["api_key"] = raw_key  # affichee UNE SEULE FOIS ; jamais recuperable ensuite
        return Response(data, status=201)

class SiteDetailView(APIView):
    """Suppression d'un site. Isolation multi-tenant identique a la
    liste : un User ne peut supprimer que SES sites, l'Admin peut tout."""
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def _get_owned_site(self, request, pk):
        try:
            site = Site.objects.get(pk=pk)
        except Site.DoesNotExist:
            return None
        if request.user.role != "admin" and site.owner_id != request.user.id:
            return None  # 404 plutot que 403 : ne revele pas l'existence du site
        return site

    def delete(self, request, pk):
        site = self._get_owned_site(request, pk)
        if site is None:
            return Response({"detail": "Site introuvable."}, status=404)
        site.delete()
        return Response(status=204)


class SiteRegenerateKeyView(APIView):
    """Regenere la cle API d'un site. L'ancienne cle devient invalide
    immediatement (le middleware du client cessera de fonctionner tant
    qu'il n'est pas mis a jour avec la nouvelle cle)."""
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request, pk):
        try:
            site = Site.objects.get(pk=pk)
        except Site.DoesNotExist:
            return Response({"detail": "Site introuvable."}, status=404)
        if request.user.role != "admin" and site.owner_id != request.user.id:
            return Response({"detail": "Site introuvable."}, status=404)

        raw_key = site.regenerate_key()
        data = SiteSerializer(site).data
        data["api_key"] = raw_key
        return Response(data)