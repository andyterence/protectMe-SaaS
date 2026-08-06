from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed

from .models import Site


class ApiKeyAuthentication(BaseAuthentication):
    """Authentification machine-a-machine pour le middleware distribuable.

    Volontairement distincte de JWT (accounts/authentication) : un site
    client n'est pas un "utilisateur" avec une session humaine, c'est un
    tenant identifie par une cle secrete de longue duree. On expose le
    Site resolu via request.auth, et request.user reste None (pas de
    session utilisateur associee a cet appel).
    """

    def authenticate(self, request):
        raw_key = request.META.get("HTTP_X_API_KEY")
        if not raw_key:
            return None  # laisse DRF essayer d'autres authentication_classes / renvoyer 401

        site = Site.resolve_from_raw_key(raw_key)
        if site is None:
            raise AuthenticationFailed("Cle API invalide ou site desactive.")

        return (None, site)

    def authenticate_header(self, request):
        """Sans cette methode, DRF retrograde automatiquement les erreurs
        d'authentification en 403 Forbidden au lieu de 401 Unauthorized
        (il considere qu'il n'y a "aucun moyen de s'authentifier" tant
        qu'aucun WWW-Authenticate n'est fourni). Renvoyer ce nom de schema
        suffit a obtenir le bon code HTTP.
        """
        return "Api-Key"
