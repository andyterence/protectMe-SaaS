from rest_framework.permissions import BasePermission

from .models import Site


class IsValidSite(BasePermission):
    """Utilisee sur l'endpoint /v1/detect : verifie qu'ApiKeyAuthentication
    a bien resolu un Site (peu importe l'utilisateur humain, il n'y en a pas).
    """

    def has_permission(self, request, view):
        return isinstance(request.auth, Site)
