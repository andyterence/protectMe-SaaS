from django.conf import settings
from django.contrib.auth import authenticate
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework_simplejwt.tokens import RefreshToken

from .serializers import LoginSerializer, UserSerializer

REFRESH_COOKIE_NAME = "protectme_refresh"
REFRESH_COOKIE_MAX_AGE = 60 * 60 * 24 * 7  # 7 jours - doit matcher SIMPLE_JWT.REFRESH_TOKEN_LIFETIME


def _set_refresh_cookie(response: Response, refresh_token: str) -> None:
    """Le refresh token ne part JAMAIS dans le corps JSON - uniquement dans un
    cookie httpOnly. Voir AuthContext.tsx / apiClient.ts cote frontend, ce
    cookie est ce que tryRestoreSession() exploite au demarrage de l'app.
    """
    response.set_cookie(
        REFRESH_COOKIE_NAME,
        refresh_token,
        max_age=REFRESH_COOKIE_MAX_AGE,
        httponly=True,
        secure=not settings.DEBUG,  # True en prod (HTTPS obligatoire) ; False en dev http local
        samesite="Lax",
        path="/api/auth/",  # envoye uniquement vers les endpoints d'auth, pas sur toute l'API
    )


class LoginView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = authenticate(
            request,
            username=serializer.validated_data["email"],
            password=serializer.validated_data["password"],
        )
        if user is None:
            return Response({"detail": "Identifiants incorrects."}, status=401)

        refresh = RefreshToken.for_user(user)
        response = Response({"access": str(refresh.access_token)})
        _set_refresh_cookie(response, str(refresh))
        return response


class RefreshView(APIView):
    """Pas de rotation du refresh token ici (simplicite assumee, sans
    l'app rest_framework_simplejwt.token_blacklist) : un refresh token vole
    reste valide jusqu'a expiration naturelle (7 jours). Attenue par sa
    protection httpOnly+Secure ; a durcir avec blacklist + rotation si le
    projet passe en production avec des donnees sensibles.
    """
    permission_classes = [AllowAny]

    def post(self, request):
        raw_refresh = request.COOKIES.get(REFRESH_COOKIE_NAME)
        if not raw_refresh:
            return Response({"detail": "Aucune session active."}, status=401)

        try:
            refresh = RefreshToken(raw_refresh)
        except TokenError:
            return Response({"detail": "Session expiree."}, status=401)

        return Response({"access": str(refresh.access_token)})


class LogoutView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        response = Response({"detail": "Deconnecte."})
        response.delete_cookie(REFRESH_COOKIE_NAME, path="/api/auth/")
        return response


class MeView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        return Response(UserSerializer(request.user).data)
