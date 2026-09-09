from django.conf import settings
from django.contrib.auth import authenticate
from .serializers import (
    RegisterSerializer,
    ChangePasswordSerializer,
    DeleteAccountSerializer,
    UserAdminSerializer,
    LoginSerializer,
    UserSerializer,
)
from django.db.models import Count
from .models import User
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.exceptions import NotFound, PermissionDenied


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
    
class RegisterView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()

        refresh = RefreshToken.for_user(user)
        response = Response({"access": str(refresh.access_token)}, status=201)
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
    
class ChangePasswordView(APIView):
    """Necessite le mot de passe actuel pour toute modification - meme un
    utilisateur deja authentifie ne doit pas pouvoir changer son mot de
    passe sur une session volee sans reconnaitre l'ancien secret.
    """
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = ChangePasswordSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = request.user
        if not user.check_password(serializer.validated_data["current_password"]):
            return Response({"detail": "Mot de passe actuel incorrect."}, status=400)

        user.set_password(serializer.validated_data["new_password"])
        user.save(update_fields=["password"])
        return Response({"detail": "Mot de passe mis a jour."})

class DeleteAccountView(APIView):
    """Suppression definitive du compte, protegee par re-saisie du mot de
    passe - meme regle de securite que ChangePasswordView : une session
    active ne suffit pas a elle seule pour une action irreversible.
    """
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = DeleteAccountSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = request.user
        if not user.check_password(serializer.validated_data["password"]):
            return Response({"detail": "Mot de passe incorrect."}, status=400)

        response = Response({"detail": "Compte supprime."})
        response.delete_cookie(REFRESH_COOKIE_NAME, path="/api/auth/")
        user.delete()
        return response
    
class UserListView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        if request.user.role != "admin":
            raise PermissionDenied("Réservé à l'Admin.")
        users = User.objects.annotate(sites_count=Count("sites", distinct=True)).order_by("-date_joined")
        return Response(UserAdminSerializer(users, many=True).data)


class UserToggleActiveView(APIView):
    """Desactive/reactive un compte SANS le supprimer - contrairement a
    DeleteAccountView qui est definitif, ici c'est reversible : utile pour
    suspendre un compte suspect sans perdre ses donnees.
    """
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def patch(self, request, pk):
        if request.user.role != "admin":
            raise PermissionDenied("Réservé à l'Admin.")
        try:
            target = User.objects.get(pk=pk)
        except User.DoesNotExist:
            raise NotFound("Utilisateur introuvable.")
        if target.id == request.user.id:
            return Response({"detail": "Vous ne pouvez pas désactiver votre propre compte."}, status=400)

        target.is_active = not target.is_active
        target.save(update_fields=["is_active"])
        return Response(UserAdminSerializer.objects if False else UserAdminSerializer(
            User.objects.annotate(sites_count=Count("sites", distinct=True)).get(pk=target.pk)
        ).data)