"""
Middleware Django distribuable, installé sur le serveur du site client.

Configuration attendue dans settings.py du site client :

    PROTECTME_API_KEY = "sk_live_xxx"          # obligatoire
    PROTECTME_API_URL = "https://api.protectme.com"  # a une valeur par défaut
    PROTECTME_TIMEOUT = 0.3                     # secondes, défaut 0.3
    PROTECTME_FAIL_OPEN = True                  # défaut True (recommandé)
    PROTECTME_ENABLED = True                    # kill switch, défaut True
    PROTECTME_EXCLUDED_PATHS = ["/static/", "/media/", "/health/"]
"""
import logging
import time

from django.conf import settings
from django.http import HttpResponseForbidden

from .client import ProtectMeClient
from .exceptions import ProtectMeConfigError, ProtectMeDetectionError
from .features import extract_features

logger = logging.getLogger("protectme")

DEFAULT_API_URL = "https://api.protectme.com"
DEFAULT_TIMEOUT = 0.3
DEFAULT_EXCLUDED_PATHS = ("/static/", "/media/", "/favicon.ico")


class ProtectMeMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response
        self.enabled = getattr(settings, "PROTECTME_ENABLED", True)

        if not self.enabled:
            # Kill switch actif : on ne valide même pas la config, le middleware
            # devient un simple pass-through. Utile pour désactiver en urgence
            # sans devoir redéployer du code.
            logger.warning("protectme désactivé via PROTECTME_ENABLED=False")
            return

        api_key = getattr(settings, "PROTECTME_API_KEY", None)
        if not api_key:
            # On échoue fort et tôt (au démarrage du serveur), jamais en silence.
            # Un oubli de clé API ne doit pas se traduire par "tout le monde
            # laisse passer sans le savoir".
            raise ProtectMeConfigError(
                "PROTECTME_API_KEY manquant dans settings.py. "
                "Définissez PROTECTME_ENABLED = False si vous voulez désactiver "
                "explicitement la protection."
            )

        self.fail_open = getattr(settings, "PROTECTME_FAIL_OPEN", True)
        self.excluded_paths = tuple(
            getattr(settings, "PROTECTME_EXCLUDED_PATHS", DEFAULT_EXCLUDED_PATHS)
        )
        self.client = ProtectMeClient(
            api_url=getattr(settings, "PROTECTME_API_URL", DEFAULT_API_URL),
            api_key=api_key,
            timeout=getattr(settings, "PROTECTME_TIMEOUT", DEFAULT_TIMEOUT),
        )

    def __call__(self, request):
        if not self.enabled or self._is_excluded(request.path):
            return self.get_response(request)

        decision = self._evaluate(request)

        if decision is True:
            logger.warning("protectme: requête bloquée path=%s", request.path)
            return HttpResponseForbidden("Requête bloquée par des mesures de sécurité.")

        return self.get_response(request)

    def _is_excluded(self, path: str) -> bool:
        """Évite de scorer les assets statiques, favicons, health checks...

        Sans ce filtre, chaque requête vers /static/style.css appellerait
        aussi l'API centrale un gaspillage pur de latence et de quota
        d'appels API pour du trafic qui n'a aucune valeur à analyser.
        """
        return path.startswith(self.excluded_paths)

    def _evaluate(self, request) -> bool:
        """Retourne True si la requête doit être bloquée, False sinon.

        Ne lève jamais d'exception vers l'appelant : toute erreur est
        absorbée ici et traduite selon la politique fail-open/fail-closed.
        """
        t0 = time.monotonic()
        try:
            features = extract_features(request)
            result = self.client.detect(features)
            return bool(result.get("attack_detected", False))
        except ProtectMeDetectionError as exc:
            logger.error("protectme: appel API indisponible (%s), fail_open=%s", exc, self.fail_open)
            return not self.fail_open  # fail_open=True -> ne bloque pas -> return False
        finally:
            elapsed_ms = (time.monotonic() - t0) * 1000
            if elapsed_ms > 50:
                logger.info("protectme: évaluation lente (%.1fms) path=%s", elapsed_ms, request.path)
