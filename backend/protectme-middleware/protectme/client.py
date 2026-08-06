"""
Client HTTP vers l'API centrale de détection, avec un circuit breaker.

Pourquoi un circuit breaker et pas juste un timeout ?
------------------------------------------------------
Un timeout seul limite le coût d'UN appel raté (ex: 300ms). Mais si la
plateforme centrale tombe en panne, CHAQUE requête sur CHAQUE visiteur du
site client attendra quand même ces 300ms avant de fail-open. Sur un site à
fort trafic, ça peut représenter des milliers de requêtes/seconde bloquées
300ms chacune, uniquement en attente d'un service qu'on sait déjà down.

Le circuit breaker retient l'état "l'API a échoué N fois récemment" et,
au-delà d'un seuil, arrête complètement d'essayer pendant une courte période
(cooldown) : les requêtes suivantes fail-open INSTANTANÉMENT, sans attendre
le timeout. Après le cooldown, une requête "test" est retentée pour voir si
le service est revenu (état "half-open", pattern standard).
"""
import threading
import time

import requests

from .exceptions import ProtectMeDetectionError

DETECT_ENDPOINT = "/v1/detect"


class _CircuitBreaker:
    """État partagé au sein d'un seul processus (un worker Gunicorn/uWSGI).

    Limite assumée : chaque worker apprend indépendamment que l'API est down
    (pas de coordination cluster-wide type Redis). C'est un compromis
    volontaire pour éviter toute dépendance externe dans un simple package
    pip un worker qui vient de démarrer retentera l'appel une fois, ce qui
    est un coût négligeable comparé à la complexité d'un état partagé.
    """

    def __init__(self, failure_threshold: int = 5, cooldown_seconds: float = 30.0):
        self.failure_threshold = failure_threshold
        self.cooldown_seconds = cooldown_seconds
        self._failure_count = 0
        self._open_until = 0.0
        self._lock = threading.Lock()

    def is_open(self) -> bool:
        with self._lock:
            return time.time() < self._open_until

    def record_success(self) -> None:
        with self._lock:
            self._failure_count = 0
            self._open_until = 0.0

    def record_failure(self) -> None:
        with self._lock:
            self._failure_count += 1
            if self._failure_count >= self.failure_threshold:
                self._open_until = time.time() + self.cooldown_seconds


class ProtectMeClient:
    """Client HTTP minimal, une instance par processus (créée une fois par le middleware)."""

    def __init__(self, api_url: str, api_key: str, timeout: float = 0.3):
        self.api_url = api_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout
        self._breaker = _CircuitBreaker()

    def detect(self, features: dict) -> dict:
        """Appelle l'API centrale. Lève ProtectMeDetectionError en cas d'échec
        ou si le circuit est ouvert c'est au middleware appelant de décider
        de la politique fail-open/fail-closed, pas à ce client.
        """
        if self._breaker.is_open():
            raise ProtectMeDetectionError("circuit_open: API marquée indisponible, appel évité")

        try:
            response = requests.post(
                f"{self.api_url}{DETECT_ENDPOINT}",
                json=features,
                headers={"X-API-Key": self.api_key},
                timeout=self.timeout,
            )
            response.raise_for_status()
        except requests.RequestException as exc:
            self._breaker.record_failure()
            raise ProtectMeDetectionError(f"appel API échoué: {exc}") from exc

        self._breaker.record_success()
        return response.json()
