"""
Tests du middleware, sans dépendre d'une vraie API centrale (via `responses`
qui intercepte les appels `requests` au niveau réseau).

Lancer avec : pytest tests/ --ds=tests.settings
"""
import django
import responses
from django.conf import settings
from django.http import HttpResponse
from django.test import RequestFactory


def configure_django():
    if not settings.configured:
        settings.configure(
            DEBUG=True,
            DATABASES={},
            SESSION_ENGINE="django.contrib.sessions.backends.signed_cookies",
            SECRET_KEY="test",
            PROTECTME_API_KEY="test_key",
            PROTECTME_API_URL="https://api.test.local",
            PROTECTME_TIMEOUT=0.3,
        )
        django.setup()


configure_django()

from protectme.middleware import ProtectMeMiddleware  # noqa: E402


def dummy_view(request):
    return HttpResponse("ok")


def make_request(path="/checkout/"):
    factory = RequestFactory()
    request = factory.get(path)
    request.session = {}
    return request


@responses.activate
def test_normal_traffic_passes_through():
    responses.add(
        responses.POST, "https://api.test.local/v1/detect",
        json={"attack_detected": False, "probability": 0.05}, status=200,
    )
    middleware = ProtectMeMiddleware(dummy_view)
    response = middleware(make_request())
    assert response.status_code == 200


@responses.activate
def test_attack_is_blocked():
    responses.add(
        responses.POST, "https://api.test.local/v1/detect",
        json={"attack_detected": True, "probability": 0.94}, status=200,
    )
    middleware = ProtectMeMiddleware(dummy_view)
    response = middleware(make_request())
    assert response.status_code == 403


@responses.activate
def test_fail_open_on_api_timeout():
    """Si l'API centrale échoue, le trafic doit passer (comportement par défaut)."""
    responses.add(responses.POST, "https://api.test.local/v1/detect", status=500)
    middleware = ProtectMeMiddleware(dummy_view)
    response = middleware(make_request())
    assert response.status_code == 200  # fail-open : on n'a pas bloqué un visiteur légitime


@responses.activate
def test_circuit_breaker_opens_after_repeated_failures():
    """Après 5 échecs, le breaker doit s'ouvrir : requests.post ne doit plus
    être appelé du tout, la 6e évaluation doit fail-open instantanément.
    """
    responses.add(responses.POST, "https://api.test.local/v1/detect", status=500)
    middleware = ProtectMeMiddleware(dummy_view)

    for _ in range(5):
        middleware(make_request())

    calls_before = len(responses.calls)
    middleware(make_request())  # 6e appel : circuit doit être ouvert
    assert len(responses.calls) == calls_before  # aucun nouvel appel HTTP émis


def test_excluded_paths_skip_detection_entirely():
    """Les assets statiques ne doivent déclencher AUCUN appel réseau."""
    middleware = ProtectMeMiddleware(dummy_view)
    request = make_request(path="/static/app.css")
    response = middleware(request)  # si un appel réseau était tenté, le test planterait (pas de mock)
    assert response.status_code == 200