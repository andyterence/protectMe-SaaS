# protectme-middleware

Middleware Django qui protège votre site en temps réel en interrogeant
l'API de détection d'intrusion protectMe à chaque requête.

## Installation

```bash
pip install protectme-middleware
```

## Configuration (`settings.py`)

```python
MIDDLEWARE = [
    ...
    "django.contrib.sessions.middleware.SessionMiddleware",  # doit être AVANT protectme
    "protectme.middleware.ProtectMeMiddleware",
    ...
]

PROTECTME_API_KEY = "sk_live_xxx"   # fournie lors de votre inscription sur protectme.com
```

## Options avancées (toutes optionnelles)

| Paramètre | Défaut | Description |
|---|---|---|
| `PROTECTME_API_URL` | `https://api.protectme.com` | À changer uniquement pour un environnement de test |
| `PROTECTME_TIMEOUT` | `0.3` | Secondes avant abandon de l'appel API |
| `PROTECTME_FAIL_OPEN` | `True` | Si `False`, bloque le trafic quand l'API est indisponible (déconseillé sauf besoin de sécurité strict) |
| `PROTECTME_ENABLED` | `True` | Kill switch pour désactiver sans redéployer |
| `PROTECTME_EXCLUDED_PATHS` | `("/static/", "/media/", "/favicon.ico")` | Chemins jamais analysés |

## Suivre les tentatives de connexion (recommandé)

Le middleware ne peut pas deviner ce qu'est une "tentative de connexion"
c'est propre à votre logique métier. Appelez ce helper dans votre vue de login :

```python
from protectme.features import record_login_attempt

def login_view(request):
    success = authenticate_user(request)
    record_login_attempt(request, success=success)
    ...
```

## Développement / tests

```bash
pip install -e ".[test]"
pytest tests/
```

## Important : requiert `SessionMiddleware`

`ProtectMeMiddleware` doit être placé **après**
`django.contrib.sessions.middleware.SessionMiddleware` dans `MIDDLEWARE`,
car il stocke l'état cumulatif (tentatives de connexion, durée de session)
dans `request.session`.
