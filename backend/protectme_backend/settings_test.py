"""
Utilise UNIQUEMENT pour faire tourner les tests/migrations dans un
environnement sans serveur MySQL installe. Le fichier settings.py de
production reste configure pour MySQL (cf. cahier des charges) - ce
module ne fait que remplacer DATABASES, tout le reste est identique.
"""
from .settings import *  # noqa: F401,F403

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": BASE_DIR / "test_db.sqlite3",
    }
}
