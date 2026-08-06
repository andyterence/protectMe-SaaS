"""
Django settings for protectme_backend.

Config sensible via variables d'environnement (12-factor app) : aucune
valeur secrete en dur dans le code source versionne sur GitHub.
"""
import os
from datetime import timedelta
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

SECRET_KEY = os.environ.get("DJANGO_SECRET_KEY", "django-insecure-dev-only-change-in-prod")
DEBUG = os.environ.get("DJANGO_DEBUG", "True") == "True"
ALLOWED_HOSTS = os.environ.get("DJANGO_ALLOWED_HOSTS", "localhost,127.0.0.1").split(",")

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "rest_framework",
    "accounts",
    "sites",
    "detection",
    "support",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    # TODO (retour au frontend) : ajouter WhiteNoise ici pour servir le build
    # React statique directement par Django, cf. l'architecture "aucun
    # service tiers" discutee precedemment. Pas necessaire pour tester le
    # backend seul aujourd'hui.
]

ROOT_URLCONF = "protectme_backend.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "protectme_backend.wsgi.application"

# Base de donnees : MySQL comme demande par le cahier des charges, via
# PyMySQL (voir protectme_backend/__init__.py) pour eviter la compilation
# native de mysqlclient. Configurable par variables d'environnement pour ne
# jamais committer d'identifiants reels.
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.mysql",
        "NAME": os.environ.get("DB_NAME", "protectme"),
        "USER": os.environ.get("DB_USER", "root"),
        "PASSWORD": os.environ.get("DB_PASSWORD", ""),
        "HOST": os.environ.get("DB_HOST", "127.0.0.1"),
        "PORT": os.environ.get("DB_PORT", "3306"),
        "OPTIONS": {"charset": "utf8mb4"},
    }
}

AUTH_USER_MODEL = "accounts.User"

AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator"},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

LANGUAGE_CODE = "fr-fr"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True

STATIC_URL = "static/"
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

# --- Django REST Framework ---------------------------------------------
# Pas de DEFAULT_AUTHENTICATION_CLASSES global : chaque vue declare
# explicitement JWTAuthentication (humains) ou ApiKeyAuthentication (sites),
# pour ne jamais melanger accidentellement les deux mondes.
REST_FRAMEWORK = {
    "DEFAULT_PERMISSION_CLASSES": [],
}

# --- SimpleJWT -----------------------------------------------------------
SIMPLE_JWT = {
    "ACCESS_TOKEN_LIFETIME": timedelta(minutes=15),
    "REFRESH_TOKEN_LIFETIME": timedelta(days=7),
    "AUTH_HEADER_TYPES": ("Bearer",),
    "USER_ID_FIELD": "id",
}

# --- protectMe : seuils de decision (doivent matcher le pipeline entraine) ---
SUSPICION_THRESHOLD = float(os.environ.get("PROTECTME_SUSPICION_THRESHOLD", 0.3))
BLOCK_THRESHOLD = float(os.environ.get("PROTECTME_BLOCK_THRESHOLD", 0.4))
