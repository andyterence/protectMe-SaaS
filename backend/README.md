# protectme-backend

Plateforme centrale : API REST (Django REST Framework), authentification
JWT (dashboard) + clé API (sites clients), moteur ML embarqué, MySQL.

## Installation

```bash
python -m venv venv
source venv/bin/activate        # venv\Scripts\activate sous Windows
pip install -r requirements.txt
```

## Base de données

Le projet est configuré pour **MySQL** via PyMySQL (aucune compilation
native requise, contrairement à `mysqlclient`). Crée la base et exporte les
variables d'environnement (ou mets-les dans un fichier `.env` chargé par ton
shell/IDE) :

```bash
mysql -u root -p -e "CREATE DATABASE protectme CHARACTER SET utf8mb4;"

export DB_NAME=protectme
export DB_USER=root
export DB_PASSWORD=ton_mot_de_passe
export DB_HOST=127.0.0.1
export DB_PORT=3306
```

Puis :
```bash
python manage.py migrate
python manage.py createsuperuser   # pour te connecter à /admin/ et créer le premier User/Admin
python manage.py runserver
```

## Tester sans MySQL installé

Pas besoin de MySQL pour lancer les tests localement : un module
`settings_test.py` bascule sur SQLite (uniquement pour les tests, la
config MySQL de `settings.py` reste celle utilisée en développement/prod
réels) :

```bash
export DJANGO_SETTINGS_MODULE=protectme_backend.settings_test
python manage.py migrate
python manage.py test accounts sites detection -v 2
```

25 tests couvrent : le flux JWT complet (login/refresh/me/logout), l'isolation
multi-tenant des sites, le endpoint `/api/v1/detect` (trafic normal vs
attaque, stockage sélectif, rejet des clés API invalides), l'enrichissement
du score de réputation IP, les écrans du dashboard ci-dessous, les tickets
de support et la commande de purge.

## Endpoints du panneau de contrôle (dashboard)

Au-delà de l'auth et de `/v1/detect`, le backend expose maintenant les
écrans du panneau type "webful.fr" :

| Endpoint | Méthode | Auth | Description |
|---|---|---|---|
| `/api/v1/attack-logs/` | GET | JWT | Liste des attaques détectées (filtrable `?site=&status=`) "qui a attaqué" |
| `/api/v1/attack-logs/{id}/review/` | PATCH | JWT | Requalifie en `confirmed`/`false_positive` alimente le futur réentraînement |
| `/api/v1/connection-logs/` | GET | JWT | Trafic **complet**, attaques ou non "qui se connecte" |
| `/api/v1/simulate/` | POST | JWT | Rejoue une prédiction (`{"preset": "normal"}` ou `"brute_force"`, ou `features` custom) **jamais persisté** |
| `/api/tickets/` | GET/POST | JWT | Tickets de support (User : les siens ; Admin : tous) |
| `/api/tickets/{id}/` | PATCH | JWT (Admin) | Répondre / changer le statut d'un ticket |

## Purge automatique de `ConnectionLog`

Contrairement à `AttackLog` (sélectif par nature), `ConnectionLog` grandit
avec **chaque** requête passant par le middleware. Un garde-fou est prévu,
sans dépendance supplémentaire (pas de Celery) juste une commande Django
à planifier en cron côté serveur :

```bash
# crontab -e, exécution quotidienne à 3h du matin
0 3 * * * cd /chemin/vers/protectme-backend && venv/bin/python manage.py cleanup_old_logs --days=30
```

## Le modèle ML

`detection/ml_artifacts/model_intrusion_detection.pkl` est déjà entraîné
(reproduction du pipeline de ton notebook `d_cleaning.ipynb`, RandomForest +
RobustScaler + OneHotEncoder). Pour le regénérer à partir d'un CSV plus
récent :

```bash
python scripts/train_model.py chemin/vers/cybersecurity_intrusion_data.csv
```

## Endpoints exposés

| Endpoint | Méthode | Auth | Description |
|---|---|---|---|
| `/api/auth/login/` | POST | — | Retourne l'access token, pose le refresh en cookie httpOnly |
| `/api/auth/refresh/` | POST | cookie | Nouvel access token |
| `/api/auth/logout/` | POST | — | Supprime le cookie refresh |
| `/api/auth/me/` | GET | JWT | Utilisateur courant |
| `/api/sites/` | GET/POST | JWT | Liste/crée les sites du User connecté (Admin voit tout) |
| `/api/v1/detect` | POST | Clé API (`X-API-Key`) | Appelé par le middleware distribuable, jamais par le dashboard |

**Important pour le middleware distribuable déjà livré** : configure
`PROTECTME_API_URL` côté site client avec l'URL de CE backend suivie de
`/api` (ex: `https://tondomaine.com/api`), puisque le middleware concatène
lui-même `/v1/detect`.

## Décisions de sécurité notables

- **Deux systèmes d'auth séparés, jamais mélangés** : `JWTAuthentication`
  pour les humains (dashboard), `ApiKeyAuthentication` pour les sites
  clients (`/v1/detect`). Aucune vue n'accepte les deux.
- **Clé API jamais stockée en clair** : seul son hash SHA-256 est en base ;
  la valeur brute n'est affichée qu'une fois, à la création du site.
- **Refresh token en cookie `httpOnly`+`Secure`** (jamais dans le JSON ni
  `localStorage`), pour limiter l'exposition en cas de faille XSS côté
  frontend.
- **Pas de rotation du refresh token** (choix de simplicité assumé, sans
  l'app `token_blacklist`) : à durcir si le projet évolue vers une charge
  de données plus sensible.
