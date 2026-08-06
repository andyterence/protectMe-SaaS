"""
Extraction des features à partir d'une requête Django.

Point de conception important : toutes les features du modèle ne sont pas
mesurables côté client. On distingue trois catégories :

1. Mesurables directement sur cette requête (network_packet_size, encryption_used,
   browser_type, unusual_time_access, protocol_type).
2. Mesurables mais cumulatives sur la session (login_attempts, failed_logins,
   session_duration) -> on les stocke dans request.session, qui vit déjà sur
   le serveur du client (DB ou cache local), on ne réinvente rien.
3. Impossible à connaître localement (ip_reputation_score) -> on envoie `None`
   et c'est la plateforme centrale qui l'enrichit à partir de son historique
   multi-tenant.
"""
import time
from datetime import datetime


BROWSER_SIGNATURES = [
    ("Edg/", "Edge"),       # Edge doit être testé AVANT Chrome (son UA contient "Chrome/")
    ("Chrome/", "Chrome"),
    ("Firefox/", "Firefox"),
    ("Safari/", "Safari"),  # Safari doit être testé APRÈS Chrome (Chrome contient aussi "Safari/")
]


def parse_browser(user_agent: str) -> str:
    """Heuristique simple de détection de navigateur depuis le User-Agent.

    Le modèle a été entraîné sur seulement 5 catégories
    (Chrome, Firefox, Edge, Safari, Unknown).
    """
    if not user_agent:
        return "Unknown"
    for signature, name in BROWSER_SIGNATURES:
        if signature in user_agent:
            return name
    return "Unknown"


def get_client_ip(request) -> str:
    """Récupère l'IP réelle du visiteur, en tenant compte d'un éventuel proxy/CDN.

    X-Forwarded-For peut contenir une chaîne d'IPs si plusieurs proxies sont
    traversés ; la première valeur est celle du client d'origine.
    """
    forwarded = request.META.get("HTTP_X_FORWARDED_FOR")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.META.get("REMOTE_ADDR", "")


def _get_session_state(request) -> dict:
    """Initialise (une seule fois) l'état cumulatif stocké dans la session Django.

    Utilise request.session, qui existe déjà dans n'importe quelle app Django
    (backend par défaut : DB, ou cache si le client l'a configuré ainsi).
    Aucune nouvelle dépendance introduite par le middleware.
    """
    if "protectme_state" not in request.session:
        request.session["protectme_state"] = {
            "session_start": time.time(),
            "login_attempts": 0,
            "failed_logins": 0,
        }
    return request.session["protectme_state"]


def record_login_attempt(request, success: bool) -> None:
    """Point d'extension à appeler explicitement dans la vue de login du client.

    Le middleware ne peut pas deviner tout seul ce qu'est une "tentative de
    connexion" (ça dépend entièrement de la logique métier du site client).
    On expose donc ce helper que le développeur du site client appelle lui-même :

        from protectme.features import record_login_attempt

        def login_view(request):
            ok = authenticate_user(...)
            record_login_attempt(request, success=ok)
            ...
    """
    state = _get_session_state(request)
    state["login_attempts"] += 1
    if not success:
        state["failed_logins"] += 1
    request.session["protectme_state"] = state
    request.session.modified = True


def extract_features(request) -> dict:
    """Construit le dictionnaire de features envoyé à l'API de détection.

    Le format et les noms de clés DOIVENT rester synchronisés avec le
    ColumnTransformer entraîné côté plateforme centrale (numeric_features /
    categorical_features) c'est le contrat d'API, toute modification ici
    nécessite une version majeure du package (cf. semver dans pyproject.toml).
    """
    state = _get_session_state(request)
    now = datetime.now()

    body_size = len(request.body) if request.body else 0
    headers_size = sum(len(k) + len(str(v)) for k, v in request.META.items() if k.startswith("HTTP_"))

    return {
        # Mesurable directement sur cette requête
        "network_packet_size": body_size + headers_size,
        "protocol_type": "TCP",  # HTTP(S) classique tourne toujours sur TCP
        "encryption_used": "AES" if request.is_secure() else "None",
        "browser_type": parse_browser(request.META.get("HTTP_USER_AGENT", "")),
        "unusual_time_access": int(now.hour < 6 or now.hour >= 22),

        # Cumulatif, stocké dans la session Django du site client
        "login_attempts": state["login_attempts"],
        "failed_logins": state["failed_logins"],
        "session_duration": round(time.time() - state["session_start"], 2),

        # Volontairement absent : enrichi côté plateforme centrale
        "ip_reputation_score": None,

        # Métadonnée utile côté serveur pour l'enrichissement IP, pas une feature du modèle
        "_client_ip": get_client_ip(request),
    }
