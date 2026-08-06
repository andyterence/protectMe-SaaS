"""
Chargement et inference du modele - jamais reentraine a la volee ici (ca,
c'est le role du futur endpoint /model/retrain reserve a l'Admin).
"""
import threading
from pathlib import Path

import joblib
import pandas as pd

MODEL_PATH = Path(__file__).resolve().parent / "ml_artifacts" / "model_intrusion_detection.pkl"

FEATURE_COLUMNS = [
    "network_packet_size", "protocol_type", "login_attempts", "session_duration",
    "encryption_used", "ip_reputation_score", "failed_logins", "browser_type",
    "unusual_time_access",
]

_model = None
_lock = threading.Lock()


def get_model():
    """Singleton charge une seule fois par processus (voir les explications
    sur ce meme piege de performance dans le middleware distribuable) :
    joblib.load() coute des dizaines de ms, inacceptable a chaque requete.
    """
    global _model
    if _model is None:
        with _lock:  # double-checked locking : evite un chargement en double
            if _model is None:  # si 2 threads arrivent simultanement au 1er appel
                _model = joblib.load(MODEL_PATH)
    return _model


def enrich_ip_reputation(ip: str) -> float:
    """Calcule un score de reputation a partir de l'historique MULTI-TENANT.
    C'est la valeur ajoutee concrete de la centralisation : un site client
    seul ne verrait jamais qu'une IP a deja attaque un AUTRE site. Version
    simple : proportion d'attaques confirmees parmi les logs passes pour
    cette IP, tous sites confondus.
    """
    from .models import AttackLog  # import tardif : evite un cycle au chargement de l'app

    qs = AttackLog.objects.filter(ip=ip)
    total = qs.count()
    if total == 0:
        return 0.0
    confirmed = qs.filter(status=AttackLog.Status.CONFIRMED).count()
    return round(confirmed / total, 4)


def predict(raw_features: dict) -> float:
    """Renvoie la probabilite d'attaque (0.0 a 1.0) a partir du dict de
    features envoye par le middleware distribuable.
    """
    row = dict(raw_features)
    client_ip = row.pop("_client_ip", "") or ""

    if row.get("ip_reputation_score") is None:
        row["ip_reputation_score"] = enrich_ip_reputation(client_ip)

    df = pd.DataFrame([{col: row.get(col) for col in FEATURE_COLUMNS}])
    proba = get_model().predict_proba(df)[0, 1]
    return float(proba)