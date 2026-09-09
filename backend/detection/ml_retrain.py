"""
Reentrainement du modele a partir des AttackLog requalifies par un humain.

Limite assumee (a garder en tete) : AttackLog ne contient que du trafic deja
juge suspect par le modele courant (proba >= SUSPICION_THRESHOLD), jamais de
trafic normal en dessous de ce seuil. Le reentrainement affine donc la
frontiere de decision sur les cas ambigus deja detectes, mais ne reapprend
pas ce qu'est du trafic normal "evident". C'est un vrai biais methodologique,
pas juste une limitation temporaire.
"""
import shutil

import joblib
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, RobustScaler

from .ml import FEATURE_COLUMNS, MODEL_PATH
from .models import AttackLog

NUMERIC_FEATURES = [
    "network_packet_size", "login_attempts", "session_duration",
    "ip_reputation_score", "failed_logins", "unusual_time_access",
]
CATEGORICAL_FEATURES = ["protocol_type", "encryption_used", "browser_type"]

# En dessous de ce seuil par classe, on refuse de reentrainer : un modele
# entraine sur trop peu d'exemples degraderait la detection en production.
MIN_SAMPLES_PER_CLASS = 20


class InsufficientDataError(Exception):
    """Levee quand il n'y a pas assez de logs requalifies pour reentrainer
    en toute securite."""


def get_dataset_counts() -> dict:
    confirmed = AttackLog.objects.filter(status=AttackLog.Status.CONFIRMED).count()
    false_positive = AttackLog.objects.filter(status=AttackLog.Status.FALSE_POSITIVE).count()
    pending = AttackLog.objects.filter(status=AttackLog.Status.PENDING).count()
    return {
        "confirmed": confirmed,
        "false_positive": false_positive,
        "pending": pending,
        "min_required_per_class": MIN_SAMPLES_PER_CLASS,
        "ready_to_retrain": confirmed >= MIN_SAMPLES_PER_CLASS and false_positive >= MIN_SAMPLES_PER_CLASS,
    }


def _build_training_dataframe() -> pd.DataFrame:
    reviewed = AttackLog.objects.filter(
        status__in=[AttackLog.Status.CONFIRMED, AttackLog.Status.FALSE_POSITIVE]
    )
    rows, labels = [], []
    for log in reviewed.iterator():
        rows.append({col: log.features.get(col) for col in FEATURE_COLUMNS})
        labels.append(1 if log.status == AttackLog.Status.CONFIRMED else 0)

    df = pd.DataFrame(rows)
    df["attack_detected"] = labels
    return df


def retrain_model() -> dict:
    """Reentraine et remplace le modele en production de facon SYNCHRONE.

    Bloquant par design pour l'instant (pas de Celery/tache de fond dans
    cette stack) : acceptable pour un volume de projet, a revoir avant
    une mise en production a plus grande echelle.
    """
    df = _build_training_dataframe()
    n_confirmed = int((df["attack_detected"] == 1).sum())
    n_false_positive = int((df["attack_detected"] == 0).sum())

    if n_confirmed < MIN_SAMPLES_PER_CLASS or n_false_positive < MIN_SAMPLES_PER_CLASS:
        raise InsufficientDataError(
            f"Pas assez de données requalifiées pour réentraîner en sécurité "
            f"({n_confirmed} confirmées, {n_false_positive} faux positifs"
            f"minimum {MIN_SAMPLES_PER_CLASS} de chaque requis)."
        )

    X = df.drop(columns=["attack_detected"])
    y = df["attack_detected"]

    preprocessor = ColumnTransformer([
        ("num", RobustScaler(), NUMERIC_FEATURES),
        ("cat", OneHotEncoder(handle_unknown="ignore"), CATEGORICAL_FEATURES),
    ])
    model = Pipeline([
        ("preprocessor", preprocessor),
        ("classifier", RandomForestClassifier(n_estimators=300, random_state=42, n_jobs=-1)),
    ])
    model.fit(X, y)

    # Sauvegarde de l'ancien modele avant ecrasement, pour pouvoir revenir
    # en arriere manuellement en cas de regression de qualite.
    if MODEL_PATH.exists():
        shutil.copy(MODEL_PATH, MODEL_PATH.with_suffix(".pkl.bak"))

    joblib.dump(model, MODEL_PATH)

    # Invalide le singleton charge en memoire (voir get_model() dans ml.py)
    # pour que le PROCHAIN appel a predict() recharge le nouveau fichier.
    # Limite assumee : sur un deploiement multi-worker, seul CE worker est
    # invalide, les autres processus continuent avec l'ancien modele en
    # memoire jusqu'a leur propre redemarrage.
    from . import ml
    ml._model = None

    return {"trained_on": len(df), "confirmed": n_confirmed, "false_positive": n_false_positive}