"""
Reproduit le pipeline entraine dans d_cleaning.ipynb, pour produire l'artefact
que detection/ml.py charge au demarrage du serveur.

Usage : python scripts/train_model.py /chemin/vers/cybersecurity_intrusion_data.csv
"""
import sys
from pathlib import Path

import joblib
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, RobustScaler

NUMERIC_FEATURES = [
    "network_packet_size", "login_attempts", "session_duration",
    "ip_reputation_score", "failed_logins", "unusual_time_access",
]
CATEGORICAL_FEATURES = ["protocol_type", "encryption_used", "browser_type"]

OUTPUT_PATH = Path(__file__).resolve().parent.parent / "detection" / "ml_artifacts" / "model_intrusion_detection.pkl"


def main(csv_path: str):
    df = pd.read_csv(csv_path)
    df["encryption_used"] = df["encryption_used"].fillna("None")

    X = df.drop(columns=["session_id", "attack_detected"])
    y = df["attack_detected"]

    X_train, _, y_train, _ = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

    preprocessor = ColumnTransformer([
        ("num", RobustScaler(), NUMERIC_FEATURES),
        ("cat", OneHotEncoder(handle_unknown="ignore"), CATEGORICAL_FEATURES),
    ])
    model = Pipeline([
        ("preprocessor", preprocessor),
        ("classifier", RandomForestClassifier(n_estimators=300, random_state=42, n_jobs=-1)),
    ])
    model.fit(X_train, y_train)

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, OUTPUT_PATH)
    print(f"Modele sauvegarde : {OUTPUT_PATH}")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "cybersecurity_intrusion_data.csv")
