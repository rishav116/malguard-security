"""
Training pipeline for MALGUARD AI Random Forest Malware Classifier.
Trains a reproducible, stratified scikit-learn RandomForestClassifier on the
verified PE Malware Dataset, evaluates multi-class metrics, and saves the
serialized model, feature schema, and evaluation metrics.
"""

import os
import sys
import json
from datetime import datetime, timezone
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    confusion_matrix,
    classification_report
)
import joblib

# Ensure backend root is on sys.path
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
BACKEND_ROOT = os.path.abspath(os.path.join(CURRENT_DIR, "..", ".."))
if BACKEND_ROOT not in sys.path:
    sys.path.insert(0, BACKEND_ROOT)

from app.ml.pe_feature_extractor import FEATURE_NAMES

DATASET_PATH = os.path.join(CURRENT_DIR, "data", "dataset_malwares.csv")
MODELS_DIR = os.path.join(CURRENT_DIR, "models")
MODEL_OUTPUT_PATH = os.path.join(MODELS_DIR, "random_forest_v1.pkl")
SCHEMA_OUTPUT_PATH = os.path.join(MODELS_DIR, "feature_schema.json")
METRICS_OUTPUT_PATH = os.path.join(MODELS_DIR, "metrics.json")
CONFIG_OUTPUT_PATH = os.path.join(MODELS_DIR, "training_config.json")

def train_malware_classifier():
    print("=" * 60)
    print("MALGUARD AI — Random Forest Classifier Training Pipeline")
    print("=" * 60)

    # 1. Load dataset
    if not os.path.exists(DATASET_PATH):
        raise FileNotFoundError(f"Dataset not found at {DATASET_PATH}. Please run download_dataset.py first.")

    print(f"Loading dataset from: {DATASET_PATH}")
    df = pd.read_csv(DATASET_PATH)
    raw_count = len(df)
    print(f"Loaded raw samples: {raw_count}")

    # 2. Check and clean duplicates
    duplicates = df.duplicated(subset=FEATURE_NAMES).sum()
    print(f"Duplicate sample vectors found: {duplicates}")
    if duplicates > 0:
        print("Deduplicating to prevent data leakage...")
        df = df.drop_duplicates(subset=FEATURE_NAMES).reset_index(drop=True)
        print(f"Remaining samples after deduplication: {len(df)}")

    # 3. Target and Features alignment
    assert "Malware" in df.columns, "Target column 'Malware' missing from dataset"
    y = df["Malware"].astype(int).values

    # Verify all 69 features are present
    missing_features = [f for f in FEATURE_NAMES if f not in df.columns]
    if missing_features:
        raise ValueError(f"Dataset is missing required features: {missing_features}")

    # Extract exact features in canonical order
    X = df[FEATURE_NAMES].astype(np.float64).values
    print(f"Features matrix shape: {X.shape} (Canonical feature count: {len(FEATURE_NAMES)})")

    # Class balance summary
    benign_count = int(np.sum(y == 0))
    malware_count = int(np.sum(y == 1))
    total_count = len(y)
    print(f"Class distribution: Benign (0)={benign_count} ({benign_count/total_count*100:.1f}%), Malware (1)={malware_count} ({malware_count/total_count*100:.1f}%)")

    # 4. Stratified Train / Test Split
    test_size = 0.20
    random_state = 42
    print(f"Splitting dataset: 80% Train, 20% Held-Out Test (stratified, random_state={random_state})...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=test_size, random_state=random_state, stratify=y
    )
    print(f"Train set: {len(y_train)} samples | Test set: {len(y_test)} samples")

    # 5. Model Initialization and Training
    rf_params = {
        "n_estimators": 120,
        "max_depth": 16,
        "min_samples_split": 4,
        "min_samples_leaf": 2,
        "max_features": "sqrt",
        "bootstrap": True,
        "oob_score": True,
        "random_state": random_state,
        "n_jobs": -1
    }

    print("\nTraining RandomForestClassifier with hyper-parameters:")
    for k, v in rf_params.items():
        print(f"  {k}: {v}")

    start_time = datetime.now(timezone.utc)
    clf = RandomForestClassifier(**rf_params)
    clf.fit(X_train, y_train)
    training_duration_sec = (datetime.now(timezone.utc) - start_time).total_seconds()
    print(f"Training completed in {training_duration_sec:.2f} seconds.")
    print(f"Out-of-Bag (OOB) Score: {clf.oob_score_:.4f}")

    # 6. Evaluation on Held-Out Test Set
    print("\nEvaluating on held-out test set...")
    y_pred = clf.predict(X_test)
    y_proba = clf.predict_proba(X_test)[:, 1]

    acc = float(accuracy_score(y_test, y_pred))
    prec_macro = float(precision_score(y_test, y_pred, average="macro"))
    rec_macro = float(recall_score(y_test, y_pred, average="macro"))
    f1_macro = float(f1_score(y_test, y_pred, average="macro"))

    prec_malware = float(precision_score(y_test, y_pred, pos_label=1))
    rec_malware = float(recall_score(y_test, y_pred, pos_label=1))
    f1_malware = float(f1_score(y_test, y_pred, pos_label=1))

    prec_benign = float(precision_score(y_test, y_pred, pos_label=0))
    rec_benign = float(recall_score(y_test, y_pred, pos_label=0))
    f1_benign = float(f1_score(y_test, y_pred, pos_label=0))

    auc = float(roc_auc_score(y_test, y_proba))
    cm = confusion_matrix(y_test, y_pred)
    tn, fp, fn, tp = [int(v) for v in cm.ravel()]

    print("\nTest Evaluation Results:")
    print(f"  Accuracy:           {acc:.4f} ({acc*100:.2f}%)")
    print(f"  ROC-AUC Score:      {auc:.4f}")
    print(f"  Malware (Class 1) - Precision: {prec_malware:.4f}, Recall: {rec_malware:.4f}, F1: {f1_malware:.4f}")
    print(f"  Benign  (Class 0) - Precision: {prec_benign:.4f}, Recall: {rec_benign:.4f}, F1: {f1_benign:.4f}")
    print(f"  Confusion Matrix:   TN={tn}, FP={fp}, FN={fn}, TP={tp}")
    print(f"  False Positive Rate: {fp / (fp + tn):.4%}")
    print(f"  False Negative Rate: {fn / (fn + tp):.4%}")

    # 7. Feature Importance Analysis
    importances = clf.feature_importances_
    sorted_indices = np.argsort(importances)[::-1]
    top_features = [
        {"rank": int(i + 1), "name": FEATURE_NAMES[idx], "importance": float(round(importances[idx], 5))}
        for i, idx in enumerate(sorted_indices[:20])
    ]

    print("\nTop 10 Most Influential Features:")
    for feat in top_features[:10]:
        print(f"  {feat['rank']}. {feat['name']}: {feat['importance']:.4f}")

    # 8. Save Artifacts
    os.makedirs(MODELS_DIR, exist_ok=True)

    # Save model weights
    joblib.dump(clf, MODEL_OUTPUT_PATH, compress=3)
    print(f"\nModel saved to: {MODEL_OUTPUT_PATH} ({os.path.getsize(MODEL_OUTPUT_PATH) / 1024 / 1024:.2f} MB)")

    # Save Feature Schema
    feature_schema = {
        "schema_version": "1.0.0",
        "model_name": "Random Forest PE Malware Classifier",
        "feature_count": len(FEATURE_NAMES),
        "feature_names": FEATURE_NAMES,
        "feature_types": ["float64"] * len(FEATURE_NAMES),
        "target_mapping": {
            "0": "benign",
            "1": "malicious"
        },
        "description": "Standardized 69-feature PE structural and header representation for Windows binaries.",
        "generated_at": datetime.now(timezone.utc).isoformat()
    }
    with open(SCHEMA_OUTPUT_PATH, "w", encoding="utf-8") as f:
        json.dump(feature_schema, f, indent=2)
    print(f"Feature schema saved to: {SCHEMA_OUTPUT_PATH}")

    # Save Metrics
    metrics_data = {
        "model_version": "1.0.0",
        "dataset_name": "PE Files Malware Dataset (VirusShare + Clean Windows PE)",
        "dataset_source": "Kaggle / VirusShare PE Static Analysis Repository",
        "total_samples": total_count,
        "train_samples": len(y_train),
        "test_samples": len(y_test),
        "benign_samples": benign_count,
        "malware_samples": malware_count,
        "evaluation_metrics": {
            "accuracy": round(acc, 4),
            "roc_auc": round(auc, 4),
            "oob_score": round(float(clf.oob_score_), 4),
            "macro_avg": {
                "precision": round(prec_macro, 4),
                "recall": round(rec_macro, 4),
                "f1_score": round(f1_macro, 4)
            },
            "malware_class": {
                "precision": round(prec_malware, 4),
                "recall": round(rec_malware, 4),
                "f1_score": round(f1_malware, 4)
            },
            "benign_class": {
                "precision": round(prec_benign, 4),
                "recall": round(rec_benign, 4),
                "f1_score": round(f1_benign, 4)
            },
            "confusion_matrix": {
                "true_negatives": tn,
                "false_positives": fp,
                "false_negatives": fn,
                "true_positives": tp
            },
            "rates": {
                "false_positive_rate": round(fp / (fp + tn), 5),
                "false_negative_rate": round(fn / (fn + tp), 5)
            }
        },
        "top_features": top_features,
        "trained_at": datetime.now(timezone.utc).isoformat()
    }
    with open(METRICS_OUTPUT_PATH, "w", encoding="utf-8") as f:
        json.dump(metrics_data, f, indent=2)
    print(f"Metrics saved to: {METRICS_OUTPUT_PATH}")

    # Save Config
    training_config = {
        "model_type": "RandomForestClassifier",
        "hyperparameters": rf_params,
        "data_split": {
            "test_size": test_size,
            "random_state": random_state,
            "stratified": True
        },
        "training_duration_seconds": round(training_duration_sec, 2),
        "environment": {
            "python_version": sys.version,
            "sklearn_version": pd.__version__
        }
    }
    with open(CONFIG_OUTPUT_PATH, "w", encoding="utf-8") as f:
        json.dump(training_config, f, indent=2)
    print(f"Training configuration saved to: {CONFIG_OUTPUT_PATH}")

    print("\nTraining pipeline successfully completed!")

if __name__ == "__main__":
    train_malware_classifier()

