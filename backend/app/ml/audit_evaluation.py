import os
import sys
import json
import numpy as np
import pandas as pd
from datetime import datetime, timezone
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score, roc_auc_score, confusion_matrix
)
import joblib

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
BACKEND_ROOT = os.path.abspath(os.path.join(CURRENT_DIR, "..", ".."))
if BACKEND_ROOT not in sys.path:
    sys.path.insert(0, BACKEND_ROOT)

from app.ml.pe_feature_extractor import FEATURE_NAMES, extract_features_from_pe

def run_temporal_audit():
    dataset_path = os.path.join(CURRENT_DIR, "data", "dataset_malwares.csv")
    df = pd.read_csv(dataset_path)
    
    # 1. Deduplication analysis
    raw_len = len(df)
    df_dedup = df.drop_duplicates(subset=FEATURE_NAMES).reset_index(drop=True)
    dedup_len = len(df_dedup)
    
    # 2. Temporal split analysis
    # Filter plausible timestamps (1995 to 2024)
    cutoff_ts = 1388534400  # Jan 1, 2014 00:00:00 UTC
    train_mask = (df_dedup['TimeDateStamp'] > 788918400) & (df_dedup['TimeDateStamp'] < cutoff_ts)
    test_mask = (df_dedup['TimeDateStamp'] >= cutoff_ts) & (df_dedup['TimeDateStamp'] < 1735689600)
    
    train_df = df_dedup[train_mask].reset_index(drop=True)
    test_df = df_dedup[test_mask].reset_index(drop=True)
    
    n_train_benign = int((train_df['Malware'] == 0).sum())
    n_train_malware = int((train_df['Malware'] == 1).sum())
    n_test_benign = int((test_df['Malware'] == 0).sum())
    n_test_malware = int((test_df['Malware'] == 1).sum())
    
    X_train = train_df[FEATURE_NAMES].values
    y_train = train_df['Malware'].values
    X_test = test_df[FEATURE_NAMES].values
    y_test = test_df['Malware'].values
    
    rf_temporal = RandomForestClassifier(
        n_estimators=120, max_depth=16, min_samples_split=4, min_samples_leaf=2,
        random_state=42, n_jobs=-1
    )
    rf_temporal.fit(X_train, y_train)
    
    y_pred = rf_temporal.predict(X_test)
    y_proba = rf_temporal.predict_proba(X_test)[:, 1]
    
    cm = confusion_matrix(y_test, y_pred)
    tn, fp, fn, tp = [int(v) for v in cm.ravel()]
    
    acc = float(accuracy_score(y_test, y_pred))
    auc = float(roc_auc_score(y_test, y_proba))
    prec_m = float(precision_score(y_test, y_pred, pos_label=1))
    rec_m = float(recall_score(y_test, y_pred, pos_label=1))
    f1_m = float(f1_score(y_test, y_pred, pos_label=1))
    prec_b = float(precision_score(y_test, y_pred, pos_label=0))
    rec_b = float(recall_score(y_test, y_pred, pos_label=0))
    f1_b = float(f1_score(y_test, y_pred, pos_label=0))
    
    # 3. Model without TimeDateStamp or version fields (Ablation test to measure bias reliance)
    # What if we exclude TimeDateStamp, MajorOperatingSystemVersion, MinorOperatingSystemVersion,
    # MajorSubsystemVersion, MinorSubsystemVersion, and MajorLinkerVersion?
    bias_features = [
        'TimeDateStamp',
        'MajorOperatingSystemVersion',
        'MinorOperatingSystemVersion',
        'MajorSubsystemVersion',
        'MinorSubsystemVersion',
        'MajorLinkerVersion',
        'MinorLinkerVersion'
    ]
    reduced_features = [f for f in FEATURE_NAMES if f not in bias_features]
    
    X_train_red = train_df[reduced_features].values
    X_test_red = test_df[reduced_features].values
    
    rf_ablation = RandomForestClassifier(
        n_estimators=120, max_depth=16, min_samples_split=4, min_samples_leaf=2,
        random_state=42, n_jobs=-1
    )
    rf_ablation.fit(X_train_red, y_train)
    y_pred_red = rf_ablation.predict(X_test_red)
    acc_red = float(accuracy_score(y_test, y_pred_red))
    auc_red = float(roc_auc_score(y_test, rf_ablation.predict_proba(X_test_red)[:, 1]))
    
    # 4. Existing deployed model evaluation on the temporal test set
    model_path = os.path.join(CURRENT_DIR, "models", "random_forest_v1.pkl")
    deployed_model = joblib.load(model_path)
    y_pred_deployed = deployed_model.predict(X_test)
    y_proba_deployed = deployed_model.predict_proba(X_test)[:, 1]
    
    cm_dep = confusion_matrix(y_test, y_pred_deployed)
    tn_d, fp_d, fn_d, tp_d = [int(v) for v in cm_dep.ravel()]
    acc_dep = float(accuracy_score(y_test, y_pred_deployed))
    auc_dep = float(roc_auc_score(y_test, y_proba_deployed))
    
    results = {
        "raw_sample_count": raw_len,
        "dedup_sample_count": dedup_len,
        "temporal_split": {
            "cutoff_date": "2014-01-01",
            "train_samples": len(train_df),
            "train_benign": n_train_benign,
            "train_malware": n_train_malware,
            "test_samples": len(test_df),
            "test_benign": n_test_benign,
            "test_malware": n_test_malware,
            "temporal_model_metrics": {
                "accuracy": round(acc, 4),
                "roc_auc": round(auc, 4),
                "malware_f1": round(f1_m, 4),
                "benign_f1": round(f1_b, 4),
                "confusion_matrix": {"tn": tn, "fp": fp, "fn": fn, "tp": tp}
            },
            "ablation_without_timestamps_or_versions": {
                "features_used": len(reduced_features),
                "excluded_features": bias_features,
                "accuracy": round(acc_red, 4),
                "roc_auc": round(auc_red, 4)
            },
            "deployed_model_on_temporal_test": {
                "accuracy": round(acc_dep, 4),
                "roc_auc": round(auc_dep, 4),
                "confusion_matrix": {"tn": tn_d, "fp": fp_d, "fn": fn_d, "tp": tp_d}
            }
        }
    }
    
    print(json.dumps(results, indent=2))
    return results

if __name__ == "__main__":
    run_temporal_audit()

