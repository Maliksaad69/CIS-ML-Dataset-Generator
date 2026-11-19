#!/usr/bin/env python3
"""
CyberGuard ML Evaluation Suite for FYP.
1. Supervised Learning: Risk Prediction (with and without Target Leakage discussion)
2. Anomaly Detection: Unsupervised Isolation Forest without risk labels
3. Temporal Analysis: Delta metrics and security state degradation/improvement trajectories
"""

import os
import json
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split, StratifiedKFold, cross_validate
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score, roc_auc_score,
    classification_report, confusion_matrix
)

from pipeline.config import (
    OUTPUT_SUPERVISED_DATASET,
    OUTPUT_ANOMALY_DATASET,
    OUTPUT_TEMPORAL_DATASET
)

def evaluate_supervised_learning():
    print("=" * 70)
    print("TASK 1: SUPERVISED LEARNING (HIGH RISK VS NORMAL RISK)")
    print("=" * 70)

    df = pd.read_csv(OUTPUT_SUPERVISED_DATASET)
    print(f"[+] Loaded Supervised Dataset: {len(df)} samples")
    print(f"[+] Class Balance: High Risk (1) = {(df['risk_label']==1).sum()} | Normal (0) = {(df['risk_label']==0).sum()}")

    target_col = "risk_label"
    y = df[target_col].values

    # -------------------------------------------------------------
    # Experiment A: With Compliance Score (Illustrating Target Leakage)
    # -------------------------------------------------------------
    print("\n--- Experiment A: Model with 'compliance_score' (Target Leakage Demonstration) ---")
    patch_col = "hours_since_last_patch" if "hours_since_last_patch" in df.columns else "days_since_last_patch"
    features_with_leakage = [
        "failed_audits", "passed_audits", "high_severity_failures", 
        "medium_severity_failures", "low_severity_failures", patch_col, 
        "critical_vulns", "high_vulns", "total_vulns", "os_type", "compliance_score"
    ]
    X_leak = df[features_with_leakage].values

    skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    rf_leak = RandomForestClassifier(n_estimators=100, max_depth=5, random_state=42)
    scores_leak = cross_validate(rf_leak, X_leak, y, cv=skf, scoring=['accuracy', 'precision', 'recall', 'f1', 'roc_auc'])

    print(f"  Accuracy : {scores_leak['test_accuracy'].mean():.4f} (+/- {scores_leak['test_accuracy'].std():.4f})")
    print(f"  Precision: {scores_leak['test_precision'].mean():.4f}")
    print(f"  Recall   : {scores_leak['test_recall'].mean():.4f}")
    print(f"  F1-Score : {scores_leak['test_f1'].mean():.4f}")
    print(f"  ROC-AUC  : {scores_leak['test_roc_auc'].mean():.4f}")
    print("  [!] METHODOLOGY NOTE ON TARGET LEAKAGE:")
    print("      Because risk_label is defined deterministically as (compliance_score < 70),")
    print("      retaining compliance_score yields a near-trivial classifier that merely")
    print("      re-identifies the cut-off boundary rather than learning predictive security patterns.")

    # -------------------------------------------------------------
    # Experiment B: Leakage-Free Model (Predicting Risk BEFORE Score Calculation)
    # -------------------------------------------------------------
    print("\n--- Experiment B: Leakage-Free Model (Excluding 'compliance_score') ---")
    leak_free_features = [
        "failed_audits", "passed_audits", "high_severity_failures", 
        "medium_severity_failures", "low_severity_failures", patch_col, 
        "critical_vulns", "high_vulns", "total_vulns", "os_type"
    ]
    X_clean = df[leak_free_features].values

    rf_clean = RandomForestClassifier(n_estimators=100, max_depth=5, random_state=42)
    scores_clean = cross_validate(rf_clean, X_clean, y, cv=skf, scoring=['accuracy', 'precision', 'recall', 'f1', 'roc_auc'])

    print(f"  Accuracy : {scores_clean['test_accuracy'].mean():.4f} (+/- {scores_clean['test_accuracy'].std():.4f})")
    print(f"  Precision: {scores_clean['test_precision'].mean():.4f}")
    print(f"  Recall   : {scores_clean['test_recall'].mean():.4f}")
    print(f"  F1-Score : {scores_clean['test_f1'].mean():.4f}")
    print(f"  ROC-AUC  : {scores_clean['test_roc_auc'].mean():.4f}")

    # Feature Importances for Leak-Free Model
    rf_clean.fit(X_clean, y)
    importances = pd.Series(rf_clean.feature_importances_, index=leak_free_features).sort_values(ascending=False)
    print("\n  Top Predictive Security Features for Compliance Risk:")
    for feat, imp in importances.items():
        print(f"    - {feat:25s}: {imp:.4f} ({imp*100:.1f}%)")

    # Logistic Regression comparison
    lr = LogisticRegression(max_iter=500, random_state=42)
    scores_lr = cross_validate(lr, X_clean, y, cv=skf, scoring=['accuracy', 'precision', 'recall', 'f1', 'roc_auc'])
    print(f"\n  Logistic Regression Comparison (Leak-Free): Accuracy={scores_lr['test_accuracy'].mean():.4f}, F1={scores_lr['test_f1'].mean():.4f}, ROC-AUC={scores_lr['test_roc_auc'].mean():.4f}")


def evaluate_anomaly_detection():
    print("\n" + "=" * 70)
    print("TASK 2: ANOMALY DETECTION (ISOLATION FOREST - NO LABELS USED)")
    print("=" * 70)

    df_anom = pd.read_csv(OUTPUT_ANOMALY_DATASET)
    print(f"[+] Loaded Anomaly Dataset: {len(df_anom)} observations")
    print(f"[+] Features used (NO risk_label): {df_anom.columns.tolist()}")

    X = df_anom.values

    # Train Isolation Forest (unsupervised)
    iso = IsolationForest(n_estimators=150, contamination=0.10, random_state=42)
    iso.fit(X)

    # In sklearn: -1 = anomaly, 1 = normal
    raw_preds = iso.predict(X)
    scores = iso.decision_function(X)

    df_anom['anomaly_score'] = scores
    df_anom['is_anomaly'] = (raw_preds == -1).astype(int)

    detected_count = (df_anom['is_anomaly'] == 1).sum()
    print(f"[+] Isolation Forest Outliers Detected: {detected_count} / {len(df_anom)} ({detected_count/len(df_anom)*100:.1f}%)")

    # Inspect top anomalies
    top_anomalies = df_anom.sort_values(by='anomaly_score').head(5)
    print("\n  Top 5 Detected Security Outliers (Most Abnormal States):")
    patch_col = "hours_since_last_patch" if "hours_since_last_patch" in df_anom.columns else "days_since_last_patch"
    print(top_anomalies[['failed_audits', 'high_severity_failures', patch_col, 'critical_vulns', 'compliance_score', 'anomaly_score']].to_string(index=False))


def evaluate_temporal_analysis():
    print("\n" + "=" * 70)
    print("TASK 3: TEMPORAL DRIFT & TRAJECTORY ANALYSIS")
    print("=" * 70)

    df_temp = pd.read_csv(OUTPUT_TEMPORAL_DATASET)
    df_temp['timestamp'] = pd.to_datetime(df_temp['timestamp'])
    df_temp = df_temp.sort_values(by=['system_id', 'timestamp']).reset_index(drop=True)

    print(f"[+] Loaded Temporal Dataset: {len(df_temp)} snapshots across {df_temp['system_id'].nunique()} persistent systems")

    # Calculate step-by-step delta metrics per persistent system
    df_temp['delta_compliance_score'] = df_temp.groupby('system_id')['compliance_score'].diff().fillna(0.0)
    df_temp['delta_failed_audits'] = df_temp.groupby('system_id')['failed_audits'].diff().fillna(0)
    df_temp['delta_critical_vulns'] = df_temp.groupby('system_id')['critical_vulns'].diff().fillna(0)
    df_temp['risk_transition'] = df_temp.groupby('system_id')['risk_label'].apply(
        lambda s: s.shift(1).astype(str) + " -> " + s.astype(str)
    ).fillna("initial")

    # Print summary per system
    for sys_id, grp in df_temp.groupby('system_id'):
        print(f"\n  System: {sys_id} ({len(grp)} observations)")
        print(f"    Initial Score: {grp.iloc[0]['compliance_score']} (Risk: {grp.iloc[0]['risk_label']})")
        print(f"    Final Score  : {grp.iloc[-1]['compliance_score']} (Risk: {grp.iloc[-1]['risk_label']})")
        print(f"    Net Score Change: {grp.iloc[-1]['compliance_score'] - grp.iloc[0]['compliance_score']:+.2f}")
        print(f"    Net Failures Change: {grp.iloc[-1]['failed_audits'] - grp.iloc[0]['failed_audits']:+d}")
        print(f"    Net Crit Vulns Change: {grp.iloc[-1]['critical_vulns'] - grp.iloc[0]['critical_vulns']:+d}")
        
        trajectory_scores = grp['compliance_score'].tolist()
        print(f"    Score Trajectory   : {' -> '.join(str(s) for s in trajectory_scores)}")
        
        transitions = grp['risk_label'].tolist()
        label_names = ["Normal" if r == 0 else "High Risk" for r in transitions]
        print(f"    Risk Trajectory    : {' -> '.join(label_names)}")

    # Save augmented temporal dataset with delta features
    augmented_path = OUTPUT_TEMPORAL_DATASET.parent / "temporal_compliance_with_deltas.csv"
    df_temp.to_csv(augmented_path, index=False)
    print(f"\n[+] Saved Augmented Temporal Dataset with Deltas: {augmented_path}")

if __name__ == "__main__":
    evaluate_supervised_learning()
    evaluate_anomaly_detection()
    evaluate_temporal_analysis()
