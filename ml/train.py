"""
AgentShield Random Forest training script.

Usage (from project root in WSL2 with venv activated):
    python -m ml.train --data-dir /path/to/cicids2017 --output-dir models/

Requirements:
    - CICIDS2017 CSV files in --data-dir
    - scikit-learn, pandas, numpy, joblib installed
"""

import argparse
import json
import logging
import sys
from datetime import datetime
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split

logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)s | %(message)s")
logger = logging.getLogger(__name__)

_project_root = Path(__file__).resolve().parent.parent
if str(_project_root) not in sys.path:
    sys.path.insert(0, str(_project_root))

from ml.data_loader import load_cicids2017
from ml.feature_schema import FEATURE_COUNT, FEATURE_NAMES


def train(data_dir: str, output_dir: str, max_rows: int | None = None) -> None:
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    model_file = output_path / "agentshield_rf.pkl"
    meta_file = output_path / "agentshield_rf_metadata.json"

    # ── Load and clean data ───────────────────────────────────────
    logger.info("Loading CICIDS2017 dataset from: %s", data_dir)
    X, y = load_cicids2017(data_dir, max_rows_per_file=max_rows)

    # Verify feature count
    if len(X.columns) != FEATURE_COUNT:
        logger.warning(
            "Feature count mismatch: dataset has %d, expected %d. "
            "Proceeding with available features.",
            len(X.columns), FEATURE_COUNT,
        )

    # ── Time-aware train/test split ───────────────────────────────
    # Use the first 70% of rows as train, last 30% as test.
    # This avoids data leakage from random row shuffling of time-ordered captures.
    split_idx = int(len(X) * 0.70)
    X_train = X.iloc[:split_idx]
    X_test = X.iloc[split_idx:]
    y_train = y.iloc[:split_idx]
    y_test = y.iloc[split_idx:]

    logger.info(
        "Train: %d rows | Test: %d rows | Train attack rate: %.1f%%",
        len(X_train), len(X_test),
        100 * (y_train == 1).mean(),
    )

    # ── Train ─────────────────────────────────────────────────────
    logger.info("Training RandomForestClassifier (n_estimators=100)...")
    clf = RandomForestClassifier(
        n_estimators=100,
        n_jobs=-1,
        random_state=42,
        class_weight="balanced",
        max_depth=None,
    )
    clf.fit(X_train, y_train)
    logger.info("Training complete.")

    # ── Evaluate ──────────────────────────────────────────────────
    y_pred = clf.predict(X_test)
    y_prob = clf.predict_proba(X_test)[:, 1]

    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, zero_division=0)
    rec = recall_score(y_test, y_pred, zero_division=0)
    f1 = f1_score(y_test, y_pred, zero_division=0)
    try:
        auc = roc_auc_score(y_test, y_prob)
    except Exception:
        auc = None
    cm = confusion_matrix(y_test, y_pred)
    tn, fp, fn, tp = cm.ravel() if cm.shape == (2, 2) else (0, 0, 0, 0)
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    fnr = fn / (fn + tp) if (fn + tp) > 0 else 0.0

    logger.info("─" * 50)
    logger.info("EVALUATION RESULTS (actual, not fabricated):")
    logger.info("  Accuracy:       %.4f", acc)
    logger.info("  Precision:      %.4f", prec)
    logger.info("  Recall:         %.4f", rec)
    logger.info("  F1-Score:       %.4f", f1)
    if auc:
        logger.info("  ROC-AUC:        %.4f", auc)
    logger.info("  False Pos Rate: %.4f", fpr)
    logger.info("  False Neg Rate: %.4f", fnr)
    logger.info("  Confusion Matrix:\n%s", cm)
    logger.info("─" * 50)
    print(classification_report(y_test, y_pred, target_names=["BENIGN", "ATTACK"]))

    # ── Save model ────────────────────────────────────────────────
    joblib.dump(clf, model_file)
    logger.info("Model saved to: %s", model_file)

    # ── Save metadata ─────────────────────────────────────────────
    metadata = {
        "version": "1.0.0",
        "training_dataset": "CICIDS2017",
        "feature_names": list(X.columns),
        "feature_count": len(X.columns),
        "training_samples": len(X_train),
        "test_samples": len(X_test),
        "training_date": datetime.utcnow().isoformat(),
        "model_type": "RandomForestClassifier",
        "hyperparameters": {
            "n_estimators": 100,
            "random_state": 42,
            "class_weight": "balanced",
        },
        "evaluation": {
            "accuracy": float(acc),
            "precision": float(prec),
            "recall": float(rec),
            "f1_score": float(f1),
            "roc_auc": float(auc) if auc else None,
            "false_positive_rate": float(fpr),
            "false_negative_rate": float(fnr),
            "confusion_matrix": cm.tolist(),
        },
        "classes": [int(c) for c in clf.classes_],
        "label_mapping": {"0": "BENIGN", "1": "ATTACK"},
    }

    with open(meta_file, "w") as f:
        json.dump(metadata, f, indent=2)
    logger.info("Metadata saved to: %s", meta_file)
    logger.info("Training complete. Model is ready.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train AgentShield Random Forest model")
    parser.add_argument("--data-dir", required=True, help="Path to CICIDS2017 CSV directory")
    parser.add_argument("--output-dir", default="models", help="Output directory for model files")
    parser.add_argument(
        "--max-rows", type=int, default=None,
        help="Max rows per CSV file (for testing with subset)"
    )
    args = parser.parse_args()
    train(args.data_dir, args.output_dir, args.max_rows)
