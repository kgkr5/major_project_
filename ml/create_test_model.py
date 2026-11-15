"""
Create a minimal synthetic test model for CI/testing without CICIDS2017 data.
This model is for TESTING ONLY — it does not have meaningful detection accuracy.

Usage:
    python -m ml.create_test_model
"""

import json
import logging
import sys
from datetime import datetime
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

_project_root = Path(__file__).resolve().parent.parent
if str(_project_root) not in sys.path:
    sys.path.insert(0, str(_project_root))

from ml.feature_schema import FEATURE_COUNT, FEATURE_NAMES


def create_test_model(output_dir: str = "models") -> None:
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    model_file = output_path / "agentshield_rf_test.pkl"
    meta_file = output_path / "agentshield_rf_test_metadata.json"

    logger.info("Creating synthetic test model with %d features...", FEATURE_COUNT)

    # Generate minimal synthetic training data
    np.random.seed(42)
    n_samples = 200
    X = np.random.rand(n_samples, FEATURE_COUNT).astype(np.float64)
    y = np.array([0] * 100 + [1] * 100)  # 50/50 BENIGN/ATTACK

    clf = RandomForestClassifier(
        n_estimators=10,  # small for fast tests
        random_state=42,
        n_jobs=1,
    )
    clf.fit(X, y)

    joblib.dump(clf, model_file)
    logger.info("Test model saved to: %s", model_file)

    metadata = {
        "version": "test-1.0.0",
        "training_dataset": "SYNTHETIC_TEST_DATA",
        "feature_names": FEATURE_NAMES,
        "feature_count": FEATURE_COUNT,
        "training_samples": n_samples,
        "training_date": datetime.utcnow().isoformat(),
        "model_type": "RandomForestClassifier",
        "note": "SYNTHETIC TEST MODEL — NOT FOR PRODUCTION. Train on CICIDS2017 for real use.",
        "evaluation": {
            "accuracy": 0.5,
            "note": "Synthetic model — accuracy has no meaning"
        },
        "classes": [0, 1],
        "label_mapping": {"0": "BENIGN", "1": "ATTACK"},
    }
    with open(meta_file, "w") as f:
        json.dump(metadata, f, indent=2)
    logger.info("Test model metadata saved to: %s", meta_file)
    logger.info("Done. This model is for CI testing only.")


if __name__ == "__main__":
    create_test_model()
