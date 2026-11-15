"""
ML service for AgentShield.

Loads the pre-trained Random Forest classifier and exposes prediction
and health-check functionality. Falls back to UNAVAILABLE status if
the model file is not found.
"""

import json
import logging
import threading
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional

import numpy as np

from backend.core.config import settings
from backend.schemas.flows import PredictionResult

logger = logging.getLogger(__name__)


class MLService:
    """
    Wraps the scikit-learn Random Forest model.
    Thread-safe for use in async FastAPI context (model inference is CPU-bound).
    """

    def __init__(self) -> None:
        self._model: Any = None
        self._metadata: Dict[str, Any] = {}
        self._status: str = "UNLOADED"
        self._lock = threading.Lock()
        self._model_path: Optional[Path] = None

    def load(self, model_path: Optional[Path] = None) -> bool:
        """
        Load the model from disk. Returns True on success.
        Tries the production model first; falls back to the test model.
        """
        import joblib

        paths_to_try = []
        if model_path:
            paths_to_try.append(Path(model_path))
        paths_to_try.append(settings.model_path)
        paths_to_try.append(settings.test_model_path)

        for path in paths_to_try:
            if not path.exists():
                continue
            try:
                with self._lock:
                    self._model = joblib.load(path)
                    self._model_path = path
                    self._status = "LOADED"
                self._load_metadata()
                logger.info("ML model loaded from %s", path)
                return True
            except Exception as exc:
                logger.warning("Failed to load model from %s: %s", path, exc)

        self._status = "UNAVAILABLE"
        logger.warning(
            "No valid model file found. ML predictions will be unavailable. "
            "Checked: %s", [str(p) for p in paths_to_try]
        )
        return False

    def _load_metadata(self) -> None:
        meta_path = settings.model_metadata_path
        if meta_path.exists():
            try:
                with open(meta_path, "r") as f:
                    self._metadata = json.load(f)
                logger.debug("Model metadata loaded: version=%s", self._metadata.get("version"))
            except Exception as exc:
                logger.warning("Could not load model metadata: %s", exc)
        else:
            # Infer minimal metadata from model object
            if self._model is not None:
                self._metadata = {
                    "version": "unknown",
                    "n_features": getattr(self._model, "n_features_in_", None),
                    "classes": list(getattr(self._model, "classes_", [])),
                    "loaded_at": datetime.utcnow().isoformat(),
                }

    def predict(self, features: np.ndarray) -> Optional[PredictionResult]:
        """
        Run inference on a (77,) float64 array.
        Returns None if model is unavailable or features are invalid.
        """
        if self._status != "LOADED" or self._model is None:
            logger.debug("Prediction skipped: model status=%s", self._status)
            return None

        if features.shape != (77,):
            logger.warning("Invalid feature shape: %s (expected (77,))", features.shape)
            return None

        if np.any(np.isnan(features)) or np.any(np.isinf(features)):
            logger.warning("Feature array contains NaN or Inf — prediction rejected.")
            return None

        try:
            with self._lock:
                X = features.reshape(1, -1)
                pred_idx = self._model.predict(X)[0]
                probas = self._model.predict_proba(X)[0]

            classes = getattr(self._model, "classes_", [0, 1])
            label_map = {0: "BENIGN", 1: "ATTACK"}

            if isinstance(pred_idx, str):
                label = pred_idx.upper()
            else:
                label = label_map.get(int(pred_idx), str(pred_idx))

            proba_dict: Dict[str, float] = {}
            for cls, prob in zip(classes, probas):
                cls_label = label_map.get(int(cls), str(cls)) if not isinstance(cls, str) else cls.upper()
                proba_dict[cls_label] = float(prob)

            confidence = proba_dict.get(label, float(max(probas)))

            return PredictionResult(
                label=label,
                confidence=confidence,
                probabilities=proba_dict,
                model_version=self._metadata.get("version"),
            )
        except Exception as exc:
            logger.error("Prediction error: %s", exc, exc_info=True)
            return None

    def health(self) -> Dict[str, Any]:
        return {
            "status": self._status,
            "model_path": str(self._model_path) if self._model_path else None,
            "version": self._metadata.get("version", "unknown"),
            "n_features": self._metadata.get("n_features"),
            "training_dataset": self._metadata.get("training_dataset"),
            "accuracy": self._metadata.get("accuracy"),
            "training_date": self._metadata.get("training_date"),
        }

    @property
    def is_available(self) -> bool:
        return self._status == "LOADED" and self._model is not None


# Global singleton
ml_service = MLService()
