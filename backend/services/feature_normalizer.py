"""
Feature normalizer for AgentShield ML pipeline.

Accepts a dictionary {feature_name: value} or a list of 77 floats,
validates and cleans values, and returns a numpy array in the exact
order required by the trained Random Forest model.
"""

import logging
import math
from typing import Dict, List, Optional

import numpy as np

import sys
from pathlib import Path
_project_root = Path(__file__).resolve().parents[2]
if str(_project_root) not in sys.path:
    sys.path.insert(0, str(_project_root))

from ml.feature_schema import FEATURE_COUNT, FEATURE_INDEX, FEATURE_NAMES

logger = logging.getLogger(__name__)

# Values exceeding this are capped (Infinity replacement)
INF_CAP: float = 1e9


class FeatureNormalizer:
    """
    Maps feature names → ordered numpy array.
    Handles NaN, Infinity, and missing features.
    """

    def normalize_dict(
        self, feature_dict: Dict[str, float], record_id: str = ""
    ) -> Optional[np.ndarray]:
        """
        Convert {name: value} to an ordered (77,) float64 array.

        Returns None if any required feature is missing.
        Logs a warning for NaN/Inf replacements.
        """
        result = np.zeros(FEATURE_COUNT, dtype=np.float64)

        for name in FEATURE_NAMES:
            if name not in feature_dict:
                logger.warning(
                    "Missing feature '%s' in record %s. Skipping record.", name, record_id
                )
                return None
            val = feature_dict[name]
            result[FEATURE_INDEX[name]] = self._clean(val, name, record_id)

        return result

    def normalize_list(
        self, feature_list: List[float], record_id: str = ""
    ) -> Optional[np.ndarray]:
        """
        Convert an ordered list of 77 floats to a (77,) float64 array.

        Returns None if length is wrong.
        """
        if len(feature_list) != FEATURE_COUNT:
            logger.error(
                "Feature list length %d ≠ expected %d. Record: %s",
                len(feature_list), FEATURE_COUNT, record_id,
            )
            return None

        result = np.zeros(FEATURE_COUNT, dtype=np.float64)
        for i, val in enumerate(feature_list):
            result[i] = self._clean(val, FEATURE_NAMES[i], record_id)

        return result

    @staticmethod
    def _clean(val: float, name: str, record_id: str) -> float:
        if math.isnan(val):
            logger.debug("NaN replaced with 0.0 for feature '%s' record '%s'", name, record_id)
            return 0.0
        if math.isinf(val):
            replacement = INF_CAP if val > 0 else -INF_CAP
            logger.debug(
                "Inf replaced with %g for feature '%s' record '%s'",
                replacement, name, record_id,
            )
            return replacement
        return float(val)

    def validate_array(self, arr: np.ndarray) -> bool:
        """Final check: correct shape, no NaN/Inf remaining."""
        if arr.shape != (FEATURE_COUNT,):
            logger.error("Array shape %s ≠ (%d,)", arr.shape, FEATURE_COUNT)
            return False
        if np.any(np.isnan(arr)) or np.any(np.isinf(arr)):
            logger.error("Array still contains NaN or Inf after normalization.")
            return False
        return True
