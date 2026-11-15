"""Tests for FeatureNormalizer."""

import math

import numpy as np
import pytest

from backend.services.feature_normalizer import FeatureNormalizer
from ml.feature_schema import FEATURE_COUNT, FEATURE_NAMES


class TestFeatureNormalizer:
    @pytest.fixture
    def normalizer(self):
        return FeatureNormalizer()

    def test_valid_dict_returns_array(self, normalizer, sample_feature_dict):
        result = normalizer.normalize_dict(sample_feature_dict)
        assert result is not None
        assert result.shape == (FEATURE_COUNT,)
        assert result.dtype == np.float64

    def test_valid_list_returns_array(self, normalizer, sample_77_features):
        result = normalizer.normalize_list(sample_77_features)
        assert result is not None
        assert result.shape == (FEATURE_COUNT,)

    def test_nan_replaced_with_zero(self, normalizer, sample_feature_dict):
        sample_feature_dict[FEATURE_NAMES[0]] = float("nan")
        result = normalizer.normalize_dict(sample_feature_dict)
        assert result is not None
        assert result[0] == 0.0

    def test_inf_capped(self, normalizer, sample_feature_dict):
        sample_feature_dict[FEATURE_NAMES[1]] = float("inf")
        result = normalizer.normalize_dict(sample_feature_dict)
        assert result is not None
        assert result[1] == 1e9

    def test_neg_inf_capped(self, normalizer, sample_feature_dict):
        sample_feature_dict[FEATURE_NAMES[1]] = float("-inf")
        result = normalizer.normalize_dict(sample_feature_dict)
        assert result is not None
        assert result[1] == -1e9

    def test_missing_feature_returns_none(self, normalizer, sample_feature_dict):
        del sample_feature_dict[FEATURE_NAMES[0]]
        result = normalizer.normalize_dict(sample_feature_dict)
        assert result is None

    def test_wrong_list_length_returns_none(self, normalizer):
        result = normalizer.normalize_list([0.0] * 50)
        assert result is None

    def test_validate_array_correct_shape(self, normalizer, sample_77_features):
        arr = np.zeros(FEATURE_COUNT, dtype=np.float64)
        assert normalizer.validate_array(arr) is True

    def test_validate_array_wrong_shape(self, normalizer):
        arr = np.zeros(50, dtype=np.float64)
        assert normalizer.validate_array(arr) is False

    def test_validate_array_nan_fails(self, normalizer):
        arr = np.zeros(FEATURE_COUNT, dtype=np.float64)
        arr[5] = float("nan")
        assert normalizer.validate_array(arr) is False

    def test_feature_ordering_preserved(self, normalizer):
        """Verify that feature ordering matches FEATURE_NAMES index."""
        feat_dict = {name: float(i) for i, name in enumerate(FEATURE_NAMES)}
        result = normalizer.normalize_dict(feat_dict)
        assert result is not None
        for i, name in enumerate(FEATURE_NAMES):
            assert result[i] == pytest.approx(float(i), abs=1e-6), (
                f"Feature '{name}' at index {i} has wrong value"
            )
