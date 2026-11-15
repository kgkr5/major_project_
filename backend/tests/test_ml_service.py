"""Tests for the ML service."""

import numpy as np
import pytest

from backend.services.ml_service import MLService
from ml.feature_schema import FEATURE_COUNT


class TestMLService:
    @pytest.fixture
    def service(self):
        svc = MLService()
        # Try to load test model; if unavailable, tests will verify graceful failure
        svc.load()
        return svc

    def test_predict_valid_features(self, service):
        if not service.is_available:
            pytest.skip("Test model not available — run ml/create_test_model.py first")
        features = np.zeros(FEATURE_COUNT, dtype=np.float64)
        result = service.predict(features)
        assert result is not None
        assert result.label in ("BENIGN", "ATTACK")
        assert 0.0 <= result.confidence <= 1.0
        assert "BENIGN" in result.probabilities
        assert "ATTACK" in result.probabilities

    def test_predict_wrong_shape_returns_none(self, service):
        if not service.is_available:
            pytest.skip("Model not available")
        features = np.zeros(50, dtype=np.float64)
        result = service.predict(features)
        assert result is None

    def test_predict_with_nan_returns_none(self, service):
        if not service.is_available:
            pytest.skip("Model not available")
        features = np.zeros(FEATURE_COUNT, dtype=np.float64)
        features[0] = float("nan")
        result = service.predict(features)
        assert result is None

    def test_predict_with_inf_returns_none(self, service):
        if not service.is_available:
            pytest.skip("Model not available")
        features = np.zeros(FEATURE_COUNT, dtype=np.float64)
        features[0] = float("inf")
        result = service.predict(features)
        assert result is None

    def test_health_when_unavailable(self):
        svc = MLService()
        # Don't load any model
        health = svc.health()
        assert health["status"] == "UNLOADED"

    def test_probabilities_sum_to_one(self, service):
        if not service.is_available:
            pytest.skip("Model not available")
        features = np.random.rand(FEATURE_COUNT).astype(np.float64)
        result = service.predict(features)
        assert result is not None
        total = sum(result.probabilities.values())
        assert abs(total - 1.0) < 1e-6
