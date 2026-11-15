"""Tests for the deterministic risk engine."""

import pytest

from backend.services.risk_engine import RiskEngine


class TestRiskEngine:
    @pytest.fixture
    def engine(self):
        return RiskEngine()

    def test_no_evidence_returns_zero(self, engine):
        result = engine.calculate(
            suricata_alert=False,
            suricata_severity=None,
            ml_prediction=None,
            ml_confidence=None,
            dest_port=None,
            related_event_count=0,
        )
        assert result.score == 0
        assert result.severity == "NORMAL"

    def test_suricata_severity_1_adds_50(self, engine):
        result = engine.calculate(
            suricata_alert=True,
            suricata_severity=1,
            ml_prediction=None,
            ml_confidence=None,
            dest_port=None,
        )
        assert result.score >= 50

    def test_ml_attack_high_confidence_adds_points(self, engine):
        result = engine.calculate(
            suricata_alert=False,
            suricata_severity=None,
            ml_prediction="ATTACK",
            ml_confidence=1.0,
            dest_port=None,
        )
        assert result.score == 30  # 1.0 * 30

    def test_sensitive_port_adds_5(self, engine):
        r_without = engine.calculate(False, None, "ATTACK", 0.5, None)
        r_with = engine.calculate(False, None, "ATTACK", 0.5, 22)
        assert r_with.score == r_without.score + 5

    def test_max_score_capped_at_100(self, engine):
        result = engine.calculate(
            suricata_alert=True,
            suricata_severity=1,
            ml_prediction="ATTACK",
            ml_confidence=1.0,
            dest_port=22,
            related_event_count=100,
        )
        assert result.score <= 100

    def test_severity_labels(self, engine):
        r = engine.calculate(True, 1, "ATTACK", 1.0, 22, related_event_count=10)
        assert r.severity in ("CRITICAL", "HIGH")

    def test_contributing_factors_not_empty(self, engine):
        r = engine.calculate(True, 2, "ATTACK", 0.8, 80)
        assert len(r.contributing_factors) > 0

    def test_benign_ml_adds_no_score(self, engine):
        r = engine.calculate(False, None, "BENIGN", 0.99, None)
        assert r.score == 0

    def test_related_events_capped_at_15(self, engine):
        r = engine.calculate(False, None, None, None, None, related_event_count=100)
        # 100 events × 2 = 200, but capped at 15
        assert r.score == 15
