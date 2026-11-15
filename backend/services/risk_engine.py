"""
Deterministic risk scoring engine for AgentShield.

The final numerical risk score is NEVER determined by an LLM.
All score components are calculated from observable evidence.
"""

import logging
from dataclasses import dataclass, field
from typing import List, Optional

from backend.core.config import settings

logger = logging.getLogger(__name__)

# Sensitive ports that increase risk when targeted
SENSITIVE_PORTS = {
    22, 23, 21, 25, 53, 80, 443, 445, 3389, 8080, 8443,
    1433, 3306, 5432, 6379, 27017, 2181, 9200, 5601,
}


@dataclass
class RiskAssessment:
    """Result of a risk engine calculation."""
    score: int                          # 0–100
    severity: str                       # CRITICAL / HIGH / MEDIUM / LOW / NORMAL
    contributing_factors: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "score": self.score,
            "severity": self.severity,
            "contributing_factors": self.contributing_factors,
        }


class RiskEngine:
    """
    Deterministic risk calculator.

    Scoring formula (max 100):
      suricata_severity_weight    (0–50)
      ml_confidence contribution  (0–30)
      related_events contribution (0–15)
      sensitive_port bonus        (0–5)
    """

    def calculate(
        self,
        suricata_alert: bool,
        suricata_severity: Optional[int],
        ml_prediction: Optional[str],
        ml_confidence: Optional[float],
        dest_port: Optional[int],
        related_event_count: int = 0,
    ) -> RiskAssessment:
        """
        Calculate a risk score from available evidence.

        Parameters
        ----------
        suricata_alert       : True if a Suricata alert was triggered
        suricata_severity    : Suricata severity 1 (high) / 2 (medium) / 3 (low)
                               Note: Suricata numbers severity inversely (1=most severe)
        ml_prediction        : "ATTACK" or "BENIGN" or None
        ml_confidence        : ML confidence score (0.0–1.0)
        dest_port            : Destination port number (may increase risk)
        related_event_count  : Number of related security events in recent history
        """
        score = 0.0
        factors: List[str] = []

        # ── Suricata alert contribution ───────────────────────────
        if suricata_alert and suricata_severity is not None:
            # Severity weight: Suricata 1=high, 2=med, 3=low
            weights = settings.suricata_severity_weights  # {1:50, 2:35, 3:20}
            weight = weights.get(suricata_severity, 20)
            score += weight
            level_name = {1: "HIGH", 2: "MEDIUM", 3: "LOW"}.get(suricata_severity, "UNKNOWN")
            factors.append(
                f"Suricata alert triggered (severity {suricata_severity}/{level_name}, +{weight} pts)"
            )

        # ── ML prediction contribution ────────────────────────────
        if ml_prediction == "ATTACK" and ml_confidence is not None:
            ml_contribution = round(ml_confidence * 30, 1)
            score += ml_contribution
            factors.append(
                f"ML classifier: ATTACK (confidence {ml_confidence:.0%}, +{ml_contribution} pts)"
            )
        elif ml_prediction == "BENIGN":
            factors.append("ML classifier: BENIGN (no score contribution)")

        # ── Related events contribution ───────────────────────────
        if related_event_count > 0:
            related_contribution = min(related_event_count * 2, 15)
            score += related_contribution
            factors.append(
                f"{related_event_count} related security event(s) from same source (+{related_contribution} pts)"
            )

        # ── Sensitive port bonus ──────────────────────────────────
        if dest_port is not None and dest_port in SENSITIVE_PORTS:
            score += 5
            factors.append(f"Sensitive port targeted (port {dest_port}, +5 pts)")

        # ── Clamp and classify ────────────────────────────────────
        final_score = min(int(round(score)), 100)
        severity = settings.severity_label(final_score)

        if not factors:
            factors.append("No significant threat indicators detected")

        logger.debug(
            "Risk score: %d (%s) | factors: %s", final_score, severity, factors
        )

        return RiskAssessment(
            score=final_score,
            severity=severity,
            contributing_factors=factors,
        )


# Global singleton
risk_engine = RiskEngine()
