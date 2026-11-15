"""
SQLAlchemy ORM models for AgentShield.
All tables include created_at / updated_at timestamps.
"""

import json
from datetime import datetime

from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    Text,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.database.database import Base


def _now() -> datetime:
    return datetime.utcnow()


# ─────────────────────────────────────────────────────────────────────────────
# SecurityEvent
# ─────────────────────────────────────────────────────────────────────────────
class SecurityEvent(Base):
    __tablename__ = "security_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    event_id: Mapped[str] = mapped_column(Text, unique=True, nullable=False)
    source_ip: Mapped[str] = mapped_column(Text, nullable=False)
    destination_ip: Mapped[str] = mapped_column(Text, nullable=False)
    source_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    destination_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    protocol: Mapped[str | None] = mapped_column(Text, nullable=True)
    attack_category: Mapped[str | None] = mapped_column(Text, nullable=True)
    ml_prediction: Mapped[str | None] = mapped_column(Text, nullable=True)
    ml_confidence: Mapped[float | None] = mapped_column(Float, nullable=True)
    suricata_alert: Mapped[bool] = mapped_column(Boolean, default=False)
    suricata_signature: Mapped[str | None] = mapped_column(Text, nullable=True)
    risk_score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    severity: Mapped[str | None] = mapped_column(Text, nullable=True)
    evidence: Mapped[str | None] = mapped_column(Text, nullable=True)   # JSON array
    raw_suricata: Mapped[str | None] = mapped_column(Text, nullable=True)  # JSON
    raw_flow: Mapped[str | None] = mapped_column(Text, nullable=True)      # JSON
    status: Mapped[str] = mapped_column(Text, default="NEW")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=_now, onupdate=_now)

    # Relationships
    risk_assessments: Mapped[list["RiskAssessment"]] = relationship(
        back_populates="event", cascade="all, delete-orphan"
    )
    investigations: Mapped[list["AgentInvestigation"]] = relationship(
        back_populates="event", cascade="all, delete-orphan"
    )

    def get_evidence(self) -> list:
        if self.evidence:
            try:
                return json.loads(self.evidence)
            except json.JSONDecodeError:
                return []
        return []

    __table_args__ = (
        Index("idx_se_src_ip", "source_ip"),
        Index("idx_se_created", "created_at"),
        Index("idx_se_severity", "severity"),
        Index("idx_se_status", "status"),
    )


# ─────────────────────────────────────────────────────────────────────────────
# NetworkFlow
# ─────────────────────────────────────────────────────────────────────────────
class NetworkFlow(Base):
    __tablename__ = "network_flows"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    flow_id: Mapped[str] = mapped_column(Text, unique=True, nullable=False)
    source_ip: Mapped[str] = mapped_column(Text, nullable=False)
    destination_ip: Mapped[str] = mapped_column(Text, nullable=False)
    source_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    destination_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    protocol: Mapped[str | None] = mapped_column(Text, nullable=True)
    duration_us: Mapped[int | None] = mapped_column(Integer, nullable=True)
    features_json: Mapped[str | None] = mapped_column(Text, nullable=True)  # JSON array
    pcap_source: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)

    # Relationships
    predictions: Mapped[list["MLPrediction"]] = relationship(
        back_populates="flow", cascade="all, delete-orphan"
    )

    __table_args__ = (
        Index("idx_nf_src", "source_ip"),
        Index("idx_nf_created", "created_at"),
    )


# ─────────────────────────────────────────────────────────────────────────────
# MLPrediction
# ─────────────────────────────────────────────────────────────────────────────
class MLPrediction(Base):
    __tablename__ = "ml_predictions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    prediction_id: Mapped[str] = mapped_column(Text, unique=True, nullable=False)
    flow_id: Mapped[str | None] = mapped_column(Text, ForeignKey("network_flows.flow_id"), nullable=True)
    label: Mapped[str] = mapped_column(Text, nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    probabilities: Mapped[str | None] = mapped_column(Text, nullable=True)  # JSON
    model_version: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)

    flow: Mapped["NetworkFlow | None"] = relationship(back_populates="predictions")


# ─────────────────────────────────────────────────────────────────────────────
# AgentInvestigation
# ─────────────────────────────────────────────────────────────────────────────
class AgentInvestigation(Base):
    __tablename__ = "agent_investigations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    investigation_id: Mapped[str] = mapped_column(Text, unique=True, nullable=False)
    event_id: Mapped[str | None] = mapped_column(
        Text, ForeignKey("security_events.event_id"), nullable=True
    )
    attack_type: Mapped[str | None] = mapped_column(Text, nullable=True)
    entry_point: Mapped[str | None] = mapped_column(Text, nullable=True)
    target: Mapped[str | None] = mapped_column(Text, nullable=True)
    affected_assets: Mapped[str | None] = mapped_column(Text, nullable=True)   # JSON
    observed_evidence: Mapped[str | None] = mapped_column(Text, nullable=True) # JSON
    hypotheses: Mapped[str | None] = mapped_column(Text, nullable=True)        # JSON
    potential_impact: Mapped[str | None] = mapped_column(Text, nullable=True)
    confidence: Mapped[float | None] = mapped_column(Float, nullable=True)
    explanation: Mapped[str | None] = mapped_column(Text, nullable=True)
    llm_used: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)

    event: Mapped["SecurityEvent | None"] = relationship(back_populates="investigations")
    attack_paths: Mapped[list["AttackPath"]] = relationship(
        back_populates="investigation", cascade="all, delete-orphan"
    )
    defence_recommendations: Mapped[list["DefenceRecommendation"]] = relationship(
        back_populates="investigation", cascade="all, delete-orphan"
    )

    __table_args__ = (
        Index("idx_ai_event_id", "event_id"),
        Index("idx_ai_created", "created_at"),
    )


# ─────────────────────────────────────────────────────────────────────────────
# AttackPath
# ─────────────────────────────────────────────────────────────────────────────
class AttackPath(Base):
    __tablename__ = "attack_paths"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    path_id: Mapped[str] = mapped_column(Text, unique=True, nullable=False)
    investigation_id: Mapped[str | None] = mapped_column(
        Text, ForeignKey("agent_investigations.investigation_id"), nullable=True
    )
    nodes: Mapped[str | None] = mapped_column(Text, nullable=True)  # JSON array
    edges: Mapped[str | None] = mapped_column(Text, nullable=True)  # JSON array
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)

    investigation: Mapped["AgentInvestigation | None"] = relationship(
        back_populates="attack_paths"
    )


# ─────────────────────────────────────────────────────────────────────────────
# RiskAssessment
# ─────────────────────────────────────────────────────────────────────────────
class RiskAssessment(Base):
    __tablename__ = "risk_assessments"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    assessment_id: Mapped[str] = mapped_column(Text, unique=True, nullable=False)
    event_id: Mapped[str | None] = mapped_column(
        Text, ForeignKey("security_events.event_id"), nullable=True
    )
    score: Mapped[int] = mapped_column(Integer, nullable=False)
    severity: Mapped[str] = mapped_column(Text, nullable=False)
    contributing_factors: Mapped[str | None] = mapped_column(Text, nullable=True)  # JSON
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)

    event: Mapped["SecurityEvent | None"] = relationship(back_populates="risk_assessments")

    __table_args__ = (
        Index("idx_ra_event_id", "event_id"),
    )


# ─────────────────────────────────────────────────────────────────────────────
# DefenceRecommendation
# ─────────────────────────────────────────────────────────────────────────────
class DefenceRecommendation(Base):
    __tablename__ = "defence_recommendations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    defence_id: Mapped[str] = mapped_column(Text, unique=True, nullable=False)
    investigation_id: Mapped[str | None] = mapped_column(
        Text, ForeignKey("agent_investigations.investigation_id"), nullable=True
    )
    risk_level: Mapped[str | None] = mapped_column(Text, nullable=True)
    recommended_actions: Mapped[str | None] = mapped_column(Text, nullable=True)  # JSON
    priority: Mapped[str | None] = mapped_column(Text, nullable=True)
    requires_admin_approval: Mapped[bool] = mapped_column(Boolean, default=True)
    execution_status: Mapped[str] = mapped_column(Text, default="RECOMMENDED")
    admin_notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=_now, onupdate=_now)

    investigation: Mapped["AgentInvestigation | None"] = relationship(
        back_populates="defence_recommendations"
    )

    __table_args__ = (
        Index("idx_dr_status", "execution_status"),
        Index("idx_dr_created", "created_at"),
    )


# ─────────────────────────────────────────────────────────────────────────────
# SystemHealth
# ─────────────────────────────────────────────────────────────────────────────
class SystemHealth(Base):
    __tablename__ = "system_health"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    component: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(Text, nullable=False)  # OK / DEGRADED / DOWN
    details: Mapped[str | None] = mapped_column(Text, nullable=True)  # JSON
    checked_at: Mapped[datetime] = mapped_column(DateTime, default=_now)

    __table_args__ = (
        Index("idx_sh_comp", "component", "checked_at"),
    )


# ─────────────────────────────────────────────────────────────────────────────
# AuditLog
# ─────────────────────────────────────────────────────────────────────────────
class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    action: Mapped[str] = mapped_column(Text, nullable=False)
    actor: Mapped[str] = mapped_column(Text, default="system")
    details: Mapped[str | None] = mapped_column(Text, nullable=True)  # JSON
    ip_address: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)

    __table_args__ = (
        Index("idx_al_action", "action"),
        Index("idx_al_created", "created_at"),
    )
