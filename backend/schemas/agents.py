"""Pydantic schemas for agent inputs/outputs."""

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


# ─── Detection Agent ────────────────────────────────────────────────────────

class DetectionEvent(BaseModel):
    """Output schema for Detection Agent (matches spec Section 4 FR-05)."""
    event_id: str
    source_ip: str
    destination_ip: str
    protocol: Optional[str] = None
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    attack_category: Optional[str] = None
    ml_prediction: Optional[str] = None
    ml_confidence: Optional[float] = Field(None, ge=0.0, le=1.0)
    suricata_alert: bool = False
    suricata_signature: Optional[str] = None
    risk_score: int = Field(0, ge=0, le=100)
    severity: str = "NORMAL"
    evidence: List[str] = []
    timestamp: datetime


class RiskAssessmentResult(BaseModel):
    score: int = Field(..., ge=0, le=100)
    severity: str
    contributing_factors: List[str]


# ─── Attack Analysis Agent ──────────────────────────────────────────────────

class AttackPathNode(BaseModel):
    id: str
    ip: str
    node_type: str   # attacker / victim / intermediate / unknown
    risk_level: Optional[str] = None
    label: Optional[str] = None


class AttackPathEdge(BaseModel):
    source: str
    target: str
    label: Optional[str] = None
    observed: bool = True  # True = confirmed connection, False = inferred


class InvestigationResult(BaseModel):
    """Output schema for Attack Analysis Agent."""
    investigation_id: str
    event_id: str
    attack_type: Optional[str] = None
    entry_point: Optional[str] = None
    target: Optional[str] = None
    attack_path: List[Dict[str, Any]] = []
    nodes: List[AttackPathNode] = []
    edges: List[AttackPathEdge] = []
    affected_assets: List[str] = []
    observed_evidence: List[str] = []
    hypotheses: List[str] = []
    potential_impact: Optional[str] = None
    confidence: Optional[float] = Field(None, ge=0.0, le=1.0)
    explanation: Optional[str] = None
    llm_used: bool = False
    created_at: datetime


# ─── Defence Agent ──────────────────────────────────────────────────────────

class RecommendedAction(BaseModel):
    action_id: str
    action_type: str         # BLOCK_IP / RESTRICT_SERVICE / REVIEW_ACCOUNT / etc.
    description: str
    target: Optional[str] = None   # IP, service name, etc.
    priority: int = Field(1, ge=1, le=5)  # 1 = highest
    rationale: str


class DefenceRecommendationOut(BaseModel):
    """Output schema for Defence Agent."""
    defence_id: str
    investigation_id: str
    risk_level: str
    recommended_actions: List[RecommendedAction]
    priority: str      # URGENT / HIGH / MEDIUM / LOW
    requires_admin_approval: bool = True
    execution_status: str = "RECOMMENDED"
    created_at: datetime


# ─── Agent Status ────────────────────────────────────────────────────────────

class AgentStatusOut(BaseModel):
    name: str
    status: str        # RUNNING / IDLE / ERROR / STARTING
    events_processed: int = 0
    last_activity: Optional[datetime] = None
    current_task: Optional[str] = None
    error_message: Optional[str] = None


class AllAgentStatus(BaseModel):
    detection: AgentStatusOut
    analysis: AgentStatusOut
    defence: AgentStatusOut
