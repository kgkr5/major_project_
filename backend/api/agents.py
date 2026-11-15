"""AI agent status and data endpoints."""

import json
import logging
from typing import List

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.database.database import get_db
from backend.database.models import AgentInvestigation, AttackPath, DefenceRecommendation, SecurityEvent
from backend.schemas.agents import AllAgentStatus, AgentStatusOut

router = APIRouter(prefix="/api/v1/agents", tags=["agents"])
logger = logging.getLogger(__name__)


@router.get("/status", response_model=AllAgentStatus)
async def agent_status(request: Request):
    det = getattr(request.app.state, "detection_agent", None)
    ana = getattr(request.app.state, "analysis_agent", None)
    def_ = getattr(request.app.state, "defence_agent", None)

    def _agent_out(agent, name: str) -> AgentStatusOut:
        if agent is None:
            return AgentStatusOut(name=name, status="NOT_STARTED")
        return AgentStatusOut(
            name=name,
            status=agent.status,
            events_processed=getattr(agent, "events_processed", None)
                or getattr(agent, "investigations_done", None)
                or getattr(agent, "recommendations_generated", 0),
            last_activity=getattr(agent, "last_activity", None),
            error_message=getattr(agent, "_error", None),
        )

    return AllAgentStatus(
        detection=_agent_out(det, "Detection Agent"),
        analysis=_agent_out(ana, "Attack Analysis Agent"),
        defence=_agent_out(def_, "Defence Agent"),
    )


@router.get("/detection/events")
async def detection_events(
    limit: int = 20,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(SecurityEvent)
        .order_by(SecurityEvent.created_at.desc())
        .limit(limit)
    )
    rows = result.scalars().all()
    return [
        {
            "event_id": r.event_id,
            "source_ip": r.source_ip,
            "destination_ip": r.destination_ip,
            "attack_category": r.attack_category,
            "severity": r.severity,
            "risk_score": r.risk_score,
            "ml_prediction": r.ml_prediction,
            "ml_confidence": r.ml_confidence,
            "suricata_alert": r.suricata_alert,
            "created_at": r.created_at.isoformat(),
        }
        for r in rows
    ]


@router.get("/analysis/investigations")
async def analysis_investigations(
    limit: int = 20,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(AgentInvestigation)
        .order_by(AgentInvestigation.created_at.desc())
        .limit(limit)
    )
    rows = result.scalars().all()

    investigation_ids = [r.investigation_id for r in rows]
    paths_by_investigation = {}

    if investigation_ids:
        paths_result = await db.execute(
            select(AttackPath)
            .where(AttackPath.investigation_id.in_(investigation_ids))
            .order_by(AttackPath.created_at.desc())
        )
        for path in paths_result.scalars().all():
            paths_by_investigation.setdefault(path.investigation_id, path)

    def parse_json_list(value):
        try:
            parsed = json.loads(value or "[]")
            return parsed if isinstance(parsed, list) else []
        except (json.JSONDecodeError, TypeError):
            return []

    return [
        {
            "investigation_id": r.investigation_id,
            "event_id": r.event_id,
            "attack_type": r.attack_type,
            "entry_point": r.entry_point,
            "target": r.target,
            "affected_assets": parse_json_list(r.affected_assets),
            "observed_evidence": parse_json_list(r.observed_evidence),
            "hypotheses": parse_json_list(r.hypotheses),
            "potential_impact": r.potential_impact,
            "confidence": r.confidence,
            "explanation": r.explanation,
            "llm_used": r.llm_used,
            "nodes": parse_json_list(
                paths_by_investigation[r.investigation_id].nodes
            ) if r.investigation_id in paths_by_investigation else [],
            "edges": parse_json_list(
                paths_by_investigation[r.investigation_id].edges
            ) if r.investigation_id in paths_by_investigation else [],
            "created_at": r.created_at.isoformat(),
        }
        for r in rows
    ]


@router.get("/defence/recommendations")
async def defence_recommendations(
    limit: int = 20,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(DefenceRecommendation)
        .order_by(DefenceRecommendation.created_at.desc())
        .limit(limit)
    )
    rows = result.scalars().all()
    return [
        {
            "defence_id": r.defence_id,
            "investigation_id": r.investigation_id,
            "risk_level": r.risk_level,
            "priority": r.priority,
            "requires_admin_approval": r.requires_admin_approval,
            "execution_status": r.execution_status,
            "recommended_actions": json.loads(r.recommended_actions or "[]"),
            "created_at": r.created_at.isoformat(),
        }
        for r in rows
    ]


@router.post("/defence/recommendations/{defence_id}/approve")
async def approve_recommendation(
    defence_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Admin action: mark recommendation as approved. Requires human review."""
    result = await db.execute(
        select(DefenceRecommendation).where(DefenceRecommendation.defence_id == defence_id)
    )
    rec = result.scalar_one_or_none()
    if rec is None:
        raise HTTPException(status_code=404, detail="Recommendation not found")

    rec.execution_status = "APPROVED"
    await db.commit()

    # Audit log
    await _audit(db, "DEFENCE_APPROVED", defence_id, request)
    logger.info("Admin approved defence recommendation: %s", defence_id)

    return {"status": "APPROVED", "defence_id": defence_id,
            "message": "Approved. Manual execution required by administrator."}


@router.post("/defence/recommendations/{defence_id}/reject")
async def reject_recommendation(
    defence_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Admin action: reject a recommendation."""
    result = await db.execute(
        select(DefenceRecommendation).where(DefenceRecommendation.defence_id == defence_id)
    )
    rec = result.scalar_one_or_none()
    if rec is None:
        raise HTTPException(status_code=404, detail="Recommendation not found")

    rec.execution_status = "REJECTED"
    await db.commit()

    await _audit(db, "DEFENCE_REJECTED", defence_id, request)
    logger.info("Admin rejected defence recommendation: %s", defence_id)

    return {"status": "REJECTED", "defence_id": defence_id}


async def _audit(db, action: str, target_id: str, request: Request) -> None:
    from backend.database.models import AuditLog
    try:
        client_ip = request.client.host if request.client else "unknown"
        log = AuditLog(
            action=action,
            actor="admin",
            details=json.dumps({"target_id": target_id}),
            ip_address=client_ip,
        )
        db.add(log)
        await db.commit()
    except Exception as exc:
        logger.warning("Audit log failed: %s", exc)
