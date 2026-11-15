"""Security events API endpoints."""

import json
import logging
import math
from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select, func, and_
from sqlalchemy.ext.asyncio import AsyncSession

from backend.database.database import get_db
from backend.database.models import AgentInvestigation, DefenceRecommendation, SecurityEvent
from backend.schemas.events import SecurityEventList, SecurityEventOut

router = APIRouter(prefix="/api/v1/events", tags=["events"])
logger = logging.getLogger(__name__)


@router.get("", response_model=SecurityEventList)
async def list_events(
    page: int = Query(default=1, ge=1),
    limit: int = Query(default=20, ge=1, le=100),
    severity: Optional[str] = None,
    from_dt: Optional[datetime] = Query(default=None, alias="from"),
    to_dt: Optional[datetime] = Query(default=None, alias="to"),
    source_ip: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
):
    filters = []
    if severity:
        filters.append(SecurityEvent.severity == severity.upper())
    if from_dt:
        filters.append(SecurityEvent.created_at >= from_dt)
    if to_dt:
        filters.append(SecurityEvent.created_at <= to_dt)
    if source_ip:
        filters.append(SecurityEvent.source_ip == source_ip)

    total_q = select(func.count(SecurityEvent.id))
    if filters:
        total_q = total_q.where(and_(*filters))
    total = (await db.execute(total_q)).scalar() or 0

    q = (
        select(SecurityEvent)
        .order_by(SecurityEvent.created_at.desc())
        .offset((page - 1) * limit)
        .limit(limit)
    )
    if filters:
        q = q.where(and_(*filters))

    rows = (await db.execute(q)).scalars().all()

    items = []
    for row in rows:
        ev = SecurityEventOut.model_validate(row)
        try:
            ev.evidence = json.loads(row.evidence) if row.evidence else []
        except Exception:
            ev.evidence = []
        items.append(ev)

    return SecurityEventList(
        items=items,
        total=total,
        page=page,
        limit=limit,
        pages=math.ceil(total / limit) if total else 0,
    )


@router.get("/{event_id}", response_model=SecurityEventOut)
async def get_event(event_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(SecurityEvent).where(SecurityEvent.event_id == event_id)
    )
    event = result.scalar_one_or_none()
    if event is None:
        raise HTTPException(status_code=404, detail=f"Event '{event_id}' not found")
    out = SecurityEventOut.model_validate(event)
    try:
        out.evidence = json.loads(event.evidence) if event.evidence else []
    except Exception:
        out.evidence = []
    return out


@router.get("/{event_id}/investigation")
async def get_event_investigation(event_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(AgentInvestigation).where(AgentInvestigation.event_id == event_id)
    )
    inv = result.scalar_one_or_none()
    if inv is None:
        raise HTTPException(status_code=404, detail=f"No investigation for event '{event_id}'")
    return {
        "investigation_id": inv.investigation_id,
        "event_id": inv.event_id,
        "attack_type": inv.attack_type,
        "entry_point": inv.entry_point,
        "target": inv.target,
        "affected_assets": json.loads(inv.affected_assets or "[]"),
        "observed_evidence": json.loads(inv.observed_evidence or "[]"),
        "hypotheses": json.loads(inv.hypotheses or "[]"),
        "potential_impact": inv.potential_impact,
        "confidence": inv.confidence,
        "explanation": inv.explanation,
        "llm_used": inv.llm_used,
        "created_at": inv.created_at.isoformat(),
    }


@router.get("/{event_id}/defence")
async def get_event_defence(event_id: str, db: AsyncSession = Depends(get_db)):
    # Find investigation for this event
    inv_result = await db.execute(
        select(AgentInvestigation).where(AgentInvestigation.event_id == event_id)
    )
    inv = inv_result.scalar_one_or_none()
    if inv is None:
        raise HTTPException(status_code=404, detail=f"No investigation for event '{event_id}'")

    def_result = await db.execute(
        select(DefenceRecommendation).where(
            DefenceRecommendation.investigation_id == inv.investigation_id
        )
    )
    rec = def_result.scalar_one_or_none()
    if rec is None:
        raise HTTPException(status_code=404, detail="No defence recommendation found")

    return {
        "defence_id": rec.defence_id,
        "investigation_id": rec.investigation_id,
        "risk_level": rec.risk_level,
        "recommended_actions": json.loads(rec.recommended_actions or "[]"),
        "priority": rec.priority,
        "requires_admin_approval": rec.requires_admin_approval,
        "execution_status": rec.execution_status,
        "admin_notes": rec.admin_notes,
        "created_at": rec.created_at.isoformat(),
    }
