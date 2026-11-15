"""Reports and data export endpoints."""

import csv
import io
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends, Query
from fastapi.responses import StreamingResponse
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.database.database import get_db
from backend.database.models import SecurityEvent, MLPrediction, AgentInvestigation

router = APIRouter(prefix="/api/v1/reports", tags=["reports"])
logger = logging.getLogger(__name__)


@router.get("/summary")
async def report_summary(
    from_dt: Optional[datetime] = Query(default=None, alias="from"),
    to_dt: Optional[datetime] = Query(default=None, alias="to"),
    db: AsyncSession = Depends(get_db),
):
    if from_dt is None:
        from_dt = datetime.utcnow() - timedelta(days=7)
    if to_dt is None:
        to_dt = datetime.utcnow()

    # Severity breakdown
    sev_result = await db.execute(
        select(SecurityEvent.severity, func.count(SecurityEvent.id))
        .where(
            SecurityEvent.created_at >= from_dt,
            SecurityEvent.created_at <= to_dt,
        )
        .group_by(SecurityEvent.severity)
    )
    severity_dist = {row[0]: row[1] for row in sev_result.all()}

    # Attack categories
    cat_result = await db.execute(
        select(SecurityEvent.attack_category, func.count(SecurityEvent.id))
        .where(
            SecurityEvent.created_at >= from_dt,
            SecurityEvent.created_at <= to_dt,
            SecurityEvent.attack_category.isnot(None),
        )
        .group_by(SecurityEvent.attack_category)
        .order_by(func.count(SecurityEvent.id).desc())
        .limit(10)
    )
    attack_categories = [
        {"category": row[0], "count": row[1]} for row in cat_result.all()
    ]

    # Top source IPs
    top_result = await db.execute(
        select(SecurityEvent.source_ip, func.count(SecurityEvent.id).label("cnt"))
        .where(
            SecurityEvent.created_at >= from_dt,
            SecurityEvent.created_at <= to_dt,
        )
        .group_by(SecurityEvent.source_ip)
        .order_by(func.count(SecurityEvent.id).desc())
        .limit(10)
    )
    top_sources = [{"ip": row[0], "count": row[1]} for row in top_result.all()]

    # ML stats
    ml_result = await db.execute(
        select(MLPrediction.label, func.count(MLPrediction.id))
        .group_by(MLPrediction.label)
    )
    ml_stats = {row[0]: row[1] for row in ml_result.all()}

    # Investigation count
    inv_count = (await db.execute(select(func.count(AgentInvestigation.id)))).scalar() or 0

    return {
        "period": {
            "from": from_dt.isoformat(),
            "to": to_dt.isoformat(),
        },
        "severity_distribution": severity_dist,
        "attack_categories": attack_categories,
        "top_source_ips": top_sources,
        "ml_statistics": ml_stats,
        "total_investigations": inv_count,
        "generated_at": datetime.utcnow().isoformat(),
    }


@router.get("/export")
async def export_report(
    format: str = Query(default="csv", pattern="^(csv)$"),
    from_dt: Optional[datetime] = Query(default=None, alias="from"),
    to_dt: Optional[datetime] = Query(default=None, alias="to"),
    db: AsyncSession = Depends(get_db),
):
    """Export security events as CSV."""
    if from_dt is None:
        from_dt = datetime.utcnow() - timedelta(days=7)
    if to_dt is None:
        to_dt = datetime.utcnow()

    result = await db.execute(
        select(SecurityEvent)
        .where(
            SecurityEvent.created_at >= from_dt,
            SecurityEvent.created_at <= to_dt,
        )
        .order_by(SecurityEvent.created_at.desc())
        .limit(10_000)
    )
    rows = result.scalars().all()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "event_id", "timestamp", "source_ip", "destination_ip",
        "source_port", "destination_port", "protocol",
        "attack_category", "ml_prediction", "ml_confidence",
        "suricata_alert", "suricata_signature", "risk_score", "severity", "status",
    ])
    for r in rows:
        writer.writerow([
            r.event_id, r.created_at.isoformat(),
            r.source_ip, r.destination_ip,
            r.source_port, r.destination_port, r.protocol,
            r.attack_category, r.ml_prediction, r.ml_confidence,
            r.suricata_alert, r.suricata_signature, r.risk_score, r.severity, r.status,
        ])

    output.seek(0)
    filename = f"agentshield_report_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.csv"
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )
