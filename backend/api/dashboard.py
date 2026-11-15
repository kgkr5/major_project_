


import logging
from datetime import datetime, timedelta, timezone
from typing import List

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.database.database import get_db
from backend.database.models import MLPrediction, NetworkFlow, SecurityEvent
from backend.schemas.dashboard import (
    DashboardStats,
    SeverityDistribution,
    ThreatTimelinePoint,
    TopSource,
)
from backend.services.ml_service import ml_service
from backend.services.ollama_service import ollama_service

router = APIRouter(prefix="/api/v1/dashboard", tags=["dashboard"])
logger = logging.getLogger(__name__)


@router.get("/stats", response_model=DashboardStats)
async def get_stats(request: Request, db: AsyncSession = Depends(get_db)):
    now = datetime.now(tz=timezone.utc)

    # Total flows
    total_flows = (
        await db.execute(select(func.count(NetworkFlow.id)))
    ).scalar() or 0

    # Total events
    total_events = (
        await db.execute(select(func.count(SecurityEvent.id)))
    ).scalar() or 0

    # Attacks
    attacks = (
        await db.execute(
            select(func.count(SecurityEvent.id)).where(
                SecurityEvent.severity.in_(
                    ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
                )
            )
        )
    ).scalar() or 0

    # Critical threats
    critical = (
        await db.execute(
            select(func.count(SecurityEvent.id)).where(
                SecurityEvent.severity == "CRITICAL"
            )
        )
    ).scalar() or 0

    # High-risk events
    high = (
        await db.execute(
            select(func.count(SecurityEvent.id)).where(
                SecurityEvent.severity == "HIGH"
            )
        )
    ).scalar() or 0

    # Benign traffic
    benign = (
        await db.execute(
            select(func.count(MLPrediction.id)).where(
                MLPrediction.label == "BENIGN"
            )
        )
    ).scalar() or 0

    # Active network sensors
    sensor_manager = getattr(
        request.app.state, "sensor_manager", None
    )
    sensor_status = getattr(sensor_manager, "status", None)

    active_sensors = (
        1 if sensor_status and sensor_status.active else 0
    )

    # Count agents using their actual status properties
    agent_names = (
        "detection_agent",
        "analysis_agent",
        "defence_agent",
    )

    active_agent_states = {
        "RUNNING",
        "PROCESSING",
        "INVESTIGATING",
        "GENERATING",
    }

    agents_running = sum(
        1
        for name in agent_names
        if str(
            getattr(
                getattr(request.app.state, name, None),
                "status",
                "UNKNOWN",
            )
        ).upper() in active_agent_states
    )

    return DashboardStats(
        total_flows=total_flows,
        total_events=total_events,
        attacks_detected=attacks,
        critical_threats=critical,
        high_risk_events=high,
        benign_traffic=benign,
        active_sensors=active_sensors,
        model_status="OK" if ml_service.is_available else "UNAVAILABLE",
        ollama_status="OK" if ollama_service.is_available else "UNKNOWN",
        agents_running=agents_running,
        last_updated=now,
    )


@router.get(
    "/threat-timeline",
    response_model=List[ThreatTimelinePoint],
)
async def threat_timeline(
    hours: int = Query(default=24, ge=1, le=168),
    db: AsyncSession = Depends(get_db),
):
    """Return hourly threat counts for the last N hours."""

    now = datetime.utcnow()
    cutoff = now - timedelta(hours=hours)

    result = await db.execute(
        select(
            SecurityEvent.created_at,
            SecurityEvent.severity,
            SecurityEvent.ml_prediction,
        )
        .where(SecurityEvent.created_at >= cutoff)
        .order_by(SecurityEvent.created_at)
    )

    rows = result.all()

    # Bucket events by hour
    buckets: dict = {}

    for row in rows:
        hour_key = row.created_at.strftime("%Y-%m-%dT%H:00")

        if hour_key not in buckets:
            buckets[hour_key] = {
                "attacks": 0,
                "benign": 0,
                "critical": 0,
                "high": 0,
            }

        if row.severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            buckets[hour_key]["attacks"] += 1
        else:
            buckets[hour_key]["benign"] += 1

        if row.severity == "CRITICAL":
            buckets[hour_key]["critical"] += 1

        if row.severity == "HIGH":
            buckets[hour_key]["high"] += 1

    return [
        ThreatTimelinePoint(
            timestamp=key,
            attacks=value["attacks"],
            benign=value["benign"],
            critical=value["critical"],
            high=value["high"],
        )
        for key, value in sorted(buckets.items())
    ]


@router.get(
    "/severity-distribution",
    response_model=SeverityDistribution,
)
async def severity_distribution(
    db: AsyncSession = Depends(get_db),
):
    counts: dict = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "NORMAL": 0,
    }

    result = await db.execute(
        select(
            SecurityEvent.severity,
            func.count(SecurityEvent.id),
        ).group_by(SecurityEvent.severity)
    )

    for severity, count in result.all():
        if severity in counts:
            counts[severity] = count

    return SeverityDistribution(
        **{key.lower(): value for key, value in counts.items()}
    )


@router.get(
    "/top-sources",
    response_model=List[TopSource],
)
async def top_sources(
    limit: int = Query(default=10, ge=1, le=50),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(
            SecurityEvent.source_ip,
            func.count(SecurityEvent.id).label("cnt"),
            func.max(SecurityEvent.severity).label("latest_sev"),
        )
        .group_by(SecurityEvent.source_ip)
        .order_by(func.count(SecurityEvent.id).desc())
        .limit(limit)
    )

    rows = result.all()

    if not rows:
        return []

    source_ips = [row.source_ip for row in rows]

    category_result = await db.execute(
        select(
            SecurityEvent.source_ip,
            SecurityEvent.attack_category,
        )
        .where(SecurityEvent.source_ip.in_(source_ips))
        .group_by(
            SecurityEvent.source_ip,
            SecurityEvent.attack_category,
        )
    )

    categories_by_ip = {}

    for ip, category in category_result.all():
        if category:
            categories_by_ip.setdefault(ip, []).append(category)

    return [
        TopSource(
            ip=row.source_ip,
            event_count=row.cnt,
            latest_severity=row.latest_sev,
            attack_categories=sorted(
                categories_by_ip.get(row.source_ip, [])
            ),
        )
        for row in rows
    ]
