"""Health check endpoints for all system components."""

import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Request
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from backend.database.database import get_db
from backend.schemas.health import ComponentHealth, SystemHealth
from backend.services.ml_service import ml_service
from backend.services.ollama_service import ollama_service

router = APIRouter(prefix="/api/v1/health", tags=["health"])
logger = logging.getLogger(__name__)


@router.get("", response_model=SystemHealth)
async def overall_health(request: Request, db: AsyncSession = Depends(get_db)):
    now = datetime.now(tz=timezone.utc)
    components = {}

    # Database
    try:
        await db.execute(text("SELECT 1"))
        components["database"] = ComponentHealth(
            component="database", status="OK",
            message="SQLite accessible", checked_at=now,
        )
    except Exception as exc:
        components["database"] = ComponentHealth(
            component="database", status="DOWN",
            message=str(exc), checked_at=now,
        )

    # ML Model
    ml_h = ml_service.health()
    components["ml_model"] = ComponentHealth(
        component="ml_model",
        status="OK" if ml_service.is_available else "DOWN",
        message=f"Model: {ml_h.get('status')}",
        details=ml_h,
        checked_at=now,
    )

    # Ollama
    ollama_h = await ollama_service.health_check()
    components["ollama"] = ComponentHealth(
        component="ollama",
        status=ollama_h.get("status", "UNKNOWN"),
        message=ollama_h.get("message"),
        details=ollama_h,
        checked_at=now,
    )

    # Suricata (access from app state if service is running)
    suricata_svc = getattr(request.app.state, "suricata_service", None)
    if suricata_svc:
        sur_h = suricata_svc.health_check()
        components["suricata"] = ComponentHealth(
            component="suricata",
            status=sur_h.get("status", "UNKNOWN"),
            message=sur_h.get("message"),
            details=sur_h,
            checked_at=now,
        )
    else:
        components["suricata"] = ComponentHealth(
            component="suricata", status="DOWN",
            message="Suricata service not started", checked_at=now,
        )

    # Packet capture
    sensor = getattr(request.app.state, "sensor_manager", None)
    if sensor:
        cap_h = sensor.get_health()
        components["capture"] = ComponentHealth(
            component="capture",
            status=cap_h.get("status", "DOWN"),
            message=cap_h.get("error") or f"Interface: {cap_h.get('interface')}",
            details=cap_h,
            checked_at=now,
        )
    else:
        components["capture"] = ComponentHealth(
            component="capture", status="DOWN",
            message="Sensor manager not started", checked_at=now,
        )

    # Determine overall status
    statuses = [c.status for c in components.values()]
    if all(s == "OK" for s in statuses):
        overall = "OK"
    elif any(s == "DOWN" for s in statuses):
        overall = "DEGRADED"
    else:
        overall = "DEGRADED"

    return SystemHealth(overall=overall, components=components, checked_at=now)


@router.get("/suricata", response_model=ComponentHealth)
async def suricata_health(request: Request):
    now = datetime.now(tz=timezone.utc)
    svc = getattr(request.app.state, "suricata_service", None)
    if svc:
        h = svc.health_check()
        return ComponentHealth(
            component="suricata",
            status=h.get("status", "UNKNOWN"),
            message=h.get("message"),
            details=h,
            checked_at=now,
        )
    return ComponentHealth(
        component="suricata", status="DOWN",
        message="Service not running", checked_at=now,
    )


@router.get("/model", response_model=ComponentHealth)
async def model_health():
    now = datetime.now(tz=timezone.utc)
    h = ml_service.health()
    return ComponentHealth(
        component="ml_model",
        status="OK" if ml_service.is_available else "DOWN",
        message=f"Model: {h.get('status')} | Version: {h.get('version')}",
        details=h,
        checked_at=now,
    )


@router.get("/ollama", response_model=ComponentHealth)
async def ollama_health():
    now = datetime.now(tz=timezone.utc)
    h = await ollama_service.health_check()
    return ComponentHealth(
        component="ollama",
        status=h.get("status", "UNKNOWN"),
        message=h.get("message"),
        details=h,
        checked_at=now,
    )


@router.get("/capture", response_model=ComponentHealth)
async def capture_health(request: Request):
    now = datetime.now(tz=timezone.utc)
    sensor = getattr(request.app.state, "sensor_manager", None)
    if sensor:
        h = sensor.get_health()
        return ComponentHealth(
            component="capture",
            status=h.get("status", "DOWN"),
            message=h.get("error") or f"Interface: {h.get('interface')}",
            details=h,
            checked_at=now,
        )
    return ComponentHealth(
        component="capture", status="DOWN",
        message="Sensor not running", checked_at=now,
    )


@router.get("/database", response_model=ComponentHealth)
async def database_health(db: AsyncSession = Depends(get_db)):
    now = datetime.now(tz=timezone.utc)
    try:
        await db.execute(text("SELECT 1"))
        return ComponentHealth(
            component="database", status="OK",
            message="SQLite accessible", checked_at=now,
        )
    except Exception as exc:
        return ComponentHealth(
            component="database", status="DOWN",
            message=str(exc), checked_at=now,
        )
