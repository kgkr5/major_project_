"""System settings endpoints."""

import logging

from fastapi import APIRouter, Request

from backend.core.config import settings

router = APIRouter(prefix="/api/v1/settings", tags=["settings"])
logger = logging.getLogger(__name__)


@router.get("")
async def get_settings():
    """Return non-sensitive configuration."""
    return {
        "capture_interface": settings.capture_interface,
        "pcap_rotation_seconds": settings.pcap_rotation_seconds,
        "suricata_eve_log": str(settings.suricata_eve_log),
        "ollama_model": settings.ollama_model,
        "ollama_host": settings.ollama_host,
        "max_pcap_upload_mb": settings.max_pcap_upload_mb,
        "risk_thresholds": {
            "critical": settings.risk_critical_threshold,
            "high": settings.risk_high_threshold,
            "medium": settings.risk_medium_threshold,
            "low": settings.risk_low_threshold,
        },
        "log_level": settings.log_level,
    }
