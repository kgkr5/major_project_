"""Pydantic schemas for dashboard data."""

from datetime import datetime
from typing import Dict, List, Optional

from pydantic import BaseModel


class DashboardStats(BaseModel):
    total_flows: int = 0
    total_events: int = 0
    attacks_detected: int = 0
    critical_threats: int = 0
    high_risk_events: int = 0
    benign_traffic: int = 0
    active_sensors: int = 0
    model_status: str = "UNKNOWN"
    ollama_status: str = "UNKNOWN"
    agents_running: int = 0
    last_updated: datetime


class ThreatTimelinePoint(BaseModel):
    timestamp: str      # ISO or "HH:MM" bucket label
    attacks: int
    benign: int
    critical: int
    high: int


class SeverityDistribution(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    normal: int = 0


class TopSource(BaseModel):
    ip: str
    event_count: int
    latest_severity: Optional[str] = None
    attack_categories: List[str] = []
