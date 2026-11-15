"""Pydantic schemas for security events."""

from datetime import datetime
from typing import Any, List, Optional

import json

from pydantic import BaseModel, Field, field_validator


class SecurityEventCreate(BaseModel):
    event_id: str
    source_ip: str
    destination_ip: str
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    protocol: Optional[str] = None
    attack_category: Optional[str] = None
    ml_prediction: Optional[str] = None
    ml_confidence: Optional[float] = Field(None, ge=0.0, le=1.0)
    suricata_alert: bool = False
    suricata_signature: Optional[str] = None
    risk_score: Optional[int] = Field(None, ge=0, le=100)
    severity: Optional[str] = None
    evidence: Optional[List[str]] = None
    raw_suricata: Optional[dict] = None
    raw_flow: Optional[dict] = None


class SecurityEventOut(BaseModel):
    id: int
    event_id: str
    source_ip: str
    destination_ip: str
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    protocol: Optional[str] = None
    attack_category: Optional[str] = None
    ml_prediction: Optional[str] = None
    ml_confidence: Optional[float] = None
    suricata_alert: bool
    suricata_signature: Optional[str] = None
    risk_score: Optional[int] = None
    severity: Optional[str] = None
    evidence: Optional[List[Any]] = None
    status: str
    created_at: datetime
    updated_at: datetime

    @field_validator("evidence", mode="before")
    @classmethod
    def parse_evidence(cls, value):
        if value is None or value == "":
            return []
        if isinstance(value, str):
            try:
                value = json.loads(value)
            except (json.JSONDecodeError, TypeError):
                return []
        return value if isinstance(value, list) else []

    model_config = {"from_attributes": True}


class SecurityEventList(BaseModel):
    items: List[SecurityEventOut]
    total: int
    page: int
    limit: int
    pages: int
