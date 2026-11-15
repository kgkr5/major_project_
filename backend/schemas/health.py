"""Pydantic schemas for system health checks."""

from datetime import datetime
from typing import Any, Dict, Optional

from pydantic import BaseModel


class ComponentHealth(BaseModel):
    component: str
    status: str          # OK / DEGRADED / DOWN / UNKNOWN
    message: Optional[str] = None
    details: Optional[Dict[str, Any]] = None
    checked_at: datetime


class SystemHealth(BaseModel):
    overall: str         # OK / DEGRADED / DOWN
    components: Dict[str, ComponentHealth]
    checked_at: datetime
