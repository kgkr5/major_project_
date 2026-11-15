"""Pydantic schemas for network flows and ML predictions."""

from datetime import datetime
from typing import Dict, List, Optional

from pydantic import BaseModel, Field


class FlowRecord(BaseModel):
    """A processed network flow with 77 extracted features."""
    flow_id: str
    src_ip: str
    dest_ip: str
    src_port: int
    dest_port: int
    protocol: str
    timestamp: datetime
    features: List[float] = Field(..., min_length=77, max_length=77)
    feature_names: List[str]
    duration_us: int
    pcap_source: Optional[str] = None


class NetworkFlowOut(BaseModel):
    id: int
    flow_id: str
    source_ip: str
    destination_ip: str
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    protocol: Optional[str] = None
    duration_us: Optional[int] = None
    pcap_source: Optional[str] = None
    created_at: datetime

    model_config = {"from_attributes": True}


class PredictionResult(BaseModel):
    label: str               # BENIGN or ATTACK
    confidence: float        # probability of the predicted class
    probabilities: Dict[str, float]  # {"BENIGN": 0.06, "ATTACK": 0.94}
    model_version: Optional[str] = None


class PCAPUploadResponse(BaseModel):
    task_id: str
    status: str
    message: str


class PCAPTaskStatus(BaseModel):
    task_id: str
    status: str       # PENDING / PROCESSING / COMPLETE / FAILED
    progress: float   # 0.0 – 1.0
    flows_extracted: Optional[int] = None
    attacks_detected: Optional[int] = None
    error: Optional[str] = None
