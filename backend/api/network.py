"""Network flows and PCAP upload endpoints."""

import logging
import math
import shutil
import uuid
from pathlib import Path

from fastapi import APIRouter, BackgroundTasks, Depends, File, HTTPException, Request, UploadFile
from fastapi.responses import JSONResponse
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from backend.core.config import settings
from backend.database.database import get_db
from backend.database.models import NetworkFlow
from backend.schemas.flows import NetworkFlowOut, PCAPTaskStatus, PCAPUploadResponse
from backend.capture.pcap_processor import get_task_status

router = APIRouter(prefix="/api/v1/flows", tags=["network"])
logger = logging.getLogger(__name__)

UPLOAD_DIR = settings.upload_dir


@router.get("", response_model=dict)
async def list_flows(
    page: int = 1,
    limit: int = 20,
    db: AsyncSession = Depends(get_db),
):
    limit = min(limit, 100)
    total = (await db.execute(select(func.count(NetworkFlow.id)))).scalar() or 0
    rows = (
        await db.execute(
            select(NetworkFlow)
            .order_by(NetworkFlow.created_at.desc())
            .offset((page - 1) * limit)
            .limit(limit)
        )
    ).scalars().all()

    return {
        "items": [NetworkFlowOut.model_validate(r).model_dump() for r in rows],
        "total": total,
        "page": page,
        "limit": limit,
        "pages": math.ceil(total / limit) if total else 0,
    }


@router.get("/{flow_id}", response_model=NetworkFlowOut)
async def get_flow(flow_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(NetworkFlow).where(NetworkFlow.flow_id == flow_id)
    )
    flow = result.scalar_one_or_none()
    if flow is None:
        raise HTTPException(status_code=404, detail=f"Flow '{flow_id}' not found")
    return NetworkFlowOut.model_validate(flow)


@router.post("/upload-pcap", response_model=PCAPUploadResponse)
async def upload_pcap(
    background_tasks: BackgroundTasks,
    request: Request,
    file: UploadFile = File(...),
):
    """Upload a PCAP file for asynchronous analysis."""
    # Validate file type (check extension and content type)
    filename = file.filename or ""
    if not (filename.endswith(".pcap") or filename.endswith(".pcapng")):
        raise HTTPException(
            status_code=400,
            detail="Only .pcap and .pcapng files are accepted",
        )

    # Validate size
    content = await file.read()
    if len(content) > settings.max_pcap_upload_bytes:
        raise HTTPException(
            status_code=413,
            detail=f"File exceeds maximum size of {settings.max_pcap_upload_mb} MB",
        )

    # Validate magic bytes
    from backend.capture.pcap_processor import _PCAP_MAGIC_LE, _PCAP_MAGIC_BE, _PCAPNG_MAGIC
    if content[:4] not in (_PCAP_MAGIC_LE, _PCAP_MAGIC_BE, _PCAPNG_MAGIC):
        raise HTTPException(status_code=400, detail="Invalid PCAP file format")

    # Save to upload directory
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    task_id = f"task-{uuid.uuid4().hex[:12]}"
    dest_path = UPLOAD_DIR / f"{task_id}_{filename}"
    dest_path.write_bytes(content)

    # Get processor from app state
    processor = getattr(request.app.state, "pcap_processor", None)
    if processor is None:
        dest_path.unlink(missing_ok=True)
        raise HTTPException(status_code=503, detail="PCAP processor not available")

    # Enqueue background processing
    background_tasks.add_task(_run_processing, processor, dest_path, task_id)

    return PCAPUploadResponse(
        task_id=task_id,
        status="PENDING",
        message=f"File '{filename}' queued for analysis",
    )


@router.get("/upload/{task_id}/status", response_model=PCAPTaskStatus)
async def pcap_task_status(task_id: str):
    task = get_task_status(task_id)
    if task is None:
        raise HTTPException(status_code=404, detail=f"Task '{task_id}' not found")
    return PCAPTaskStatus(
        task_id=task.task_id,
        status=task.status,
        progress=task.progress,
        flows_extracted=task.flows_extracted,
        attacks_detected=task.attacks_detected,
        error=task.error,
    )


async def _run_processing(processor, pcap_path: Path, task_id: str) -> None:
    """Background task wrapper. Deletes temp file after processing."""
    try:
        await processor.process_file(pcap_path, task_id=task_id)
    finally:
        try:
            pcap_path.unlink(missing_ok=True)
        except Exception:
            pass
