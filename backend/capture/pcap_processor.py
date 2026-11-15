"""
PCAP file processor.
Accepts a PCAP path, extracts flows via FlowExtractor, normalizes
features, runs ML prediction, and emits results to the detection queue.
"""

import asyncio
import logging
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Optional

from backend.core.config import settings
from backend.services.feature_normalizer import FeatureNormalizer
from backend.services.flow_extractor import FlowExtractor
from backend.services.ml_service import ml_service

logger = logging.getLogger(__name__)

# Validate PCAP magic bytes
_PCAP_MAGIC_LE = b"\xd4\xc3\xb2\xa1"
_PCAP_MAGIC_BE = b"\xa1\xb2\xc3\xd4"
_PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"

# In-memory task status tracker
_task_registry: Dict[str, "ProcessingTask"] = {}


@dataclass
class ProcessingTask:
    task_id: str
    status: str = "PENDING"
    progress: float = 0.0
    flows_extracted: int = 0
    attacks_detected: int = 0
    error: Optional[str] = None


def validate_pcap_magic(file_path: Path) -> bool:
    """Check that the file starts with a known PCAP magic number."""
    try:
        with open(file_path, "rb") as fh:
            header = fh.read(4)
        return header in (_PCAP_MAGIC_LE, _PCAP_MAGIC_BE, _PCAPNG_MAGIC)
    except OSError:
        return False


class PcapProcessor:
    """
    Processes PCAP files into ML predictions and detection events.
    Also persists flows and predictions to the database.
    """

    def __init__(
        self,
        detection_queue: asyncio.Queue,
        db_session_factory,
    ) -> None:
        self._detection_queue = detection_queue
        self._db_factory = db_session_factory
        self._normalizer = FeatureNormalizer()
        try:
            self._extractor = FlowExtractor()
        except RuntimeError as exc:
            logger.warning("FlowExtractor unavailable: %s", exc)
            self._extractor = None

    async def process_file(self, pcap_path: Path, task_id: Optional[str] = None) -> str:
        """
        Process a PCAP file asynchronously.
        Returns the task_id for status tracking.
        """
        if task_id is None:
            task_id = f"task-{uuid.uuid4().hex[:12]}"

        task = ProcessingTask(task_id=task_id)
        _task_registry[task_id] = task

        if self._extractor is None:
            task.status = "FAILED"
            task.error = "Flow extractor not available (dpkt not installed)"
            logger.error(task.error)
            return task_id

        # Validate file
        if not pcap_path.exists():
            task.status = "FAILED"
            task.error = f"File not found: {pcap_path}"
            return task_id

        if not validate_pcap_magic(pcap_path):
            task.status = "FAILED"
            task.error = "File does not appear to be a valid PCAP"
            return task_id

        task.status = "PROCESSING"
        logger.info("Processing PCAP: %s (task: %s)", pcap_path, task_id)

        try:
            # Run CPU-bound extraction in thread pool
            loop = asyncio.get_event_loop()
            flows = await loop.run_in_executor(
                None, self._extractor.extract_from_file, pcap_path
            )
            task.flows_extracted = len(flows)
            task.progress = 0.5

            logger.info("Extracted %d flows from %s", len(flows), pcap_path.name)

            attacks = 0
            for i, flow in enumerate(flows):
                task.progress = 0.5 + (i / max(len(flows), 1)) * 0.5

                # Normalize features
                arr = self._normalizer.normalize_list(
                    flow.features, record_id=flow.flow_id
                )
                if arr is None:
                    continue

                # ML prediction
                prediction = ml_service.predict(arr)

                # Persist flow + prediction
                await self._persist_flow_and_prediction(flow, prediction)

                # Send attacks to detection queue
                if prediction and prediction.label == "ATTACK":
                    attacks += 1
                    await self._detection_queue.put((flow, prediction))

            task.attacks_detected = attacks
            task.status = "COMPLETE"
            task.progress = 1.0
            logger.info(
                "PCAP task %s complete: %d flows, %d attacks",
                task_id, task.flows_extracted, attacks,
            )

        except Exception as exc:
            task.status = "FAILED"
            task.error = str(exc)
            logger.error("PCAP processing error: %s", exc, exc_info=True)

        return task_id

    async def _persist_flow_and_prediction(self, flow, prediction) -> None:
        import json
        from backend.database.models import NetworkFlow, MLPrediction

        try:
            async with self._db_factory() as session:
                nf = NetworkFlow(
                    flow_id=flow.flow_id,
                    source_ip=flow.src_ip,
                    destination_ip=flow.dest_ip,
                    source_port=flow.src_port,
                    destination_port=flow.dest_port,
                    protocol=flow.protocol,
                    duration_us=flow.duration_us,
                    features_json=json.dumps(flow.features),
                    pcap_source=flow.pcap_source,
                )
                session.add(nf)

                if prediction:
                    mp = MLPrediction(
                        prediction_id=f"pred-{uuid.uuid4().hex[:12]}",
                        flow_id=flow.flow_id,
                        label=prediction.label,
                        confidence=prediction.confidence,
                        probabilities=json.dumps(prediction.probabilities),
                        model_version=prediction.model_version,
                    )
                    session.add(mp)

                await session.commit()
        except Exception as exc:
            logger.error("Flow/prediction persist error: %s", exc)


def get_task_status(task_id: str) -> Optional[ProcessingTask]:
    return _task_registry.get(task_id)
