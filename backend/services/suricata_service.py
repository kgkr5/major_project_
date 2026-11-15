"""
Suricata EVE JSON log monitor.

Tails /var/log/suricata/eve.json (configurable), parses alert and flow
events, deduplicates within a time window, and pushes results to an
asyncio queue consumed by the Detection Agent.
"""

import asyncio
import hashlib
import json
import logging
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from backend.core.config import settings

logger = logging.getLogger(__name__)

# ─── Event schemas ───────────────────────────────────────────────────────────

class SuricataAlert:
    """Parsed Suricata alert event."""
    __slots__ = (
        "event_id", "timestamp", "src_ip", "dest_ip", "src_port",
        "dest_port", "protocol", "signature", "signature_id",
        "severity", "category", "action", "raw",
    )

    def __init__(
        self,
        event_id: str,
        timestamp: datetime,
        src_ip: str,
        dest_ip: str,
        src_port: int,
        dest_port: int,
        protocol: str,
        signature: str,
        signature_id: int,
        severity: int,
        category: str,
        action: str,
        raw: dict,
    ) -> None:
        self.event_id = event_id
        self.timestamp = timestamp
        self.src_ip = src_ip
        self.dest_ip = dest_ip
        self.src_port = src_port
        self.dest_port = dest_port
        self.protocol = protocol
        self.signature = signature
        self.signature_id = signature_id
        self.severity = severity
        self.category = category
        self.action = action
        self.raw = raw

    def to_dict(self) -> dict:
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp.isoformat(),
            "src_ip": self.src_ip,
            "dest_ip": self.dest_ip,
            "src_port": self.src_port,
            "dest_port": self.dest_port,
            "protocol": self.protocol,
            "signature": self.signature,
            "signature_id": self.signature_id,
            "severity": self.severity,
            "category": self.category,
            "action": self.action,
        }


# ─── Deduplication cache ─────────────────────────────────────────────────────

class _DedupCache:
    """Track recently seen (src_ip, dest_ip, sig_id) keys with TTL."""

    def __init__(self, ttl_seconds: int) -> None:
        self._ttl = ttl_seconds
        self._seen: dict[str, float] = {}

    def is_duplicate(self, key: str) -> bool:
        now = time.monotonic()
        # Purge expired entries periodically
        if len(self._seen) > 10_000:
            self._seen = {k: v for k, v in self._seen.items() if now - v < self._ttl}
        last = self._seen.get(key)
        if last is not None and now - last < self._ttl:
            return True
        self._seen[key] = now
        return False


# ─── Main service ────────────────────────────────────────────────────────────

class SuricataService:
    """
    Monitors Suricata EVE JSON log and pushes parsed alerts to a queue.
    Handles log rotation by tracking file inode and position.
    """

    def __init__(self, queue: asyncio.Queue, eve_log: Optional[Path] = None) -> None:
        self._queue = queue
        self._eve_log = Path(eve_log or settings.suricata_eve_log)
        self._dedup = _DedupCache(settings.suricata_dedup_window_seconds)
        self._running = False
        self._file_pos = 0
        self._file_inode: Optional[int] = None
        self._alerts_parsed = 0
        self._last_event_time: Optional[datetime] = None
        self._status = "STOPPED"

    # ── Public API ────────────────────────────────────────────────

    @property
    def status(self) -> str:
        return self._status

    @property
    def alerts_parsed(self) -> int:
        return self._alerts_parsed

    @property
    def last_event_time(self) -> Optional[datetime]:
        return self._last_event_time

    async def start(self) -> None:
        self._running = True
        self._status = "RUNNING"
        logger.info("SuricataService started. Monitoring: %s", self._eve_log)
        await self._tail_loop()

    async def stop(self) -> None:
        self._running = False
        self._status = "STOPPED"
        logger.info("SuricataService stopped.")

    def health_check(self) -> dict:
        """Return health status without async I/O."""
        if not self._eve_log.exists():
            return {
                "status": "DOWN",
                "message": f"EVE log not found: {self._eve_log}",
            }
        try:
            stat = self._eve_log.stat()
            age_seconds = time.time() - stat.st_mtime
            if age_seconds > 300:  # file not updated in 5 min
                return {
                    "status": "DEGRADED",
                    "message": f"EVE log not updated for {int(age_seconds)}s",
                    "alerts_parsed": self._alerts_parsed,
                }
            return {
                "status": "OK",
                "message": "Suricata EVE log active",
                "alerts_parsed": self._alerts_parsed,
                "last_event": self._last_event_time.isoformat() if self._last_event_time else None,
            }
        except OSError as exc:
            return {"status": "DOWN", "message": str(exc)}

    # ── Internal ─────────────────────────────────────────────────

    async def _tail_loop(self) -> None:
        """Continuously tail the EVE JSON log."""
        while self._running:
            try:
                await self._read_new_lines()
            except Exception as exc:
                logger.error("SuricataService error: %s", exc, exc_info=True)
                self._status = "DEGRADED"
            await asyncio.sleep(1)  # poll interval

    async def _read_new_lines(self) -> None:
        if not self._eve_log.exists():
            return

        try:
            stat = self._eve_log.stat()
            current_inode = stat.st_ino
        except OSError:
            return

        # Detect log rotation (new inode or file shrunk)
        if self._file_inode != current_inode or stat.st_size < self._file_pos:
            logger.info("EVE log rotated. Resetting position.")
            self._file_pos = 0
            self._file_inode = current_inode

        if stat.st_size <= self._file_pos:
            return  # no new data

        try:
            with open(self._eve_log, "r", encoding="utf-8", errors="replace") as fh:
                fh.seek(self._file_pos)
                while True:
                    raw_line = fh.readline()
                    if not raw_line:
                        break
                    self._file_pos = fh.tell()
                    line = raw_line.strip()
                    if not line:
                        continue
                    try:
                        event = json.loads(line)
                    except json.JSONDecodeError:
                        logger.debug("Skipping malformed EVE line: %s", line[:80])
                        continue
                    await self._dispatch(event)
        except OSError as exc:
            logger.warning("Cannot read EVE log: %s", exc)

    async def _dispatch(self, event: dict) -> None:
        event_type = event.get("event_type", "")
        if event_type == "alert":
            parsed = self._parse_alert(event)
            if parsed is not None:
                self._alerts_parsed += 1
                self._last_event_time = parsed.timestamp
                self._status = "RUNNING"
                await self._queue.put(parsed)
        # flow events are processed separately if needed

    def _parse_alert(self, event: dict) -> Optional[SuricataAlert]:
        try:
            alert_data = event.get("alert", {})
            ts_str = event.get("timestamp", "")
            ts = _parse_timestamp(ts_str)

            src_ip = event.get("src_ip", "0.0.0.0")
            dest_ip = event.get("dest_ip", "0.0.0.0")
            src_port = int(event.get("src_port", 0))
            dest_port = int(event.get("dest_port", 0))
            protocol = event.get("proto", "UNKNOWN").upper()
            signature = alert_data.get("signature", "Unknown")
            signature_id = int(alert_data.get("signature_id", 0))
            severity = int(alert_data.get("severity", 2))
            category = alert_data.get("category", "Unknown")
            action = alert_data.get("action", "allowed")

            # Deduplication key
            dedup_key = f"{src_ip}:{dest_ip}:{signature_id}"
            if self._dedup.is_duplicate(dedup_key):
                return None

            # Stable event_id from content hash
            event_id = "sur-" + hashlib.sha1(
                f"{ts_str}{src_ip}{dest_ip}{signature_id}".encode()
            ).hexdigest()[:16]

            return SuricataAlert(
                event_id=event_id,
                timestamp=ts,
                src_ip=src_ip,
                dest_ip=dest_ip,
                src_port=src_port,
                dest_port=dest_port,
                protocol=protocol,
                signature=signature,
                signature_id=signature_id,
                severity=severity,
                category=category,
                action=action,
                raw=event,
            )
        except Exception as exc:
            logger.warning("Failed to parse Suricata alert: %s | event: %s", exc, str(event)[:200])
            return None


def _parse_timestamp(ts_str: str) -> datetime:
    """Parse Suricata's ISO-8601 timestamp with optional timezone offset."""
    if not ts_str:
        return datetime.now(tz=timezone.utc)
    # Remove microseconds beyond 6 digits
    ts_str = ts_str.strip()
    try:
        # Handle format: 2023-06-15T14:30:00.123456+0000
        return datetime.fromisoformat(ts_str.replace("+0000", "+00:00"))
    except ValueError:
        try:
            return datetime.strptime(ts_str[:19], "%Y-%m-%dT%H:%M:%S").replace(
                tzinfo=timezone.utc
            )
        except ValueError:
            return datetime.now(tz=timezone.utc)
