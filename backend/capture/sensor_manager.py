"""
Sensor manager: manages the live packet capture process lifecycle.

On Linux/WSL2, uses scapy to write rotating PCAP files.
Reports sensor health and interface status.
"""

import asyncio
import logging
import os
import platform
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from backend.core.config import settings

logger = logging.getLogger(__name__)


class SensorStatus:
    def __init__(self) -> None:
        self.active: bool = False
        self.interface: str = settings.capture_interface
        self.packets_captured: int = 0
        self.last_update: Optional[datetime] = None
        self.current_pcap: Optional[Path] = None
        self.error: Optional[str] = None
        self.platform_note: Optional[str] = None


class SensorManager:
    """
    Manages live packet capture using Scapy.

    LIMITATION: In WSL2, this captures traffic on WSL2 virtual interfaces.
    Windows host traffic is NOT fully visible from WSL2 without bridging.
    The dashboard clearly reports which interfaces are being monitored.
    """

    def __init__(self, pcap_processor) -> None:
        self._processor = pcap_processor
        self._status = SensorStatus()
        self._running = False
        self._capture_task: Optional[asyncio.Task] = None
        self._rotation_task: Optional[asyncio.Task] = None

        # Platform note
        if platform.system() == "Windows":
            self._status.platform_note = (
                "Running on Windows. Capture requires Npcap. "
                "Start the backend in WSL2 for full Linux capture support."
            )
        elif "microsoft" in platform.uname().release.lower():
            self._status.platform_note = (
                "Running in WSL2. Monitoring WSL2 virtual interfaces. "
                "Windows host traffic visibility is limited without network bridging."
            )

    @property
    def status(self) -> SensorStatus:
        return self._status

    async def start(self) -> None:
        if self._running:
            logger.warning("SensorManager already running.")
            return

        # Ensure output directory exists
        settings.pcap_output_dir.mkdir(parents=True, exist_ok=True)

        self._running = True
        self._status.active = True
        logger.info(
            "SensorManager starting. Interface: %s | Output: %s",
            settings.capture_interface, settings.pcap_output_dir,
        )

        self._capture_task = asyncio.create_task(self._capture_loop())

    async def stop(self) -> None:
        self._running = False
        self._status.active = False
        if self._capture_task:
            self._capture_task.cancel()
        logger.info("SensorManager stopped.")

    async def _capture_loop(self) -> None:
        """Periodically trigger PCAP rotation and processing."""
        while self._running:
            try:
                pcap_path = await self._write_pcap_segment()
                if pcap_path and pcap_path.exists() and pcap_path.stat().st_size > 0:
                    self._status.current_pcap = pcap_path
                    self._status.last_update = datetime.now(tz=timezone.utc)
                    # Process in background without blocking capture rotation
                    asyncio.create_task(
                        self._processor.process_file(pcap_path)
                    )
            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.error("Capture loop error: %s", exc, exc_info=True)
                self._status.error = str(exc)

            await asyncio.sleep(settings.pcap_rotation_seconds)

    async def _write_pcap_segment(self) -> Optional[Path]:
        """
        Write a PCAP segment using scapy's sniff() in a thread pool executor.
        Returns the path to the written file.
        """
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = settings.pcap_output_dir / f"live_{ts}.pcap"

        try:
            from scapy.all import sniff, wrpcap  # type: ignore
            loop = asyncio.get_event_loop()

            def _sniff_and_write() -> int:
                packets = sniff(
                    iface=settings.capture_interface,
                    timeout=settings.pcap_rotation_seconds,
                    store=True,
                )
                if packets:
                    wrpcap(str(output_path), packets)
                    return len(packets)
                return 0

            count = await loop.run_in_executor(None, _sniff_and_write)
            self._status.packets_captured += count
            logger.debug("Captured %d packets → %s", count, output_path)
            return output_path

        except ImportError:
            logger.warning(
                "Scapy not available. Live capture disabled. "
                "Use PCAP upload for analysis."
            )
            self._status.active = False
            self._status.error = "Scapy not installed"
            return None
        except PermissionError:
            logger.warning(
                "Permission denied for packet capture on interface %s. "
                "Run with sudo/root in WSL2.",
                settings.capture_interface,
            )
            self._status.active = False
            self._status.error = f"Permission denied on interface {settings.capture_interface}"
            return None
        except Exception as exc:
            logger.error("Capture error: %s", exc)
            self._status.error = str(exc)
            return None

    def get_health(self) -> dict:
        return {
            "status": "OK" if self._status.active else "DOWN",
            "interface": self._status.interface,
            "packets_captured": self._status.packets_captured,
            "last_update": self._status.last_update.isoformat() if self._status.last_update else None,
            "current_pcap": str(self._status.current_pcap) if self._status.current_pcap else None,
            "error": self._status.error,
            "platform_note": self._status.platform_note,
        }
