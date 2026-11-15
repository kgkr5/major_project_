"""
AGENT 3: Defence Agent

Generates prioritized defensive recommendations from investigation results.
IMPORTANT: Operates in recommendation-only mode. Does NOT execute any
network commands or firewall changes. All actions require admin approval.
"""

import asyncio
import json
import logging
import uuid
from datetime import datetime, timezone
from typing import List, Optional

from backend.core.websocket_manager import manager as ws_manager
from backend.schemas.agents import (
    DefenceRecommendationOut,
    InvestigationResult,
    RecommendedAction,
)

logger = logging.getLogger(__name__)

# Recommendation templates keyed by attack category
_TEMPLATES = {
    "Port Scanning": [
        ("BLOCK_IP", "Block source IP {src_ip} at perimeter firewall", 1),
        ("ENABLE_RATE_LIMITING", "Enable port-scan rate limiting on border router", 2),
        ("REVIEW_EXPOSED_SERVICES", "Audit externally exposed services on {target}", 3),
    ],
    "Brute Force": [
        ("BLOCK_IP", "Block source IP {src_ip} at perimeter firewall", 1),
        ("REVIEW_ACCOUNT", "Review account lockout policy for service on port {dest_port}", 2),
        ("ENABLE_MFA", "Enable multi-factor authentication on targeted service", 2),
        ("REVIEW_AUTH_LOGS", "Review authentication logs on {target}", 3),
    ],
    "Denial of Service": [
        ("RATE_LIMIT", "Rate-limit traffic from {src_ip} at network boundary", 1),
        ("ENABLE_SCRUBBING", "Enable traffic scrubbing / DDoS protection", 1),
        ("REVIEW_BANDWIDTH", "Review bandwidth limits and capacity thresholds", 2),
        ("CONTACT_ISP", "Consider upstream ISP-level filtering if volumetric attack continues", 3),
    ],
    "Botnet Communication": [
        ("ISOLATE_HOST", "Isolate host {src_ip} from network pending forensic review", 1),
        ("BLOCK_C2", "Block suspected C2 IP {dest_ip} at firewall", 1),
        ("SCAN_MALWARE", "Run malware scan on host {src_ip}", 1),
        ("REVIEW_DNS", "Review DNS queries from affected host", 2),
    ],
    "Suspicious DNS": [
        ("REVIEW_DNS_LOGS", "Review DNS query logs for host {src_ip}", 1),
        ("BLOCK_DOMAIN", "Block suspicious domains identified in traffic to {dest_ip}", 2),
        ("ENABLE_DNSSEC", "Enable DNSSEC validation on DNS resolvers", 3),
    ],
    "Reconnaissance": [
        ("BLOCK_IP", "Block source IP {src_ip} at perimeter firewall", 1),
        ("REVIEW_EXPOSED", "Review externally visible services that were probed", 2),
        ("CONSIDER_HONEYPOT", "Consider deploying honeypot on commonly scanned ports", 4),
    ],
    "Suspicious TCP": [
        ("REVIEW_CONNECTIONS", "Review half-open and RST connections from {src_ip}", 2),
        ("ENABLE_TCP_LIMITS", "Enable SYN cookie protection on affected systems", 2),
        ("BLOCK_IP", "Block source IP {src_ip} if behavior continues", 3),
    ],
    "default": [
        ("REVIEW_TRAFFIC", "Review traffic from {src_ip} in network logs", 2),
        ("CHECK_TARGET", "Verify integrity of target system {target}", 2),
        ("UPDATE_RULES", "Update IDS/IPS signatures to improve detection coverage", 3),
    ],
}

_PRIORITY_MAP = {
    "CRITICAL": "URGENT",
    "HIGH": "HIGH",
    "MEDIUM": "MEDIUM",
    "LOW": "LOW",
    "NORMAL": "INFORMATIONAL",
}


class DefenceAgent:
    """
    Generates defensive recommendations. Recommendation-only mode.
    No commands are executed without explicit administrator approval.
    """

    def __init__(
        self,
        defence_queue: asyncio.Queue,
        db_session_factory,
    ) -> None:
        self._in_queue = defence_queue
        self._db_factory = db_session_factory
        self._running = False
        self._recommendations_generated = 0
        self._last_activity: Optional[datetime] = None
        self._status = "IDLE"
        self._error: Optional[str] = None

    @property
    def status(self) -> str:
        return self._status

    @property
    def recommendations_generated(self) -> int:
        return self._recommendations_generated

    @property
    def last_activity(self) -> Optional[datetime]:
        return self._last_activity

    async def start(self) -> None:
        self._running = True
        self._status = "RUNNING"
        logger.info("DefenceAgent started.")
        await self._run_loop()

    async def stop(self) -> None:
        self._running = False
        self._status = "STOPPED"

    async def _run_loop(self) -> None:
        while self._running:
            try:
                investigation: InvestigationResult = await asyncio.wait_for(
                    self._in_queue.get(), timeout=1.0
                )
                await self._recommend(investigation)
                self._in_queue.task_done()
            except asyncio.TimeoutError:
                continue
            except Exception as exc:
                logger.error("DefenceAgent error: %s", exc, exc_info=True)
                self._error = str(exc)
                self._status = "DEGRADED"

    async def _recommend(self, inv: InvestigationResult) -> None:
        self._last_activity = datetime.now(tz=timezone.utc)
        self._status = "GENERATING"

        attack_type = inv.attack_type or "default"
        templates = _TEMPLATES.get(attack_type, _TEMPLATES["default"])

        actions: List[RecommendedAction] = []
        for action_type, desc_template, priority in templates:
            desc = desc_template.format(
                src_ip=inv.entry_point or "unknown",
                dest_ip=inv.target or "unknown",
                target=inv.target or "unknown",
                dest_port=inv.attack_path[0].get("port", "N/A") if inv.attack_path else "N/A",
            )
            actions.append(RecommendedAction(
                action_id=f"act-{uuid.uuid4().hex[:8]}",
                action_type=action_type,
                description=desc,
                target=inv.entry_point,
                priority=priority,
                rationale=(
                    f"Based on {attack_type} activity detected from {inv.entry_point}. "
                    f"Risk level: {inv.potential_impact or 'UNKNOWN'}. "
                    f"Confidence: {inv.confidence:.0%}" if inv.confidence else "N/A"
                ),
            ))

        # Sort by priority (1 = highest)
        actions.sort(key=lambda a: a.priority)

        priority_label = _PRIORITY_MAP.get(inv.potential_impact or "MEDIUM", "MEDIUM")

        recommendation = DefenceRecommendationOut(
            defence_id=f"def-{uuid.uuid4().hex[:12]}",
            investigation_id=inv.investigation_id,
            risk_level=inv.potential_impact or "MEDIUM",
            recommended_actions=actions,
            priority=priority_label,
            requires_admin_approval=True,        # ALWAYS True — never auto-execute
            execution_status="RECOMMENDED",       # NEVER "EXECUTED" without admin
            created_at=datetime.now(tz=timezone.utc),
        )

        await self._persist(recommendation)
        self._recommendations_generated += 1
        self._status = "IDLE"

        # Broadcast
        await ws_manager.broadcast({
            "type": "defence_recommendation",
            "payload": recommendation.model_dump(),
        })

        logger.info(
            "DefenceAgent: %d recommendation(s) for investigation %s | priority=%s",
            len(actions), inv.investigation_id, priority_label,
        )

    async def _persist(self, rec: DefenceRecommendationOut) -> None:
        from backend.database.models import DefenceRecommendation

        try:
            async with self._db_factory() as session:
                dr = DefenceRecommendation(
                    defence_id=rec.defence_id,
                    investigation_id=rec.investigation_id,
                    risk_level=rec.risk_level,
                    recommended_actions=json.dumps(
                        [a.model_dump() for a in rec.recommended_actions]
                    ),
                    priority=rec.priority,
                    requires_admin_approval=True,     # enforced in DB layer too
                    execution_status="RECOMMENDED",
                )
                session.add(dr)
                await session.commit()
        except Exception as exc:
            logger.error("DefenceAgent DB persist error: %s", exc, exc_info=True)
