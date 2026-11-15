"""
AGENT 2: Attack Analysis Agent

Investigates detected threats, constructs attack-path graphs,
and generates evidence-based explanations using Ollama (with
deterministic fallback when Ollama is unavailable).
"""

import asyncio
import json
import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import List, Optional

from backend.core.config import settings
from backend.core.websocket_manager import manager as ws_manager
from backend.schemas.agents import (
    AttackPathEdge,
    AttackPathNode,
    DetectionEvent,
    InvestigationResult,
)
from backend.services.ollama_service import ollama_service

logger = logging.getLogger(__name__)

# Prompt template for Ollama
_INVESTIGATION_PROMPT = """You are a cybersecurity analyst reviewing network security events.
Based ONLY on the following observed network evidence, provide a brief structured analysis.

RULES:
- Do NOT invent CVEs, exploit names, or specific vulnerabilities
- Do NOT claim a host is compromised solely because an alert was generated
- Clearly distinguish OBSERVED FACTS from HYPOTHESES
- Keep each section to 2-3 sentences maximum

Observed Evidence:
- Source IP: {src_ip}
- Target IP: {dest_ip}
- Detected attack category: {category}
- Suricata alerts triggered: {signatures}
- ML classification: {ml_label} (confidence: {ml_conf})
- Destination port: {dest_port}
- Related events in last 24h from source: {related_count}
- Protocol: {protocol}

Provide the following sections:
1. OBSERVED: What network behavior was detected (facts only)
2. POSSIBLE_PROGRESSION: Possible attack progression IF evidence supports it (label as hypothesis)
3. AFFECTED_ASSETS: Which systems are potentially affected based on observed IPs/ports
4. INVESTIGATION_STEPS: 3 recommended investigation steps

Format each section with its label followed by a colon."""


class AttackAnalysisAgent:
    """
    Investigates DetectionEvents and produces InvestigationResults
    with attack path graphs.
    """

    def __init__(
        self,
        analysis_queue: asyncio.Queue,
        defence_queue: asyncio.Queue,
        db_session_factory,
    ) -> None:
        self._in_queue = analysis_queue
        self._out_queue = defence_queue
        self._db_factory = db_session_factory
        self._running = False
        self._investigations_done = 0
        self._last_activity: Optional[datetime] = None
        self._status = "IDLE"
        self._error: Optional[str] = None

    @property
    def status(self) -> str:
        return self._status

    @property
    def investigations_done(self) -> int:
        return self._investigations_done

    @property
    def last_activity(self) -> Optional[datetime]:
        return self._last_activity

    async def start(self) -> None:
        self._running = True
        self._status = "RUNNING"
        logger.info("AttackAnalysisAgent started.")
        await self._run_loop()

    async def stop(self) -> None:
        self._running = False
        self._status = "STOPPED"

    async def _run_loop(self) -> None:
        while self._running:
            try:
                event: DetectionEvent = await asyncio.wait_for(
                    self._in_queue.get(), timeout=1.0
                )
                await self._investigate(event)
                self._in_queue.task_done()
            except asyncio.TimeoutError:
                continue
            except Exception as exc:
                logger.error("AttackAnalysisAgent error: %s", exc, exc_info=True)
                self._error = str(exc)
                self._status = "DEGRADED"

    async def _investigate(self, event: DetectionEvent) -> None:
        self._last_activity = datetime.now(tz=timezone.utc)
        self._status = "INVESTIGATING"

        # Query related events for context
        related_events = await self._get_related_events(event.source_ip, event.destination_ip)
        related_count = len(related_events)

        # Build attack path graph
        nodes, edges = self._build_attack_path(event, related_events)

        # Determine affected assets
        affected_assets = list({event.source_ip, event.destination_ip})
        for rel in related_events:
            if rel.get("destination_ip") and rel["destination_ip"] not in affected_assets:
                affected_assets.append(rel["destination_ip"])

        # Build observed evidence list
        observed = list(event.evidence)
        if related_count > 0:
            observed.append(f"{related_count} related event(s) found from same source in last 24h")

        # Generate explanation
        llm_used = False
        explanation = None

        if settings.debug is False or True:  # always attempt
            prompt = _INVESTIGATION_PROMPT.format(
                src_ip=event.source_ip,
                dest_ip=event.destination_ip,
                category=event.attack_category or "Unknown",
                signatures=event.suricata_signature or "None",
                ml_label=event.ml_prediction or "N/A",
                ml_conf=f"{event.ml_confidence:.0%}" if event.ml_confidence else "N/A",
                dest_port=event.destination_port or "Unknown",
                related_count=related_count,
                protocol=event.protocol or "Unknown",
            )
            llm_response = await ollama_service.generate(prompt)
            if llm_response:
                explanation = llm_response
                llm_used = True
            else:
                explanation = self._fallback_explanation(event, related_count)
        else:
            explanation = self._fallback_explanation(event, related_count)

        # Build hypotheses
        hypotheses = self._generate_hypotheses(event)

        # Determine confidence based on evidence strength
        confidence = self._estimate_confidence(event, related_count)

        investigation = InvestigationResult(
            investigation_id=f"inv-{uuid.uuid4().hex[:12]}",
            event_id=event.event_id,
            attack_type=event.attack_category,
            entry_point=event.source_ip,
            target=event.destination_ip,
            nodes=nodes,
            edges=edges,
            attack_path=[
                {"source": event.source_ip, "target": event.destination_ip,
                 "protocol": event.protocol, "port": event.destination_port}
            ],
            affected_assets=affected_assets,
            observed_evidence=observed,
            hypotheses=hypotheses,
            potential_impact=self._assess_impact(event),
            confidence=confidence,
            explanation=explanation,
            llm_used=llm_used,
            created_at=datetime.now(tz=timezone.utc),
        )

        await self._persist(investigation)
        self._investigations_done += 1
        self._status = "IDLE"

        # Broadcast
        await ws_manager.broadcast({
            "type": "investigation_complete",
            "payload": investigation.model_dump(),
        })

        # Forward to Defence Agent
        await self._out_queue.put(investigation)
        logger.info(
            "AttackAnalysisAgent: investigation %s complete | type=%s | llm=%s",
            investigation.investigation_id, event.attack_category, llm_used,
        )

    def _build_attack_path(
        self, event: DetectionEvent, related_events: list
    ) -> tuple[List[AttackPathNode], List[AttackPathEdge]]:
        """Build React Flow-compatible nodes and edges."""
        nodes: List[AttackPathNode] = []
        edges: List[AttackPathEdge] = []
        seen_ips: set = set()

        # Attacker node
        nodes.append(AttackPathNode(
            id=f"node-{event.source_ip.replace('.', '_')}",
            ip=event.source_ip,
            node_type="attacker",
            risk_level=event.severity,
            label=f"Attacker\n{event.source_ip}",
        ))
        seen_ips.add(event.source_ip)

        # Target node
        nodes.append(AttackPathNode(
            id=f"node-{event.destination_ip.replace('.', '_')}",
            ip=event.destination_ip,
            node_type="victim",
            risk_level="MEDIUM",
            label=f"Target\n{event.destination_ip}",
        ))
        seen_ips.add(event.destination_ip)

        # Edge: attacker → target
        edges.append(AttackPathEdge(
            source=f"node-{event.source_ip.replace('.', '_')}",
            target=f"node-{event.destination_ip.replace('.', '_')}",
            label=f"{event.protocol or 'UNKNOWN'}:{event.destination_port or '?'}",
            observed=True,
        ))

        # Additional intermediate nodes from related events
        for rel in related_events[:5]:  # limit to avoid graph clutter
            rel_dest = rel.get("destination_ip", "")
            if rel_dest and rel_dest not in seen_ips and rel_dest != event.destination_ip:
                node_id = f"node-{rel_dest.replace('.', '_')}"
                nodes.append(AttackPathNode(
                    id=node_id,
                    ip=rel_dest,
                    node_type="intermediate",
                    risk_level="LOW",
                    label=f"Related\n{rel_dest}",
                ))
                edges.append(AttackPathEdge(
                    source=f"node-{event.source_ip.replace('.', '_')}",
                    target=node_id,
                    label="related",
                    observed=True,
                ))
                seen_ips.add(rel_dest)

        return nodes, edges

    def _fallback_explanation(self, event: DetectionEvent, related_count: int) -> str:
        """Generate a deterministic explanation when Ollama is unavailable."""
        lines = [
            f"OBSERVED: Network traffic from {event.source_ip} to {event.destination_ip} "
            f"was classified as suspicious. "
            + (f"Suricata triggered: '{event.suricata_signature}'. " if event.suricata_alert else "")
            + (f"ML model classified traffic as {event.ml_prediction} "
               f"({event.ml_confidence:.0%} confidence). " if event.ml_prediction else ""),
        ]

        if event.attack_category:
            lines.append(
                f"POSSIBLE_PROGRESSION: [HYPOTHESIS] Based on the detected pattern "
                f"({event.attack_category}), the source may be attempting to {event.attack_category.lower()}. "
                "This is a hypothesis based on behavioral patterns, not confirmed compromise."
            )

        lines.append(
            f"AFFECTED_ASSETS: Source {event.source_ip} and target {event.destination_ip} "
            "are directly involved. Additional hosts may be at risk if lateral movement occurs."
        )

        steps = [
            f"Review firewall logs for traffic from {event.source_ip}",
            f"Check service health on {event.destination_ip}:{event.destination_port or 'N/A'}",
        ]
        if related_count > 0:
            steps.append(f"Investigate {related_count} related events from the same source")
        lines.append("INVESTIGATION_STEPS: " + "; ".join(steps))

        return "\n\n".join(lines)

    def _generate_hypotheses(self, event: DetectionEvent) -> List[str]:
        hypotheses = []
        if event.attack_category == "Port Scanning":
            hypotheses.append(
                "[HYPOTHESIS] Source may be mapping open ports for subsequent exploitation"
            )
        elif event.attack_category == "Brute Force":
            hypotheses.append(
                "[HYPOTHESIS] Source may be attempting unauthorized credential access"
            )
        elif event.attack_category == "Denial of Service":
            hypotheses.append(
                "[HYPOTHESIS] Source may be attempting service disruption"
            )
        elif event.attack_category == "Botnet Communication":
            hypotheses.append(
                "[HYPOTHESIS] Source may be communicating with a command-and-control server"
            )
        else:
            hypotheses.append(
                "[HYPOTHESIS] Exact attack intent unclear from available evidence alone"
            )
        return hypotheses

    def _assess_impact(self, event: DetectionEvent) -> str:
        if event.severity in ("CRITICAL", "HIGH"):
            return "HIGH"
        if event.severity == "MEDIUM":
            return "MEDIUM"
        return "LOW"

    def _estimate_confidence(self, event: DetectionEvent, related_count: int) -> float:
        """Evidence-based confidence: more sources = higher confidence."""
        score = 0.0
        if event.suricata_alert:
            score += 0.4
        if event.ml_prediction == "ATTACK":
            score += (event.ml_confidence or 0.0) * 0.4
        if related_count > 0:
            score += min(related_count * 0.05, 0.2)
        return round(min(score, 1.0), 2)

    async def _get_related_events(self, src_ip: str, dest_ip: str) -> list:
        from backend.database.models import SecurityEvent
        from sqlalchemy import select, or_

        try:
            async with self._db_factory() as session:
                cutoff = datetime.utcnow() - timedelta(hours=24)
                result = await session.execute(
                    select(SecurityEvent)
                    .where(
                        or_(
                            SecurityEvent.source_ip == src_ip,
                            SecurityEvent.destination_ip == dest_ip,
                        ),
                        SecurityEvent.created_at >= cutoff,
                    )
                    .limit(20)
                )
                rows = result.scalars().all()
                return [
                    {
                        "event_id": r.event_id,
                        "source_ip": r.source_ip,
                        "destination_ip": r.destination_ip,
                        "attack_category": r.attack_category,
                        "severity": r.severity,
                    }
                    for r in rows
                ]
        except Exception as exc:
            logger.warning("Could not query related events: %s", exc)
            return []

    async def _persist(self, inv: InvestigationResult) -> None:
        from backend.database.models import AgentInvestigation, AttackPath

        try:
            async with self._db_factory() as session:
                ai = AgentInvestigation(
                    investigation_id=inv.investigation_id,
                    event_id=inv.event_id,
                    attack_type=inv.attack_type,
                    entry_point=inv.entry_point,
                    target=inv.target,
                    affected_assets=json.dumps(inv.affected_assets),
                    observed_evidence=json.dumps(inv.observed_evidence),
                    hypotheses=json.dumps(inv.hypotheses),
                    potential_impact=inv.potential_impact,
                    confidence=inv.confidence,
                    explanation=inv.explanation,
                    llm_used=inv.llm_used,
                )
                session.add(ai)

                ap = AttackPath(
                    path_id=f"path-{uuid.uuid4().hex[:12]}",
                    investigation_id=inv.investigation_id,
                    nodes=json.dumps([n.model_dump() for n in inv.nodes]),
                    edges=json.dumps([e.model_dump() for e in inv.edges]),
                )
                session.add(ap)
                await session.commit()
        except Exception as exc:
            logger.error("AttackAnalysisAgent DB persist error: %s", exc, exc_info=True)
