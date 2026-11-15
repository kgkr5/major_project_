


import asyncio
from datetime import datetime, timezone

import pytest
from sqlalchemy import select, func

from backend.database.database import AsyncSessionLocal
from backend.database.models import (
    SecurityEvent,
    AgentInvestigation,
    AttackPath,
    DefenceRecommendation,
)

from backend.agents.detection_agent import DetectionAgent
from backend.agents.attack_analysis_agent import AttackAnalysisAgent
from backend.agents.defence_agent import DefenceAgent

from backend.schemas.flows import FlowRecord, PredictionResult
from ml.feature_schema import FEATURE_NAMES, FEATURE_INDEX


@pytest.mark.asyncio
async def test_three_agent_attack_pipeline(db_session):

    # Create communication queues
    detection_queue = asyncio.Queue()
    analysis_queue = asyncio.Queue()
    defence_queue = asyncio.Queue()

    # Initialize all three agents
    detection = DetectionAgent(
        detection_queue,
        analysis_queue,
        AsyncSessionLocal
    )

    analysis = AttackAnalysisAgent(
        analysis_queue,
        defence_queue,
        AsyncSessionLocal
    )

    defence = DefenceAgent(
        defence_queue,
        AsyncSessionLocal
    )

    # Create simulated network traffic
    features = [0.0] * 77

    features[FEATURE_INDEX["Destination Port"]] = 22
    features[FEATURE_INDEX["SYN Flag Count"]] = 8
    features[FEATURE_INDEX["ACK Flag Count"]] = 0

    flow = FlowRecord(
        flow_id="agentshield-test-flow",
        src_ip="192.0.2.55",
        dest_ip="198.51.100.20",
        src_port=49152,
        dest_port=22,
        protocol="TCP",
        timestamp=datetime.now(timezone.utc),
        features=features,
        feature_names=FEATURE_NAMES,
        duration_us=1000000,
        pcap_source="automated_test",
    )

    # Simulated ML attack prediction
    prediction = PredictionResult(
        label="ATTACK",
        confidence=0.99,
        probabilities={
            "BENIGN": 0.01,
            "ATTACK": 0.99
        },
        model_version="test",
    )

    # ==========================================
    # STAGE 1: DETECTION AGENT
    # ==========================================

    await detection._process((flow, prediction))

    assert not analysis_queue.empty(), (
        "Detection Agent did not forward the event!"
    )

    event = await analysis_queue.get()

    assert event.attack_category == "Port Scanning"
    assert event.ml_prediction == "ATTACK"
    assert event.risk_score > 0

    print("\n[1] DETECTION AGENT: PASSED")
    print(f"Attack Category: {event.attack_category}")
    print(f"Risk Score: {event.risk_score}")
    print(f"Event ID: {event.event_id}")

    # ==========================================
    # STAGE 2: ATTACK ANALYSIS AGENT
    # ==========================================

    await analysis._investigate(event)

    assert not defence_queue.empty(), (
        "Attack Analysis Agent did not forward investigation!"
    )

    investigation = await defence_queue.get()

    assert investigation.event_id == event.event_id
    assert len(investigation.nodes) >= 2

    print("\n[2] ATTACK ANALYSIS AGENT: PASSED")
    print(f"Attack Type: {investigation.attack_type}")
    print(f"Attack Path Nodes: {len(investigation.nodes)}")
    print(f"LLM Used: {investigation.llm_used}")

    # ==========================================
    # STAGE 3: DEFENCE AGENT
    # ==========================================

    await defence._recommend(investigation)

    print("\n[3] DEFENCE AGENT: PASSED")
    print("Defence recommendations generated.")

    # ==========================================
    # STAGE 4: DATABASE PERSISTENCE VERIFICATION
    # ==========================================

    print("\n===== DATABASE VERIFICATION =====")

    tables = {
        "Security Events": SecurityEvent,
        "Investigations": AgentInvestigation,
        "Attack Paths": AttackPath,
        "Defence Recommendations": DefenceRecommendation,
    }

    async with AsyncSessionLocal() as session:

        for name, model in tables.items():

            result = await session.execute(
                select(func.count()).select_from(model)
            )

            count = result.scalar_one()

            print(f"{name}: {count}")

            assert count >= 1, (
                f"Database persistence failed for {name}!"
            )

    print("\n===== ALL PIPELINE CHECKS PASSED =====")
