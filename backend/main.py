"""
AgentShield FastAPI application entry point.

Startup sequence:
1. Configure logging
2. Initialize database
3. Load ML model
4. Start background services (Suricata monitor, sensor manager)
5. Start AI agents
6. Register API routers
7. Open WebSocket endpoint
"""

import asyncio
import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

from backend.core.config import settings
from backend.core.logging_config import setup_logging
from backend.core.websocket_manager import manager as ws_manager
from backend.database.database import close_db, init_db, AsyncSessionLocal
from backend.services.ml_service import ml_service
from backend.services.ollama_service import ollama_service

# Set up logging first
setup_logging(log_level=settings.log_level, log_file=settings.log_file)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan: start services on startup, clean up on shutdown."""
    logger.info("=" * 60)
    logger.info("AgentShield %s starting up", settings.app_version)
    logger.info("=" * 60)

    # Ensure required directories exist
    for d in [settings.pcap_output_dir, settings.upload_dir, Path("data"), Path("logs")]:
        d.mkdir(parents=True, exist_ok=True)

    # Initialize database
    try:
        await init_db()
        logger.info("Database initialized.")
    except Exception as exc:
        logger.critical("Database initialization failed: %s", exc, exc_info=True)
        raise

    # Load ML model (non-fatal if missing)
    loaded = ml_service.load()
    if loaded:
        logger.info("ML model loaded successfully.")
    else:
        logger.warning("ML model not loaded. Predictions will be unavailable.")

    # Check Ollama
    ollama_health = await ollama_service.health_check()
    logger.info("Ollama status: %s", ollama_health.get("status"))

    # Build async queues for agent pipeline
    detection_queue: asyncio.Queue = asyncio.Queue(maxsize=1000)
    analysis_queue: asyncio.Queue = asyncio.Queue(maxsize=1000)
    defence_queue: asyncio.Queue = asyncio.Queue(maxsize=1000)

    # Create PCAP processor
    from backend.capture.pcap_processor import PcapProcessor
    pcap_processor = PcapProcessor(
        detection_queue=detection_queue,
        db_session_factory=AsyncSessionLocal,
    )
    app.state.pcap_processor = pcap_processor

    # Create Suricata service
    from backend.services.suricata_service import SuricataService
    suricata_svc = SuricataService(queue=detection_queue)
    app.state.suricata_service = suricata_svc

    # Create sensor manager
    from backend.capture.sensor_manager import SensorManager
    sensor = SensorManager(pcap_processor=pcap_processor)
    app.state.sensor_manager = sensor

    # Create AI agents
    from backend.agents.detection_agent import DetectionAgent
    from backend.agents.attack_analysis_agent import AttackAnalysisAgent
    from backend.agents.defence_agent import DefenceAgent

    detection_agent = DetectionAgent(
        detection_queue=detection_queue,
        analysis_queue=analysis_queue,
        db_session_factory=AsyncSessionLocal,
    )
    analysis_agent = AttackAnalysisAgent(
        analysis_queue=analysis_queue,
        defence_queue=defence_queue,
        db_session_factory=AsyncSessionLocal,
    )
    defence_agent = DefenceAgent(
        defence_queue=defence_queue,
        db_session_factory=AsyncSessionLocal,
    )

    app.state.detection_agent = detection_agent
    app.state.analysis_agent = analysis_agent
    app.state.defence_agent = defence_agent

    # Start background tasks
    tasks = [
        asyncio.create_task(suricata_svc.start(), name="suricata-monitor"),
        asyncio.create_task(sensor.start(), name="sensor-manager"),
        asyncio.create_task(detection_agent.start(), name="detection-agent"),
        asyncio.create_task(analysis_agent.start(), name="analysis-agent"),
        asyncio.create_task(defence_agent.start(), name="defence-agent"),
    ]
    app.state.background_tasks = tasks

    logger.info("All services started. AgentShield is ready.")
    logger.info("API: http://%s:%d", settings.api_host, settings.api_port)
    logger.info("Docs: http://%s:%d/docs", settings.api_host, settings.api_port)

    yield  # ← Application runs here

    # Shutdown
    logger.info("AgentShield shutting down...")
    await suricata_svc.stop()
    await sensor.stop()
    await detection_agent.stop()
    await analysis_agent.stop()
    await defence_agent.stop()

    for task in tasks:
        task.cancel()
        try:
            await task
        except (asyncio.CancelledError, Exception):
            pass

    await close_db()
    logger.info("Shutdown complete.")


# ── FastAPI Application ───────────────────────────────────────────────────────

app = FastAPI(
    title="AgentShield API",
    version=settings.app_version,
    description="Multi-Agent AI Framework for Attack-Path Verification and Autonomous Cyber Defense",
    lifespan=lifespan,
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register API routers
from backend.api.dashboard import router as dashboard_router
from backend.api.events import router as events_router
from backend.api.agents import router as agents_router
from backend.api.network import router as network_router
from backend.api.reports import router as reports_router
from backend.api.settings import router as settings_router
from backend.api.health import router as health_router

app.include_router(dashboard_router)
app.include_router(events_router)
app.include_router(agents_router)
app.include_router(network_router)
app.include_router(reports_router)
app.include_router(settings_router)
app.include_router(health_router)


# ── WebSocket ─────────────────────────────────────────────────────────────────

@app.websocket("/ws/events")
async def websocket_endpoint(websocket: WebSocket):
    await ws_manager.connect(websocket)
    try:
        # Send initial snapshot
        from backend.services.ml_service import ml_service as ml
        await ws_manager.send_personal(websocket, {
            "type": "connection_ack",
            "payload": {
                "message": "Connected to AgentShield",
                "model_status": "OK" if ml.is_available else "UNAVAILABLE",
                "connections": ws_manager.connection_count,
            },
        })

        # Keep connection alive and handle incoming pings
        while True:
            try:
                data = await asyncio.wait_for(websocket.receive_text(), timeout=30)
                if data == "ping":
                    await ws_manager.send_personal(websocket, {"type": "pong"})
            except asyncio.TimeoutError:
                # Send keepalive
                await ws_manager.send_personal(websocket, {"type": "keepalive"})
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)


# ── Root endpoint ─────────────────────────────────────────────────────────────

@app.get("/")
async def root():
    return {
        "name": "AgentShield",
        "version": settings.app_version,
        "status": "running",
        "docs": "/docs",
    }
