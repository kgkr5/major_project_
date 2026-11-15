# AgentShield – Implementation Task List

**Version:** 1.0  
**Date:** 2026-11-01

Status key: `[ ]` = pending · `[~]` = in progress · `[x]` = complete · `[!]` = blocked

---

## PHASE 1: Project Architecture and Environment Setup

### Task 1.1 – Repository structure
- [ ] Create top-level directories: `backend/`, `frontend/`, `ml/`, `models/`, `data/captures/`, `data/test_pcaps/`, `logs/`, `docs/`
- [ ] Create `backend/` subdirectories: `agents/`, `capture/`, `services/`, `database/`, `api/`, `schemas/`, `core/`, `tests/`
- [ ] Create placeholder `__init__.py` files in all Python packages
- [ ] Create `.gitignore` (Python, Node, env, PCAP files, model files, SQLite DB)

### Task 1.2 – Backend environment
- [ ] Create `backend/requirements.txt` with pinned versions:
  - fastapi, uvicorn[standard], pydantic, pydantic-settings
  - sqlalchemy, aiosqlite, alembic
  - scapy, dpkt
  - scikit-learn, pandas, numpy, joblib
  - httpx (Ollama client)
  - python-multipart (file upload)
  - pytest, pytest-asyncio, pytest-cov
- [ ] Create `backend/.env.example` with all config keys documented
- [ ] Create `backend/core/config.py` using Pydantic Settings
- [ ] Create `backend/core/logging_config.py` with structured logging setup
- [ ] Verify Python 3.10+ is available in WSL2

### Task 1.3 – Frontend scaffolding
- [ ] Scaffold with `npm create vite@latest frontend -- --template react-ts`
- [ ] Install and pin: tailwindcss, recharts, reactflow, react-router-dom, @tanstack/react-query, lucide-react, zustand
- [ ] Configure `tailwind.config.ts` with custom color palette from design doc
- [ ] Create base layout shell (Sidebar + Header + main content area)
- [ ] Configure `vite.config.ts` API proxy to `http://localhost:8000`

### Task 1.4 – ML directory
- [ ] Create `ml/` directory with `README_training.md`
- [ ] Create `ml/feature_schema.py` defining the 77-feature ordered list (single source of truth)
- [ ] Create `models/` directory with `.gitkeep`

**Phase 1 done when:** `backend/core/config.py` imports without error; `cd frontend && npm run build` succeeds; directory structure matches design doc.

---

## PHASE 2: Database and Backend Foundation

### Task 2.1 – Database models
- [ ] Create `backend/database/database.py`: async SQLAlchemy engine, session factory, `get_db` dependency
- [ ] Create `backend/database/models.py`: all 8 SQLAlchemy ORM models matching design doc schema
- [ ] Create `backend/database/init_db.py`: `create_all_tables()` function
- [ ] Add indexes as defined in design doc

### Task 2.2 – Pydantic schemas
- [ ] Create `backend/schemas/events.py`: `SecurityEvent`, `SecurityEventCreate`, `SecurityEventList`
- [ ] Create `backend/schemas/flows.py`: `FlowRecord`, `NetworkFlow`
- [ ] Create `backend/schemas/agents.py`: `DetectionEvent`, `InvestigationResult`, `DefenceRecommendation`
- [ ] Create `backend/schemas/health.py`: `ComponentHealth`, `SystemHealth`
- [ ] Create `backend/schemas/dashboard.py`: `DashboardStats`, `ThreatTimelinePoint`

### Task 2.3 – FastAPI application skeleton
- [ ] Create `backend/main.py`: FastAPI app with CORS, lifespan, router registration
- [ ] Create `backend/api/dashboard.py`: stub endpoints returning empty data
- [ ] Create `backend/api/events.py`: stub endpoints
- [ ] Create `backend/api/health.py`: stub health endpoint returning component status
- [ ] Create `backend/api/network.py`: stub endpoints
- [ ] Create `backend/api/agents.py`: stub endpoints
- [ ] Create `backend/api/reports.py`: stub endpoint
- [ ] Create `backend/api/settings.py`: stub endpoint
- [ ] Register all routers in `main.py`
- [ ] Verify `uvicorn main:app --reload` starts successfully
- [ ] Verify `GET /api/v1/health` returns 200

### Task 2.4 – WebSocket foundation
- [ ] Create `backend/core/websocket_manager.py`: connection manager for broadcast
- [ ] Add `/ws/events` WebSocket endpoint to `main.py`
- [ ] Verify WebSocket connects and receives `connection_ack` message

### Task 2.5 – Database tests
- [ ] Write `backend/tests/test_database.py`: create/read/update for each model
- [ ] Verify all tests pass

**Phase 2 done when:** all DB model tests pass; FastAPI starts; `/api/v1/health` returns 200; WebSocket connects.

---

## PHASE 3: Suricata Integration and Event Processing

### Task 3.1 – Suricata service
- [ ] Create `backend/services/suricata_service.py`
  - Tail-read EVE JSON with file position tracking
  - Parse `alert` and `flow` event types
  - Deduplicate within configurable window
  - Handle log rotation (file shrinks / new inode)
  - Push parsed events to asyncio queue
- [ ] Create `backend/services/suricata_health.py`: verify process running + log freshness

### Task 3.2 – Suricata health API
- [ ] Implement `GET /api/v1/health/suricata` with real check
- [ ] Update `GET /api/v1/health` to include Suricata component

### Task 3.3 – Suricata tests
- [ ] Create `backend/tests/test_suricata_service.py`
  - Test parsing a sample `alert` event
  - Test parsing a sample `flow` event
  - Test deduplication
  - Test file rotation handling
  - Use fixture EVE JSON files in `backend/tests/fixtures/`
- [ ] Verify all tests pass

**Phase 3 done when:** Suricata service parses test fixtures correctly; health endpoint reflects real Suricata status; all Suricata tests pass.

---

## PHASE 4: PCAP Processing and CICFlowMeter Feature Extraction

### Task 4.1 – Flow extractor
- [ ] Create `backend/services/flow_extractor.py`
  - Bidirectional flow tracking keyed by (src_ip, dest_ip, src_port, dest_port, proto)
  - Compute all 77 features per flow
  - Use `dpkt` for packet parsing (no dependency on Java CICFlowMeter binary)
  - Return `List[FlowRecord]`
- [ ] Import feature schema from `ml/feature_schema.py` to guarantee ordering

### Task 4.2 – Feature normalizer
- [ ] Create `backend/services/feature_normalizer.py`
  - Map feature names to model-ordered indices
  - Handle Inf → cap, NaN → 0 with warning
  - Verify output length = 77
  - Log and return None for invalid records

### Task 4.3 – PCAP processor
- [ ] Create `backend/capture/pcap_processor.py`
  - Accept PCAP file path
  - Call flow extractor → normalizer
  - Return `List[FlowRecord]` + stats
- [ ] Create `backend/capture/packet_capture.py`
  - Scapy-based rotating PCAP writer
  - Start/stop control
  - Write to `data/captures/`
- [ ] Create `backend/capture/sensor_manager.py`
  - Lifecycle management
  - Status reporting

### Task 4.4 – PCAP upload API
- [ ] Implement `POST /api/v1/flows/upload-pcap` in `backend/api/network.py`
  - Validate file type (check PCAP magic bytes: `\xd4\xc3\xb2\xa1` or `\xa1\xb2\xc3\xd4`)
  - Enforce size limit
  - Run processing in FastAPI `BackgroundTask`
  - Return `task_id` immediately
- [ ] Implement `GET /api/v1/flows/upload/{task_id}/status`

### Task 4.5 – Flow extraction tests
- [ ] Create `backend/tests/test_flow_extractor.py`
  - Generate synthetic PCAP with Scapy for: TCP, UDP, bidirectional, multiple flows
  - Verify feature count = 77 for each flow
  - Verify no NaN/Inf in output
  - Verify packet count features are accurate
  - Test with TCP retransmissions
  - Test with different TCP flags
- [ ] Verify all tests pass

**Phase 4 done when:** flow extractor produces 77-feature vectors from test PCAPs; upload endpoint accepts and processes a PCAP asynchronously; all extraction tests pass.

---

## PHASE 5: Feature Validation and Reference Comparison

### Task 5.1 – Feature verification
- [ ] Create `backend/tests/test_feature_normalizer.py`
  - Test with valid feature dict → correct numpy array
  - Test with NaN values → warning + replacement
  - Test with Inf values → capping
  - Test with missing feature → returns None + log
  - Test with wrong feature count → raises error
- [ ] Document differences from Java CICFlowMeter in `docs/feature_differences.md`

### Task 5.2 – Feature schema validation
- [ ] Create `backend/tests/test_feature_schema.py`
  - Assert exactly 77 features defined in `ml/feature_schema.py`
  - Assert no duplicate feature names
  - Assert feature order matches model metadata (after model training in Phase 6)

**Phase 5 done when:** all normalizer tests pass; schema validation test passes; differences from reference implementation are documented.

---

## PHASE 6: Random Forest Model Integration

### Task 6.1 – Training script
- [ ] Create `ml/data_loader.py`: load CICIDS2017 CSVs, clean, encode labels
- [ ] Create `ml/feature_selector.py`: select/reorder the 77 features matching `feature_schema.py`
- [ ] Create `ml/train.py`: full training pipeline with time-aware split, RandomForestClassifier, save model + metadata
- [ ] Create `ml/evaluate.py`: print accuracy, precision, recall, F1, confusion matrix, FPR, FNR
- [ ] Create `ml/README_training.md`: dataset download instructions, training command

### Task 6.2 – Fallback model for testing
- [ ] Create `ml/create_test_model.py`: generate a small synthetic model (without real CICIDS data) for CI testing
- [ ] Save to `models/agentshield_rf_test.pkl` (NOT overwriting production model)

### Task 6.3 – ML service
- [ ] Create `backend/services/ml_service.py`
  - Load model + metadata at startup
  - `predict(features: np.ndarray) -> PredictionResult`
  - Model health check
  - Handle model file not found gracefully (status = UNAVAILABLE)
- [ ] Implement `GET /api/v1/health/model`

### Task 6.4 – ML tests
- [ ] Create `backend/tests/test_ml_service.py`
  - Load test model (from `create_test_model.py`)
  - Test predict with valid 77-feature vector
  - Test predict with wrong feature count → error
  - Test predict with NaN → error before reaching model
  - Test model health when file missing
- [ ] Verify all tests pass

**Phase 6 done when:** ML service loads model, predicts, and handles errors correctly; all ML tests pass; model health endpoint works.

---

## PHASE 7: Detection Agent

### Task 7.1 – Detection agent implementation
- [ ] Create `backend/agents/detection_agent.py`
  - Async event loop consuming from detection_queue
  - Correlate Suricata alerts with ML predictions by (IP, time ±5 s)
  - Apply all attack-category detection rules from design doc
  - Call `risk_engine.calculate()`
  - Produce `DetectionEvent` output schema
  - Persist to `security_events` and `risk_assessments` tables
  - Broadcast via WebSocket manager
  - Enqueue to analysis_queue

### Task 7.2 – Risk engine
- [ ] Create `backend/services/risk_engine.py`
  - Deterministic scoring formula from design doc
  - Configurable thresholds from settings
  - Output `RiskAssessment` with `score`, `severity`, `contributing_factors`

### Task 7.3 – Detection Agent API
- [ ] Implement `GET /api/v1/agents/detection/events`
- [ ] Implement `GET /api/v1/agents/status` (all three agents)

### Task 7.4 – Detection agent tests
- [ ] Create `backend/tests/test_detection_agent.py`
  - Test with Suricata alert only → produces event
  - Test with ML ATTACK prediction only → produces event
  - Test with both → correlates correctly
  - Test attack category rules (port scan, brute force, DoS)
  - Test risk score calculation
  - Test event persistence
- [ ] Create `backend/tests/test_risk_engine.py`
  - Test each contributing factor
  - Test threshold boundaries
  - Test max score capping at 100
- [ ] Verify all tests pass

**Phase 7 done when:** Detection Agent processes test events end-to-end; produces correct schema; persists to DB; risk scores calculated deterministically; all tests pass.

---

## PHASE 8: Attack Analysis Agent

### Task 8.1 – Ollama service
- [ ] Create `backend/services/ollama_service.py`
  - POST to `{OLLAMA_HOST}/api/generate`
  - Timeout handling
  - Connection error → return None
  - Parse streamed response
- [ ] Implement `GET /api/v1/health/ollama`

### Task 8.2 – Attack analysis agent implementation
- [ ] Create `backend/agents/attack_analysis_agent.py`
  - Async event loop consuming from analysis_queue
  - DB query for related events
  - Build attack path graph (nodes + edges)
  - Call Ollama with structured prompt (fallback to template if unavailable)
  - Produce `InvestigationResult` output schema
  - Persist to `agent_investigations` and `attack_paths` tables
  - Broadcast via WebSocket
  - Enqueue to defence_queue

### Task 8.3 – Investigation API
- [ ] Implement `GET /api/v1/agents/analysis/investigations`
- [ ] Implement `GET /api/v1/events/{event_id}/investigation`

### Task 8.4 – Attack analysis tests
- [ ] Create `backend/tests/test_attack_analysis_agent.py`
  - Test with Ollama available (mock Ollama server)
  - Test with Ollama unavailable → fallback template used
  - Test attack path graph construction
  - Test related-events query
  - Test investigation persistence
- [ ] Create `backend/tests/test_ollama_service.py`
  - Test timeout handling
  - Test connection error handling
  - Test response parsing
- [ ] Verify all tests pass

**Phase 8 done when:** Attack Analysis Agent produces investigations with attack paths; Ollama integration works with fallback; all tests pass.

---

## PHASE 9: Defence Agent and Risk Engine

### Task 9.1 – Defence agent implementation
- [ ] Create `backend/agents/defence_agent.py`
  - Async event loop consuming from defence_queue
  - Map attack_type + severity → recommendation templates
  - Generate prioritized `RecommendedAction` list
  - Set `requires_admin_approval = True`
  - Set `execution_status = "RECOMMENDED"`
  - Persist to `defence_recommendations`
  - Broadcast via WebSocket

### Task 9.2 – Defence Agent API
- [ ] Implement `GET /api/v1/agents/defence/recommendations`
- [ ] Implement `POST /api/v1/agents/defence/recommendations/{id}/approve` (admin action, audit logged)
- [ ] Implement `POST /api/v1/agents/defence/recommendations/{id}/reject` (admin action, audit logged)
- [ ] Implement `GET /api/v1/events/{event_id}/defence`

### Task 9.3 – Defence agent tests
- [ ] Create `backend/tests/test_defence_agent.py`
  - Test recommendation generation for each attack type
  - Test `requires_admin_approval = True` enforced
  - Test `execution_status = "RECOMMENDED"` (never "EXECUTED")
  - Test approve/reject audit logging
  - Test persistence
- [ ] Verify all tests pass

**Phase 9 done when:** Defence Agent generates appropriate recommendations; admin approve/reject works; no commands executed automatically; all tests pass.

---

## PHASE 10: FastAPI Endpoints and WebSockets

### Task 10.1 – Dashboard API
- [ ] Implement `GET /api/v1/dashboard/stats` (from DB aggregation)
- [ ] Implement `GET /api/v1/dashboard/threat-timeline`
- [ ] Implement `GET /api/v1/dashboard/severity-distribution`
- [ ] Implement `GET /api/v1/dashboard/top-sources`

### Task 10.2 – Events API
- [ ] Implement `GET /api/v1/events` with pagination, filtering, date range
- [ ] Implement `GET /api/v1/events/{event_id}` with full detail

### Task 10.3 – Reports API
- [ ] Implement `GET /api/v1/reports/summary` (JSON summary)
- [ ] Implement `GET /api/v1/reports/export?format=csv` (CSV export)

### Task 10.4 – Settings API
- [ ] Implement `GET /api/v1/settings` (read current config)
- [ ] Implement `PUT /api/v1/settings` (update non-secret config, audit logged)

### Task 10.5 – WebSocket complete implementation
- [ ] Wire all agent outputs to WebSocket broadcast
- [ ] Implement `connection_ack` with current stats snapshot
- [ ] Handle client disconnect gracefully
- [ ] Test concurrent WebSocket connections

### Task 10.6 – End-to-end pipeline startup
- [ ] Wire all async queues and agents in `main.py` lifespan
- [ ] Start sensor manager, Suricata service, all three agents as background tasks
- [ ] Verify full pipeline processes a test PCAP on startup

### Task 10.7 – API tests
- [ ] Create `backend/tests/test_api_dashboard.py`
- [ ] Create `backend/tests/test_api_events.py`
- [ ] Create `backend/tests/test_api_health.py`
- [ ] Create `backend/tests/test_api_network.py`
- [ ] Create `backend/tests/test_websocket.py`
- [ ] Verify all tests pass

**Phase 10 done when:** all REST endpoints return real data; WebSocket broadcasts new events; full pipeline starts from `main.py`; all API tests pass.

---

## PHASE 11: React SOC Dashboard

### Task 11.1 – Base layout and routing
- [ ] Implement `Sidebar` with 8-page navigation
- [ ] Implement `Header` with connection status indicator
- [ ] Implement `StatusBar` showing component health
- [ ] Set up React Router routes for all 8 pages
- [ ] Set up WebSocket hook (`useWebSocket.ts`)
- [ ] Set up React Query client

### Task 11.2 – Overview Dashboard (Page 1)
- [ ] Implement stat cards: flows, events, attacks, critical, high, benign, active sensors, model status, agent status
- [ ] Implement `ThreatTimeline` chart (Recharts AreaChart)
- [ ] Implement `SeverityDistribution` chart (Recharts PieChart)
- [ ] Implement `RecentEvents` table with severity badges
- [ ] Wire all data to `/api/v1/dashboard/*` endpoints

### Task 11.3 – Live Network Monitoring (Page 2)
- [ ] Implement live flow table with auto-refresh via WebSocket
- [ ] Show: src IP, dest IP, ports, protocol, packets, rate, classification, detection status
- [ ] Add column sorting and pagination

### Task 11.4 – Threat Detection (Page 3)
- [ ] Implement threat list with severity filter, search, date range filter
- [ ] Show: category, severity badge, risk score bar, ML prediction + confidence, Suricata sig, timestamp, evidence summary
- [ ] Click-through to Event Detail page

### Task 11.5 – Attack Path Analysis (Page 4)
- [ ] Implement React Flow graph component
- [ ] Node types: attacker (red), victim (orange), intermediate (yellow), safe (green)
- [ ] Edge labels: protocol + port, observed vs inferred styling
- [ ] Investigation summary panel alongside graph
- [ ] Investigation list sidebar for selection

### Task 11.6 – AI Agent Activity (Page 5)
- [ ] Detection Agent panel: status, events analyzed, threats detected, latest findings
- [ ] Attack Analysis Agent panel: investigations completed, current analysis, hypotheses
- [ ] Defence Agent panel: recommendations, priority badges, approval status, history
- [ ] Real-time updates via WebSocket

### Task 11.7 – Security Event Detail (Page 6)
- [ ] Full event metadata display
- [ ] Suricata evidence section
- [ ] ML prediction display with confidence bar
- [ ] Agent analysis section
- [ ] Risk explanation section
- [ ] Defence recommendations section with approve/reject buttons (admin action)

### Task 11.8 – Reports (Page 7)
- [ ] Summary statistics display
- [ ] Historical trend chart
- [ ] Severity distribution
- [ ] Top affected hosts table
- [ ] Export buttons: CSV
- [ ] Date range picker

### Task 11.9 – Settings & System Health (Page 8)
- [ ] Component health grid: Suricata, capture, CICFlowMeter, ML model, Ollama, backend, database
- [ ] Each component: status indicator (green/yellow/red), last checked time, details
- [ ] Sensor configuration display
- [ ] Clear "unavailable" indicators when components are down

**Phase 11 done when:** all 8 pages render with real backend data; WebSocket updates reflect in real time; no hardcoded values in any UI metric.

---

## PHASE 12: Complete System Integration

### Task 12.1 – End-to-end pipeline verification
- [ ] Run full pipeline with a real or synthetic PCAP file
- [ ] Verify: PCAP → features → ML prediction → Detection Agent → DB → WebSocket → dashboard update
- [ ] Verify: Suricata alert → Detection Agent → Attack Analysis Agent → Defence Agent → recommendations
- [ ] Verify: all 8 dashboard pages show data from the pipeline run

### Task 12.2 – WSL2 / Windows integration
- [ ] Document which network interfaces are visible in WSL2
- [ ] Test capture on WSL2 loopback and Ethernet bridge
- [ ] Document Npcap setup for Windows-level capture (optional)
- [ ] Update Settings page to show which interfaces are available

### Task 12.3 – Ollama integration verification
- [ ] Verify `llama3.2` model is available in Ollama
- [ ] Test Attack Analysis Agent with Ollama enabled
- [ ] Test fallback behavior when Ollama is stopped
- [ ] Verify explanations are structured and not hallucinated CVEs

**Phase 12 done when:** full end-to-end pipeline demonstrated; dashboard shows real data from real pipeline; Ollama fallback tested.

---

## PHASE 13: Testing, Debugging, and Performance

### Task 13.1 – Integration test suite
- [ ] Create `backend/tests/test_integration.py`
  - Full pipeline test: synthetic PCAP → flow extraction → ML → Detection Agent → DB → WebSocket
  - PCAP upload API → background task → results available via API
  - Suricata fixture → Detection Agent → Investigation → Defence recommendation
- [ ] All integration tests must pass without live network access

### Task 13.2 – Performance verification
- [ ] Measure API response time for `/api/v1/dashboard/stats` under simulated load
- [ ] Measure flow extraction time for 60-second PCAP
- [ ] Verify WebSocket broadcast latency < 2 seconds
- [ ] Profile and optimize any bottlenecks found

### Task 13.3 – Error handling review
- [ ] Verify all error cases are handled (not just happy path)
- [ ] Test with malformed PCAP file → graceful error
- [ ] Test with Suricata down → health shows DEGRADED, pipeline continues
- [ ] Test with ML model missing → health shows model UNAVAILABLE, pipeline continues without ML
- [ ] Test with database locked → retry logic works
- [ ] Verify no unhandled exceptions bubble to API responses

### Task 13.4 – Coverage report
- [ ] Run `pytest --cov=. --cov-report=html`
- [ ] Review coverage and add missing tests for critical paths
- [ ] Target ≥ 70% coverage on core services and agents

**Phase 13 done when:** all integration tests pass; error scenarios handled correctly; coverage ≥ 70%.

---

## PHASE 14: Documentation and Deployment

### Task 14.1 – README.md
- [ ] Architecture diagram (ASCII or image)
- [ ] Prerequisites (Python, Node, WSL2, Suricata, Ollama, CICIDS2017)
- [ ] Installation steps (backend, frontend, ML model, Suricata, Ollama)
- [ ] Running instructions (backend, frontend, full pipeline)
- [ ] Configuration reference (all `.env` variables)
- [ ] Troubleshooting section
- [ ] Known limitations section
- [ ] End-to-end demonstration instructions

### Task 14.2 – Component documentation
- [ ] `docs/suricata_setup.md`: Suricata installation and configuration in WSL2
- [ ] `docs/ollama_setup.md`: Ollama installation and model download
- [ ] `docs/ml_training.md`: CICIDS2017 dataset download + training steps
- [ ] `docs/feature_differences.md`: differences from Java CICFlowMeter
- [ ] `docs/api_reference.md`: all endpoints with request/response examples

### Task 14.3 – Deployment scripts
- [ ] Create `scripts/setup_wsl.sh`: install Python deps, create venv, init DB
- [ ] Create `scripts/start_backend.sh`: activate venv, start uvicorn
- [ ] Create `scripts/start_frontend.sh`: install node deps, start dev server
- [ ] Create `scripts/test_all.sh`: run all tests with coverage

**Phase 14 done when:** README covers all installation and usage steps; all documentation files present; setup scripts tested.

---

## Dependency Matrix

```
Phase 1  → no dependencies
Phase 2  → Phase 1
Phase 3  → Phase 2
Phase 4  → Phase 2, Phase 3 (parallel with Phase 3)
Phase 5  → Phase 4
Phase 6  → Phase 5 (needs feature schema from Phase 1/5)
Phase 7  → Phase 6, Phase 3 (Detection Agent needs ML + Suricata)
Phase 8  → Phase 7
Phase 9  → Phase 8
Phase 10 → Phase 7, Phase 8, Phase 9
Phase 11 → Phase 10 (frontend needs working API)
Phase 12 → Phase 10, Phase 11
Phase 13 → Phase 12
Phase 14 → Phase 13
```

---

## Test Fixtures Required

Create in `backend/tests/fixtures/`:

| File | Purpose |
|------|---------|
| `sample_alert.json` | Single Suricata alert event |
| `sample_flow_event.json` | Single Suricata flow event |
| `eve_sample.json` | Multi-event EVE JSON file |
| `test_tcp.pcap` | Simple TCP flow (Scapy-generated) |
| `test_udp.pcap` | UDP flow |
| `test_mixed.pcap` | Multiple simultaneous flows |
| `test_portscan.pcap` | SYN scan pattern |
| `test_malformed.pcap` | Truncated PCAP for error testing |
