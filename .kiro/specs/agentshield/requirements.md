# AgentShield – Requirements Specification

**Version:** 1.0  
**Date:** 2026-11-01  
**Project:** AgentShield: A Multi-Agent AI Framework for Attack-Path Verification and Autonomous Cyber Defense

---

## 1. Purpose

AgentShield is an intelligent cybersecurity monitoring platform that monitors authorized network traffic, identifies suspicious activity, detects potential attacks, analyzes attack paths, calculates risk levels, and provides defensive recommendations. It operates like a lightweight Security Operations Center (SOC).

---

## 2. Stakeholders

| Role | Interest |
|------|----------|
| Security Analyst | Monitor threats, investigate incidents, view recommendations |
| Network Administrator | Configure sensors, review firewall recommendations |
| System Administrator | Manage deployments, approve defensive actions |
| Final Year Project Evaluator | Assess technical completeness and correctness |

---

## 3. Scope

### In Scope
- Authorized network traffic monitoring on designated interfaces
- Intrusion detection via Suricata IDS
- Network flow feature extraction (77 CICIDS2017-compatible features)
- ML-based binary classification (BENIGN / ATTACK)
- Three AI agents: Detection, Attack Analysis, Defence
- Risk scoring engine (deterministic, 0–100)
- Attack-path construction and visualization
- Real-time SOC dashboard (React)
- PCAP upload and offline analysis
- SQLite storage with historical querying
- WebSocket-based live updates

### Out of Scope
- Automated firewall rule execution without administrator approval
- Offensive exploitation capabilities
- Production deployment on cloud infrastructure
- Windows-wide host-based intrusion detection beyond network telemetry

---

## 4. Functional Requirements

### FR-01: Network Traffic Capture
- **FR-01.1** The system SHALL capture network packets on a configurable authorized network interface.
- **FR-01.2** The system SHALL write rotating PCAP files at a configurable interval (default 60 s).
- **FR-01.3** The system SHALL accept PCAP file uploads for offline analysis.
- **FR-01.4** The system SHALL display current sensor status (active / inactive / error) on the dashboard.
- **FR-01.5** The system SHALL identify which interfaces are actually visible from within WSL2 and report limitations clearly.

### FR-02: Suricata Integration
- **FR-02.1** The system SHALL monitor Suricata's EVE JSON log at a configurable path (default `/var/log/suricata/eve.json`).
- **FR-02.2** The system SHALL parse `alert` events and extract: timestamp, src_ip, dest_ip, src_port, dest_port, proto, signature, severity, category.
- **FR-02.3** The system SHALL also parse `flow` events for traffic correlation.
- **FR-02.4** The system SHALL track the last-read file position to avoid reprocessing events.
- **FR-02.5** The system SHALL handle EVE log rotation without data loss.
- **FR-02.6** The system SHALL expose a Suricata health-check endpoint.
- **FR-02.7** The system SHALL deduplicate alerts within a configurable time window.

### FR-03: Network Flow Feature Extraction
- **FR-03.1** The system SHALL extract exactly 77 CICIDS2017-compatible numerical features from network flows.
- **FR-03.2** Feature extraction SHALL cover: forward/backward packet counts, byte counts, packet lengths (min/max/mean/std), header lengths, inter-arrival times (IAT), TCP flag counts, flow duration, flow rates, active/idle periods, bulk statistics, subflow statistics.
- **FR-03.3** The extractor SHALL process both live rotating PCAP files and uploaded PCAP files.
- **FR-03.4** The feature extractor SHALL maintain feature name-to-index mapping consistent with trained model expectations.
- **FR-03.5** The system SHALL log and skip malformed flows rather than crashing.

### FR-04: Machine Learning Classification
- **FR-04.1** The system SHALL load a pre-trained Random Forest model from `models/agentshield_rf.pkl`.
- **FR-04.2** The model SHALL classify each flow as BENIGN or ATTACK with a confidence score.
- **FR-04.3** The system SHALL receive exactly 77 features in the trained model's feature order.
- **FR-04.4** The system SHALL reject feature vectors containing non-finite values (NaN, Inf).
- **FR-04.5** The system SHALL expose model metadata: training dataset, feature count, version, training date, evaluation metrics.
- **FR-04.6** The system SHALL report actual training metrics; fabricated accuracy figures are prohibited.
- **FR-04.7** The system SHALL expose a model health-check endpoint.

### FR-05: Detection Agent
- **FR-05.1** The Detection Agent SHALL receive Suricata alerts and ML predictions as input.
- **FR-05.2** The Detection Agent SHALL apply deterministic rule-based logic combined with ML output to produce a threat assessment.
- **FR-05.3** The Detection Agent SHALL assign an initial risk score (0–100) using the risk engine.
- **FR-05.4** The Detection Agent SHALL identify a possible attack category (port scan, brute-force, DoS, suspicious TCP, suspicious DNS, botnet, malicious traffic, reconnaissance) based on available evidence.
- **FR-05.5** The Detection Agent SHALL NOT claim an attack type unsupported by evidence.
- **FR-05.6** The Detection Agent SHALL produce a structured JSON output as defined in Section 4 of the main spec.
- **FR-05.7** The Detection Agent SHALL persist each detection event to the database.

### FR-06: Attack Analysis Agent
- **FR-06.1** The Attack Analysis Agent SHALL receive confirmed detection events from the Detection Agent.
- **FR-06.2** The Attack Analysis Agent SHALL query the database for related events (same src_ip, dest_ip, timeframe) to build context.
- **FR-06.3** The Attack Analysis Agent SHALL construct an attack-path representation including entry point, intermediate hops, and target.
- **FR-06.4** The Attack Analysis Agent SHALL use Ollama (local LLM, e.g. Llama 3.2) to generate a structured natural-language explanation.
- **FR-06.5** The Attack Analysis Agent SHALL clearly distinguish observed evidence from inferred hypotheses.
- **FR-06.6** The Attack Analysis Agent SHALL NOT invent CVEs, vulnerabilities, or claim host compromise solely from an alert.
- **FR-06.7** The Attack Analysis Agent SHALL output a confidence score supported by evidence count.
- **FR-06.8** The Attack Analysis Agent SHALL fall back to deterministic analysis when Ollama is unavailable.
- **FR-06.9** Investigation results SHALL be persisted to the database.

### FR-07: Defence Agent
- **FR-07.1** The Defence Agent SHALL receive investigation results from the Attack Analysis Agent.
- **FR-07.2** The Defence Agent SHALL generate a prioritized list of recommended defensive actions.
- **FR-07.3** The Defence Agent SHALL operate in recommendation-only mode by default.
- **FR-07.4** The Defence Agent SHALL mark all actions as requiring administrator approval.
- **FR-07.5** The Defence Agent SHALL NOT automatically execute firewall commands or modify network configurations.
- **FR-07.6** Recommended actions SHALL include: IP blocking suggestion, service restriction, account review, firewall review, endpoint isolation suggestion, DNS review.
- **FR-07.7** Recommendations SHALL be persisted to the database with status tracking.

### FR-08: Risk Assessment Engine
- **FR-08.1** The risk engine SHALL produce a deterministic score (0–100) from: Suricata severity, ML confidence, attack indicators, related-event count, target asset information, repeated suspicious activity.
- **FR-08.2** Risk thresholds SHALL be configurable: CRITICAL 90–100, HIGH 70–89, MEDIUM 40–69, LOW 1–39, NORMAL 0.
- **FR-08.3** The risk engine SHALL document the scoring rationale for each event.
- **FR-08.4** An LLM SHALL NOT determine the final numerical risk score.

### FR-09: REST API
- **FR-09.1** The backend SHALL expose a FastAPI REST API with documented endpoints.
- **FR-09.2** Required endpoint groups: dashboard stats, security events (list/detail), attack analysis, agent status, network flows, threat history, risk scores, defence recommendations, PCAP upload, sensor health, model health, Ollama health, report generation.
- **FR-09.3** All endpoints SHALL validate input with Pydantic schemas.
- **FR-09.4** Endpoints SHALL return appropriate HTTP status codes and structured error responses.
- **FR-09.5** PCAP uploads SHALL enforce file-size limits (configurable, default 50 MB) and validate file type.
- **FR-09.6** Large PCAP processing SHALL be executed asynchronously (background task).

### FR-10: WebSocket Real-Time Updates
- **FR-10.1** The backend SHALL expose a WebSocket endpoint at `/ws/events`.
- **FR-10.2** New security events SHALL be broadcast to all connected clients within 2 seconds of detection.
- **FR-10.3** Dashboard statistics SHALL be pushed on change.
- **FR-10.4** Agent status updates SHALL be broadcast.
- **FR-10.5** Clients SHALL receive a full status snapshot on connection.

### FR-11: React SOC Dashboard
- **FR-11.1** The frontend SHALL have 8 pages: Overview, Live Network Monitoring, Threat Detection, Attack Path Analysis, AI Agent Activity, Security Event Details, Reports, Settings & System Health.
- **FR-11.2** The frontend SHALL connect to the backend WebSocket and update in real time.
- **FR-11.3** The Attack Path page SHALL use React Flow to render attack-path graphs.
- **FR-11.4** The dashboard SHALL clearly indicate when components are unavailable.
- **FR-11.5** All metrics displayed SHALL originate from backend API data, not hardcoded values.
- **FR-11.6** The Reports page SHALL allow PDF/CSV export of security summaries.
- **FR-11.7** The UI SHALL use a dark cybersecurity theme (dark navy / charcoal with restrained accent colors).

### FR-12: Database
- **FR-12.1** The system SHALL use SQLite for initial deployment.
- **FR-12.2** Required tables: security_events, network_flows, ml_predictions, agent_investigations, attack_paths, risk_assessments, defence_recommendations, system_health, audit_logs.
- **FR-12.3** All tables SHALL include created_at and updated_at timestamps.
- **FR-12.4** The database SHALL support pagination, filtering, and indexed searches.
- **FR-12.5** The database layer SHALL be abstracted with SQLAlchemy ORM.

---

## 5. Non-Functional Requirements

### NFR-01: Performance
- **NFR-01.1** API response time for dashboard statistics SHALL be ≤ 500 ms under normal load.
- **NFR-01.2** Flow feature extraction SHALL process a 60-second PCAP capture in ≤ 30 seconds.
- **NFR-01.3** WebSocket event broadcast latency SHALL be ≤ 2 seconds from event creation.
- **NFR-01.4** The ML inference step SHALL complete in ≤ 100 ms per flow record.

### NFR-02: Reliability
- **NFR-02.1** Failed flow records SHALL be logged and skipped, not crash the pipeline.
- **NFR-02.2** Suricata log rotation SHALL not cause event loss.
- **NFR-02.3** Ollama unavailability SHALL not prevent the Detection or Defence agents from operating.
- **NFR-02.4** Database write failures SHALL be retried with exponential back-off (max 3 attempts).

### NFR-03: Security
- **NFR-03.1** No credentials or API keys SHALL be hardcoded.
- **NFR-03.2** All configurable secrets SHALL be loaded from environment variables or a `.env` file.
- **NFR-03.3** PCAP file uploads SHALL be validated for type and size before processing.
- **NFR-03.4** The system SHALL implement audit logging for all administrative operations.
- **NFR-03.5** The Defence Agent SHALL require explicit administrator confirmation before any network change.

### NFR-04: Maintainability
- **NFR-04.1** All Python code SHALL use type hints.
- **NFR-04.2** All modules SHALL include structured logging (Python `logging` with log levels).
- **NFR-04.3** Configuration SHALL be managed through a centralized `core/config.py` using Pydantic Settings.
- **NFR-04.4** The 77-feature schema SHALL be defined in one place and imported everywhere needed.

### NFR-05: Testability
- **NFR-05.1** Each major component SHALL have automated unit tests.
- **NFR-05.2** An end-to-end integration test SHALL exercise the full pipeline from PCAP input to dashboard update.
- **NFR-05.3** Tests SHALL use synthetic PCAP files and not depend on live network access.
- **NFR-05.4** Test coverage SHALL be reported.

### NFR-06: Portability
- **NFR-06.1** The backend SHALL run on WSL2 Ubuntu with Python 3.10+.
- **NFR-06.2** The frontend SHALL run on any modern browser (Chrome, Firefox, Edge).
- **NFR-06.3** All Python dependencies SHALL be pinned in `requirements.txt`.
- **NFR-06.4** All Node.js dependencies SHALL be pinned in `package.json`.

---

## 6. Constraints

| Constraint | Description |
|-----------|-------------|
| Platform | Windows 11 + WSL2 Ubuntu for backend; Windows browser for frontend |
| Network access | Monitoring only authorized interfaces; WSL2 cannot see all Windows host traffic |
| LLM | Must use Ollama with a locally installed model (e.g. Llama 3.2) |
| Defensive actions | Recommendation-only; no auto-execution without admin approval |
| Dataset | CICIDS2017 for ML training |
| Model type | Random Forest binary classifier (BENIGN/ATTACK) |

---

## 7. Assumptions

1. Suricata is installed and running in WSL2 Ubuntu.
2. Ollama is installed and a model (e.g. `llama3.2`) is pulled.
3. The developer has root/sudo access in WSL2 for packet capture.
4. Network interfaces for monitoring are identified and authorized by the user.
5. The CICIDS2017 dataset CSV files are available for model training.
6. Npcap or an equivalent is installed on the Windows host if Windows-level capture is desired.

---

## 8. Glossary

| Term | Definition |
|------|-----------|
| EVE JSON | Suricata's extensible event format output |
| CICFlowMeter | Canadian Institute for Cybersecurity network flow analyzer |
| CICIDS2017 | CIC Intrusion Detection System dataset 2017 |
| SOC | Security Operations Center |
| IDS | Intrusion Detection System |
| PCAP | Packet Capture file format |
| IAT | Inter-Arrival Time between packets |
| LLM | Large Language Model |
| Ollama | Local LLM runtime |
| WSL2 | Windows Subsystem for Linux version 2 |
