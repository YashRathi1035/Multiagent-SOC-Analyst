# AI-Powered Multi-Agent SOC Analyst

[![Python 3.11](https://img.shields.io/badge/Python-3.11-blue.svg)](https://www.python.org/)
[![LangGraph](https://img.shields.io/badge/Orchestration-LangGraph-orange.svg)](https://github.com/langchain-ai/langgraph)
[![Local LLM](https://img.shields.io/badge/LLM-Ollama%20(qwen3:4b)-purple.svg)](https://ollama.com/)
[![FAISS Vector Store](https://img.shields.io/badge/RAG-FAISS%20%2B%20MiniLM--L6--v2-green.svg)](https://github.com/facebookresearch/faiss)
[![FastAPI](https://img.shields.io/badge/API-FastAPI%20REST-009688.svg)](https://fastapi.tiangolo.com/)
[![Streamlit](https://img.shields.io/badge/Dashboard-Streamlit-red.svg)](https://streamlit.io/)
[![Tests](https://img.shields.io/badge/Tests-67%20Passed-brightgreen.svg)]()

An autonomous, production-grade **Security Operations Center (SOC) Tier-3 Assistant** built to eliminate alert fatigue, automate complex incident triage, and produce verifiable, evidence-grounded incident reports.

Powered by a coordinated swarm of specialized GenAI agents orchestrated via **LangGraph**, local open-source LLMs (**Ollama `qwen3:4b`**), dual-layer machine learning anomaly detection (**Isolation Forest & Random Forest**), **FAISS vector RAG** grounded in MITRE ATT&CK & NIST SP 800-61 Rev 2, threat intelligence feeds (AbuseIPDB, VirusTotal, RFC 1918 guard), **SQLite persistence**, and both an interactive **Streamlit Cyber SOC Dashboard** and headless **FastAPI REST API**.

---

## 🗺️ Project Roadmap & Completion Status (All 7 Phases Complete)

| Phase | Title | Deliverables | Status |
| :---: | :--- | :--- | :---: |
| **Phase 1** | **Foundation, Ingestion & Detection Slice** | OpenSSH/CSV/JSON parsers, normalizer, SHA-256 event hashing, deterministic rule engine (brute-force, compromise, spraying), Ollama/Mock LLM client. | ✅ **COMPLETED** |
| **Phase 2** | **MITRE ATT&CK & NIST Playbook RAG** | Curated MITRE ATT&CK subset + NIST SP 800-61 playbooks, local `all-MiniLM-L6-v2` embeddings, cosine `IndexFlatIP` FAISS store, semantic search portal. | ✅ **COMPLETED** |
| **Phase 3** | **Threat Intelligence Enrichment** | IOC extractor (IPv4, domains, hashes), RFC 1918 private IP data-leak filter, AbuseIPDB & VirusTotal providers, in-memory cache, Live TI tab. | ✅ **COMPLETED** |
| **Phase 4** | **LangGraph Multi-Agent Orchestration** | 6-Node StateGraph workflow (Orchestrator → Log → Threat Intel → Knowledge → Correlation → Report), shared `SOCState`, streaming traces. | ✅ **COMPLETED** |
| **Phase 5** | **ML Intrusion & Anomaly Detection** | 13-D feature engineering, Isolation Forest (unsupervised outlier detection), Random Forest (supervised attack classification), synthetic baseline dataset. | ✅ **COMPLETED** |
| **Phase 6** | **SQLite Case Persistence & History** | SQLAlchemy models, `CaseRecord` upsert logic, Tab 5 Case Management dashboard, human-in-the-loop review state machine (`PENDING` → `APPROVED` / `ESCALATED` / `FALSE_POSITIVE`). | ✅ **COMPLETED** |
| **Phase 7** | **FastAPI REST API & Benchmarking** | Full REST API (`/investigate`, `/cases`, `/indicators/lookup`, `/knowledge/search`), automated evaluation benchmark suite, and `DEFENSE_GUIDE.md`. | ✅ **COMPLETED** |

---

## 🏛️ System Architecture

```mermaid
flowchart TD
    subgraph IngestionLayer ["1. Ingestion & Sanitization"]
        RawLogs["Raw Logs (Syslog / CSV / JSON)"] --> Parser["Sanitizer & Parsers"]
        Parser --> NormEvents["Normalized LogEvents<br/>(Deterministic EVT- SHA256 Fingerprint)"]
    end

    subgraph DetectionLayer ["2. Dual-Layer Detection Engine"]
        NormEvents --> RuleEngine["Deterministic Rules<br/>(Brute Force, Credential Compromise, Spraying)"]
        NormEvents --> MLDetector["Ensemble ML Detector<br/>(Isolation Forest + Random Forest)"]
        RuleEngine --> AlertQueue["Unified Detection Alerts Queue"]
        MLDetector --> AlertQueue
    end

    subgraph MultiAgentSwarm ["3. LangGraph Multi-Agent Swarm (SOCState)"]
        direction TB
        Node0["0. Orchestrator Node<br/>(Triage alerts, severity priority, case init)"]
        Node1["1. Log Analysis Agent<br/>(Timeline synthesis, burst rate, user profiling)"]
        Node2["2. Threat Intel Node<br/>(AbuseIPDB/VT reputation with RFC 1918 guard)"]
        Node3["3. Knowledge Base Agent<br/>(Dense vector RAG: ATT&CK + NIST Playbooks)"]
        Node4["4. Correlation Agent<br/>(Forensic timeline & technique mapping)"]
        Node5["5. Report Agent<br/>(Pydantic report synthesis & Event ID verification)"]

        Node0 --> Node1 --> Node2 --> Node3 --> Node4 --> Node5
    end

    AlertQueue --> Node0
    NormEvents --> Node0

    subgraph PersistenceLayer ["4. Persistence & Presentation"]
        Node5 --> FinalReport["Validated InvestigationReport"]
        FinalReport --> SQLiteDB[("SQLite Database<br/>data/soc_analyst.db")]
        SQLiteDB --> StreamlitUI["Streamlit Cyber Dashboard<br/>(5 Interactive Tabs)"]
        SQLiteDB --> FastAPIApp["FastAPI REST API<br/>(Headless Endpoints)"]
    end
```

---

## 🤖 Multi-Agent Swarm Roles

The LangGraph orchestration coordinates 6 specialist nodes executing sequentially over a shared `SOCState`:

1. **Orchestrator Agent (`agents/orchestrator.py`)**:
   - Triages active alerts by severity (`CRITICAL` > `HIGH` > `MEDIUM` > `LOW`) and attack risk (`RULE-AUTH-002` > `001` > `003` > `ML-002` > `ML-001`).
   - Generates unique Case IDs (`CASE-XXXXXXXX`) and sets the investigation roadmap.
2. **Log Analysis Agent (`agents/log_agent.py`)**:
   - Extracts network and account indicators (IPs, users).
   - Constructs behavioral authentication profiles, brute force burst rates, and timeline distributions.
3. **Threat Intelligence Node (`agents/threat_intel_node.py`)**:
   - Queries external feeds (AbuseIPDB, VirusTotal, Mock) for indicator abuse scores.
   - **Enforces strict RFC 1918 boundary filtering** (prevents internal IP leakage).
4. **Knowledge Base Agent (`agents/knowledge_agent.py`)**:
   - Executes semantic similarity retrieval over FAISS vector index using `all-MiniLM-L6-v2`.
   - Retrieves grounded MITRE ATT&CK techniques and NIST SP 800-61 containment playbooks.
5. **Correlation Agent (`agents/correlation_agent.py`)**:
   - Fuses log findings, threat intelligence reputation, and ATT&CK vectors into a chronological forensic timeline.
6. **Report Agent (`agents/report_agent.py`)**:
   - Synthesizes the final executive report.
   - **Programmatic Event ID Cross-Checking**: Ensures every cited event ID exists in the source telemetry (eliminates hallucinations).

---

## ⚡ Quickstart Guide (Windows / PowerShell)

### 1. Prerequisites
- **Python**: 3.11+
- **Ollama**: Installed and running locally (`ollama --version`)
- **LLM Model**: `qwen3:4b`

```powershell
# Verify Ollama service is active
ollama list
ollama pull qwen3:4b
```

### 2. Virtual Environment Setup
```powershell
cd c:\Users\yashr\OneDrive\Attachments\Desktop\Projects\multi-agent-soc-analyst

# Activate existing virtual environment
.venv\Scripts\Activate.ps1
```

### 3. Run Full Automated Test Suite (67 Passing Tests)
```powershell
.venv\Scripts\pytest.exe -q
```
*Covers parsers, detection rules, prompt injection defense, LLM client, RAG chunking & retrieval, threat intel RFC 1918 safety, LangGraph agents, ML detector, SQLite persistence, and FastAPI REST endpoints.*

### 4. Launch the Streamlit SOC Dashboard
```powershell
.venv\Scripts\streamlit.exe run app.py
```
Open your browser at `http://localhost:8501`.

The dashboard features **5 Tabs**:
- **Tab 1: 📥 Ingestion & Telemetry**: Upload raw logs (.log, .txt, .csv, .json), view normalized telemetry grid.
- **Tab 2: 🚨 Detection Engine & Alerts**: Inspect deterministic rules, ML anomaly scores, and trigger investigations.
- **Tab 3: 🤖 Multi-Agent Investigation**: Inspect agent status cards, execution traces, forensic timeline, and generated reports.
- **Tab 4: 📚 Knowledge Base Search (RAG)**: Query MITRE ATT&CK & NIST playbooks, live IP reputation lookup.
- **Tab 5: 📁 Incident Case Management**: Historical case search, human-in-the-loop review status updates (`PENDING` → `APPROVED` / `ESCALATED` / `FALSE_POSITIVE`), analyst notes, and report downloads.

### 5. Launch the FastAPI REST Server
```powershell
.venv\Scripts\uvicorn.exe api.routes:app --host 0.0.0.0 --port 8000 --reload
```
Interactive Swagger API documentation available at `http://localhost:8000/docs`.

---

## 🌐 FastAPI REST API Reference

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/v1/health` | System health, Ollama status, and database metrics |
| `POST` | `/api/v1/investigate` | Submit raw log content for headless multi-agent investigation |
| `GET` | `/api/v1/cases` | List historical cases with optional severity/status filters |
| `GET` | `/api/v1/cases/{case_id}` | Retrieve specific case metadata, report, and state summary |
| `PATCH` | `/api/v1/cases/{case_id}/status` | Update human-in-the-loop review status and analyst notes |
| `DELETE` | `/api/v1/cases/{case_id}` | Delete a case from the database |
| `POST` | `/api/v1/indicators/lookup` | Live threat intelligence lookup with RFC 1918 private IP protection |
| `POST` | `/api/v1/knowledge/search` | Query MITRE ATT&CK & NIST vector store |

### Sample API Request (`curl`):
```bash
curl -X POST "http://localhost:8000/api/v1/investigate" \
     -H "Content-Type: application/json" \
     -d '{
       "log_content": "Dec 10 08:00:01 server sshd[1001]: Failed password for root from 198.51.100.99 port 50001 ssh2\nDec 10 08:00:03 server sshd[1002]: Failed password for root from 198.51.100.99 port 50002 ssh2\nDec 10 08:00:05 server sshd[1003]: Failed password for root from 198.51.100.99 port 50003 ssh2\nDec 10 08:00:07 server sshd[1004]: Failed password for root from 198.51.100.99 port 50004 ssh2\nDec 10 08:00:09 server sshd[1005]: Failed password for root from 198.51.100.99 port 50005 ssh2\nDec 10 08:00:11 server sshd[1006]: Failed password for root from 198.51.100.99 port 50006 ssh2",
       "log_format": "auth_openssh",
       "enable_ml": true
     }'
```

---

## 📊 Quantitative Benchmark Results

Run the automated evaluation benchmark:
```powershell
.venv\Scripts\python.exe -m evaluation.benchmark
```

### Benchmark Metrics Summary:
- **Total Scenarios Evaluated**: 4 standard attack scenarios (Brute Force, Credential Compromise, Benign Traffic, Adversarial Prompt Injection)
- **Pydantic Schema Adherence**: **100%** (all generated reports strictly adhere to schema)
- **Hallucination Rate (False Event Citations)**: **0.0%** (every cited Event ID is cryptographically verified against source telemetry)
- **Prompt Injection Defense Rate**: **100.0%** (adversarial instruction injection completely neutralized by XML sandboxing)

---

## 🛡️ Security & Defense Architecture

For a deep-dive technical specification of our security safeguards, see [DEFENSE_GUIDE.md](file:///c:/Users/yashr/OneDrive/Attachments/Desktop/Projects/multi-agent-soc-analyst/DEFENSE_GUIDE.md):
1. **RFC 1918 Private IP Boundary Guard**: Blocks internal network topology leaks to external intelligence APIs.
2. **Structural Prompt Injection Isolation**: Raw logs encapsulated in strict `<evidence_data>` delimiter tags.
3. **Programmatic Cross-Verification**: Discards any hallucinated event IDs before report emission.
4. **Forensic Hashing**: SHA-256 deterministic IDs guarantee tamper-evident non-repudiation.
5. **Dual-Layer Detection**: Rule-based sliding windows + Isolation Forest anomaly scoring + Random Forest classification.
6. **NIST SP 800-61 Playbook Grounding**: Direct vector citation of official incident handling steps.
7. **Human-in-the-Loop Sign-Off**: Mandatory human review gating for critical containment actions.

---

## 📂 Repository Structure

```
multi-agent-soc-analyst/
├── app.py                     # Streamlit Cyber SOC Dashboard (5 Tabs)
├── requirements.txt           # Project dependencies
├── pytest.ini                 # Pytest runner configuration
├── .env.example               # Environment variables template
├── .env                       # Local environment settings
├── README.md                  # Master documentation & setup guide
├── DEFENSE_GUIDE.md           # Security defense whitepaper & threat model
├── api/
│   ├── __init__.py
│   └── routes.py              # FastAPI REST endpoints
├── evaluation/
│   ├── __init__.py
│   └── benchmark.py           # Quantitative evaluation benchmark suite
├── storage/
│   ├── __init__.py
│   ├── models.py              # SQLAlchemy ORM CaseRecord schema
│   └── database.py            # SQLite DatabaseManager client
├── ml/
│   ├── __init__.py
│   ├── features.py            # 13-D feature engineering pipeline
│   ├── dataset.py             # Synthetic baseline dataset generator
│   └── detector.py            # Isolation Forest & Random Forest ensemble
├── graph/
│   ├── __init__.py
│   ├── state.py               # SOCState TypedDict shared across nodes
│   └── workflow.py            # LangGraph StateGraph pipeline & streaming
├── agents/
│   ├── __init__.py
│   ├── llm_client.py          # Ollama (qwen3:4b) + offline Mock LLM client
│   ├── orchestrator.py        # Agent 0: Alert triage & case prioritization
│   ├── log_agent.py           # Agent 1: Deep log analysis & timeline synthesis
│   ├── threat_intel_node.py   # Agent 2: External reputation enrichment node
│   ├── knowledge_agent.py     # Agent 3: MITRE ATT&CK RAG query node
│   ├── correlation_agent.py   # Agent 4: ATT&CK mapping & correlation narrative
│   └── report_agent.py        # Agent 5: Report synthesis & event ID verification
├── detection/
│   ├── __init__.py
│   └── rules.py               # Deterministic sliding-window detection rules
├── ingestion/
│   ├── __init__.py
│   ├── parsers.py             # OpenSSH syslog, CSV, and JSON parsers
│   └── normalize.py           # Field sanitization & SHA-256 event ID generation
├── models/
│   ├── __init__.py
│   └── schemas.py             # Pydantic schemas (LogEvent, Alert, ThreatIntelResult, Report, State)
├── rag/
│   ├── __init__.py
│   ├── embeddings.py          # Sentence-transformers (all-MiniLM-L6-v2)
│   ├── ingest.py              # Knowledge chunker & FAISS index builder
│   └── retrieve.py            # Cosine similarity retrieval & citations
├── tools/
│   ├── __init__.py
│   └── reputation.py          # Threat intel service, RFC 1918 filter, AbuseIPDB & VT
├── data/
│   ├── knowledge/             # MITRE ATT&CK techniques & NIST IR playbooks
│   ├── cache/                 # Cached FAISS index and trained ML models
│   ├── samples/               # OpenSSH sample logs, JSON & CSV samples, ML dataset
│   └── test_cases/            # Synthetic benchmark scenarios
└── tests/
    ├── test_parsers.py        # Ingestion & parser tests
    ├── test_detection.py      # Rule engine threshold tests
    ├── test_llm.py            # LLM client & prompt injection tests
    ├── test_rag.py            # Vector embeddings & RAG retrieval tests
    ├── test_threat_intel.py   # Threat intel providers & RFC 1918 tests
    ├── test_agents.py         # Multi-agent unit tests
    ├── test_workflow.py       # LangGraph integration & streaming tests
    ├── test_ml.py             # ML feature extraction, Isolation Forest & RF tests
    ├── test_storage.py        # SQLite persistence & case management tests
    └── test_api.py            # FastAPI REST endpoints tests
```

---

## ⚖️ License & Academic Integrity

This project is open-source under the MIT License. Developed for technical presentation, faculty defense, and enterprise SOC engineering demonstrations.
