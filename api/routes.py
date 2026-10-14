"""FastAPI REST API application for the Multi-Agent SOC Analyst (Phase 7).

Provides programmatic endpoints for:
1. Health and status check
2. Log ingestion and multi-agent investigation execution
3. Persistent incident case retrieval and status management
4. Indicator threat intelligence lookup
5. RAG knowledge search across MITRE ATT&CK and NIST IR playbooks
"""

from datetime import datetime
import logging
from typing import Any, Dict, List, Optional
from fastapi import FastAPI, HTTPException, Query, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from agents.llm_client import get_llm_client
from config.settings import settings
from detection.rules import DetectionEngine
from graph.workflow import run_investigation
from ingestion.normalize import normalize_events
from ingestion.parsers import parse_csv_log, parse_json_log, parse_openssh_log, validate_file_size
from models.schemas import InvestigationReport, ReviewStatus, SeverityLevel, ThreatIntelResult
from rag.retrieve import RAGRetriever
from storage.database import get_db
from tools.reputation import ThreatIntelService

logger = logging.getLogger("api")

app = FastAPI(
    title="AI-Powered Multi-Agent SOC Analyst API",
    version="1.0.0",
    description=(
        "Production REST API for autonomous security log investigation, "
        "deterministic detection, MITRE ATT&CK RAG, and incident case persistence."
    ),
)

# Enable CORS for cross-origin dashboard integrations
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Request & Response Schemas
# ---------------------------------------------------------------------------

class IngestionRequest(BaseModel):
    """Payload for submitting raw security logs for multi-agent investigation."""
    log_content: str = Field(..., description="Raw text content of security logs")
    log_format: str = Field(
        default="auth_openssh",
        description="Log format: 'auth_openssh', 'auth_csv', or 'auth_json'",
    )
    raw_filename: Optional[str] = Field(None, description="Original source filename")
    enable_ml: bool = Field(default=True, description="Enable ML anomaly detection alongside rules")


class InvestigationResponse(BaseModel):
    """Response returned upon completing an investigation."""
    case_id: str
    status: str
    report: Optional[InvestigationReport] = None
    alerts_detected: int = 0
    events_normalized: int = 0
    agent_trace: List[str] = Field(default_factory=list)
    errors: List[str] = Field(default_factory=list)


class StatusUpdateRequest(BaseModel):
    """Payload to transition review status of an existing case."""
    status: ReviewStatus = Field(..., description="New analyst review status")
    notes: Optional[str] = Field(None, description="Forensic notes from the analyst")


class IndicatorLookupRequest(BaseModel):
    """Payload for threat intelligence indicator lookup."""
    indicator: str = Field(..., description="IP address or indicator to enrich")


class KnowledgeSearchRequest(BaseModel):
    """Payload for querying MITRE ATT&CK / NIST RAG knowledge base."""
    query: str = Field(..., description="Cybersecurity query or observed pattern")
    top_k: int = Field(default=3, ge=1, le=10, description="Number of excerpts to return")


class HealthResponse(BaseModel):
    """System health and operational telemetry."""
    status: str
    timestamp: str
    environment: str
    llm_runtime: str
    ollama_online: bool
    database_cases: int
    version: str = "1.0.0"


# ---------------------------------------------------------------------------
# API Endpoints
# ---------------------------------------------------------------------------

@app.get("/", tags=["Health"])
@app.get("/api/v1/health", response_model=HealthResponse, tags=["Health"])
def health_check() -> HealthResponse:
    """Return system health, LLM connectivity, and database metrics."""
    llm = get_llm_client()
    db = get_db()
    avail = llm.is_available()
    is_online = avail[0] if isinstance(avail, tuple) else bool(avail)

    return HealthResponse(
        status="healthy",
        timestamp=datetime.utcnow().isoformat(),
        environment=settings.ENVIRONMENT,
        llm_runtime=type(llm).__name__,
        ollama_online=is_online,
        database_cases=db.get_case_count(),
    )


@app.post(
    "/api/v1/investigate",
    response_model=InvestigationResponse,
    status_code=status.HTTP_200_OK,
    tags=["Investigation"],
)
def investigate_logs(req: IngestionRequest) -> InvestigationResponse:
    """Ingest raw logs, run deterministic & ML detection, and execute LangGraph swarm."""
    if not req.log_content.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="log_content cannot be empty",
        )

    # 1. Parse logs
    fname = req.raw_filename or f"api_upload_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"
    fmt = req.log_format.lower()
    try:
        if fmt == "auth_csv":
            records, warns = parse_csv_log(req.log_content, source_file=fname)
        elif fmt == "auth_json":
            records, warns = parse_json_log(req.log_content, source_file=fname)
        else:
            records, warns = parse_openssh_log(req.log_content, source_file=fname)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Parsing error: {e}",
        )

    # 2. Normalize
    normalized_events, norm_warns = normalize_events(records)
    if not normalized_events:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="No valid events could be normalized from the provided log content.",
        )

    # 3. Detect alerts (Deterministic + ML)
    engine = DetectionEngine()
    alerts = engine.run_all_rules(normalized_events, include_ml=req.enable_ml)

    # 4. Multi-agent investigation
    final_state = run_investigation(
        normalized_events=normalized_events,
        alerts=alerts,
        raw_filename=fname,
    )

    case_id = final_state.get("case_id", "CASE-UNKNOWN")
    final_report = final_state.get("final_report")

    # 5. Persist to SQLite
    if final_report:
        try:
            get_db().save_case(
                case_id=case_id,
                report=final_report,
                raw_filename=fname,
                state=final_state,
            )
        except Exception as save_err:
            logger.warning("Failed to persist case %s: %s", case_id, save_err)

    return InvestigationResponse(
        case_id=case_id,
        status="completed" if final_report else "no_report_generated",
        report=final_report,
        alerts_detected=len(alerts),
        events_normalized=len(normalized_events),
        agent_trace=final_state.get("agent_trace", []),
        errors=final_state.get("errors", []),
    )


@app.get("/api/v1/cases", tags=["Case Management"])
def list_cases(
    limit: int = Query(50, ge=1, le=200),
    severity: Optional[str] = Query(None, description="Filter: CRITICAL, HIGH, MEDIUM, LOW"),
    status: Optional[str] = Query(None, description="Filter: PENDING, APPROVED, ESCALATED, FALSE_POSITIVE"),
) -> Dict[str, Any]:
    """Retrieve historical cases stored in SQLite with optional filtering."""
    db = get_db()
    records = db.list_cases(limit=limit, severity=severity, status=status)
    return {
        "total": len(records),
        "metrics": db.get_metrics(),
        "cases": [r.to_dict() for r in records],
    }


@app.get("/api/v1/cases/{case_id}", tags=["Case Management"])
def get_case(case_id: str) -> Dict[str, Any]:
    """Retrieve full details and serialized report for a specific case."""
    db = get_db()
    record = db.get_case(case_id)
    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case {case_id} not found",
        )

    return {
        "metadata": record.to_dict(),
        "report": record.get_report(),
        "soc_state_summary": record.soc_state_json,
    }


@app.patch("/api/v1/cases/{case_id}/status", tags=["Case Management"])
def update_case_status(case_id: str, req: StatusUpdateRequest) -> Dict[str, Any]:
    """Update human-in-the-loop analyst review status and notes."""
    db = get_db()
    success = db.update_case_status(case_id, status=req.status, notes=req.notes)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case {case_id} not found",
        )

    updated_rec = db.get_case(case_id)
    return {
        "message": f"Case {case_id} status updated to {req.status.value}",
        "case": updated_rec.to_dict() if updated_rec else None,
    }


@app.delete("/api/v1/cases/{case_id}", tags=["Case Management"])
def delete_case(case_id: str) -> Dict[str, Any]:
    """Delete an incident case from the database."""
    db = get_db()
    success = db.delete_case(case_id)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case {case_id} not found",
        )
    return {"message": f"Case {case_id} deleted successfully"}


@app.post("/api/v1/indicators/lookup", response_model=ThreatIntelResult, tags=["Threat Intelligence"])
def lookup_indicator(req: IndicatorLookupRequest) -> ThreatIntelResult:
    """Enrich an IP indicator using threat intelligence feeds (with RFC 1918 guard)."""
    service = ThreatIntelService()
    return service.enrich_ip(req.indicator.strip())


@app.post("/api/v1/knowledge/search", tags=["RAG Knowledge"])
def search_knowledge(req: KnowledgeSearchRequest) -> Dict[str, Any]:
    """Query the FAISS vector database for relevant MITRE ATT&CK techniques & playbooks."""
    retriever = RAGRetriever()
    results = retriever.retrieve(req.query, top_k=req.top_k)
    return {
        "query": req.query,
        "count": len(results),
        "results": [
            {
                "id": r.chunk_id,
                "title": r.title,
                "score": round(r.similarity_score, 3),
                "tactics": r.tactics,
                "url": r.url,
                "text_snippet": r.text[:300] + "..." if len(r.text) > 300 else r.text,
            }
            for r in results
        ],
    }
