"""Shared SOC investigation state for LangGraph multi-agent workflow.

SOCState is the single immutable-style message object that every node
reads from and writes to. LangGraph merges each node's returned dict
with the existing state, so nodes only need to return the keys they mutate.
"""

from typing import Any, Dict, List, Optional
from typing_extensions import TypedDict

from models.schemas import (
    DetectionAlert,
    InvestigationReport,
    LogEvent,
    MitreTechniqueMapping,
    ReviewStatus,
    ThreatIntelResult,
)


class SOCState(TypedDict, total=False):
    """Full investigation state shared across all LangGraph agent nodes.

    Key design principles:
    - Every field is Optional so nodes can be tested in isolation.
    - Lists are appended-to (never overwritten) by intermediate nodes.
    - `final_report` is only set by the ReportAgent at the end.
    - `errors` accumulates non-fatal failures from any node.
    - `agent_trace` records a human-readable audit log of each node's actions.
    """

    # -- Investigation Identity --
    case_id: str
    created_at: str

    # -- Input Data --
    raw_filename: Optional[str]
    normalized_events: List[LogEvent]
    alerts: List[DetectionAlert]

    # -- Orchestrator Selection --
    selected_alert: Optional[DetectionAlert]
    investigation_plan: Dict[str, Any]          # orchestrator routing metadata

    # -- Log Agent Output --
    extracted_indicators: List[str]             # IPs / domains extracted
    log_analysis_findings: Dict[str, Any]       # behavioral timeline, patterns

    # -- Threat Intelligence Agent Output --
    threat_intel_results: List[ThreatIntelResult]
    threat_intel_summary: str

    # -- Knowledge / RAG Agent Output --
    retrieved_knowledge: List[Dict[str, Any]]
    knowledge_context: str

    # -- Correlation Agent Output --
    candidate_mitre_mappings: List[MitreTechniqueMapping]
    timeline: List[Dict[str, Any]]
    correlation_summary: str

    # -- Report Agent Output --
    final_report: Optional[InvestigationReport]
    report_markdown: str
    review_status: ReviewStatus

    # -- Meta --
    errors: List[str]
    agent_trace: List[str]          # ordered log of completed node names
    current_node: str               # name of the node currently executing
