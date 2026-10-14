"""LangGraph multi-agent SOC investigation workflow.

Defines and compiles the StateGraph that orchestrates the full investigation pipeline:

    START
      |
  [orchestrator]          Selects highest-priority alert, initializes case
      |
      +--(no alert)--> END
      |
      +--(alert found)-->
      |
  [log_agent]             Analyzes auth logs, extracts IOCs & behavioral patterns
      |
  [threat_intel_node]     Enriches IOCs with external reputation lookups
      |
  [knowledge_agent]       Retrieves MITRE ATT&CK + IR playbook context via RAG
      |
  [correlation_agent]     Correlates all findings, maps MITRE techniques, builds timeline
      |
  [report_agent]          Synthesizes final InvestigationReport via LLM
      |
     END

Error handling:
- Each node catches exceptions internally and appends to state['errors'].
- The graph has a recursion_limit to prevent infinite loops.
- A fallback MockLLMClient is used if Ollama fails during report generation.
"""

import logging
from typing import Any, Dict, List, Optional

from langgraph.graph import END, START, StateGraph

from agents.orchestrator import orchestrator_node, route_after_orchestrator
from agents.log_agent import log_agent_node
from agents.threat_intel_node import threat_intel_node
from agents.knowledge_agent import knowledge_agent_node
from agents.correlation_agent import correlation_agent_node
from agents.report_agent import report_agent_node
from graph.state import SOCState
from models.schemas import DetectionAlert, InvestigationReport, LogEvent

logger = logging.getLogger(__name__)

# Maximum number of graph steps to prevent infinite loops
GRAPH_RECURSION_LIMIT = 25


def build_soc_workflow() -> StateGraph:
    """Build and compile the multi-agent SOC investigation StateGraph.

    Returns:
        Compiled LangGraph StateGraph ready for invocation.
    """
    graph = StateGraph(SOCState)

    # Register nodes
    graph.add_node("orchestrator", orchestrator_node)
    graph.add_node("log_agent", log_agent_node)
    graph.add_node("threat_intel_node", threat_intel_node)
    graph.add_node("knowledge_agent", knowledge_agent_node)
    graph.add_node("correlation_agent", correlation_agent_node)
    graph.add_node("report_agent", report_agent_node)

    # START -> Orchestrator
    graph.add_edge(START, "orchestrator")

    # Orchestrator -> conditional routing
    graph.add_conditional_edges(
        "orchestrator",
        route_after_orchestrator,
        {
            "log_agent": "log_agent",
            "end": END,
        },
    )

    # Sequential pipeline after orchestrator selects an alert
    graph.add_edge("log_agent", "threat_intel_node")
    graph.add_edge("threat_intel_node", "knowledge_agent")
    graph.add_edge("knowledge_agent", "correlation_agent")
    graph.add_edge("correlation_agent", "report_agent")
    graph.add_edge("report_agent", END)

    compiled = graph.compile()
    logger.info("SOC multi-agent workflow compiled successfully.")
    return compiled


# Module-level compiled workflow singleton (lazy-initialized)
_workflow_instance = None


def get_workflow():
    """Lazy singleton accessor for the compiled LangGraph workflow."""
    global _workflow_instance
    if _workflow_instance is None:
        _workflow_instance = build_soc_workflow()
    return _workflow_instance


def run_investigation(
    normalized_events: List[LogEvent],
    alerts: List[DetectionAlert],
    raw_filename: Optional[str] = None,
    case_id: Optional[str] = None,
) -> SOCState:
    """High-level convenience function to run the full multi-agent investigation.

    Args:
        normalized_events: List of normalized log events from ingestion.
        alerts: Detection alerts from the rule-based engine.
        raw_filename: Optional original filename for audit trail.
        case_id: Optional pre-assigned case ID (auto-generated if omitted).

    Returns:
        Final SOCState after all agent nodes have executed.
    """
    workflow = get_workflow()

    initial_state: SOCState = {
        "normalized_events": normalized_events,
        "alerts": alerts,
        "raw_filename": raw_filename,
        "errors": [],
        "agent_trace": [],
    }
    if case_id:
        initial_state["case_id"] = case_id

    logger.info(
        "Starting SOC investigation | Events: %d | Alerts: %d",
        len(normalized_events),
        len(alerts),
    )

    try:
        final_state: SOCState = workflow.invoke(
            initial_state,
            config={"recursion_limit": GRAPH_RECURSION_LIMIT},
        )
        logger.info(
            "Investigation complete | Case: %s | Report: %s | Errors: %d",
            final_state.get("case_id"),
            "generated" if final_state.get("final_report") else "FAILED",
            len(final_state.get("errors", [])),
        )

        # Auto-persist to SQLite case management store
        if final_state.get("final_report") and final_state.get("case_id"):
            try:
                from storage.database import get_db
                get_db().save_case(
                    case_id=final_state["case_id"],
                    report=final_state["final_report"],
                    raw_filename=raw_filename,
                    state=final_state,
                )
            except Exception as save_err:
                logger.warning("Failed to auto-save case %s: %s", final_state.get("case_id"), save_err)

        return final_state
    except Exception as exc:
        logger.exception("Workflow execution failed: %s", exc)
        # Return a partial state with the error
        return {
            **initial_state,
            "errors": [f"Workflow fatal error: {exc}"],
            "agent_trace": ["Workflow execution failed"],
            "final_report": None,
        }


def stream_investigation(
    normalized_events: List[LogEvent],
    alerts: List[DetectionAlert],
    raw_filename: Optional[str] = None,
):
    """Stream the multi-agent investigation step by step.

    Yields one (node_name, partial_state) tuple per completed agent node.
    Useful for displaying live agent progress in the dashboard.

    Args:
        normalized_events: Normalized log events.
        alerts: Detection alerts.
        raw_filename: Optional source filename.

    Yields:
        Tuple of (str, SOCState) — node name and partial state snapshot.
    """
    workflow = get_workflow()

    initial_state: SOCState = {
        "normalized_events": normalized_events,
        "alerts": alerts,
        "raw_filename": raw_filename,
        "errors": [],
        "agent_trace": [],
    }

    logger.info(
        "Streaming SOC investigation | Events: %d | Alerts: %d",
        len(normalized_events),
        len(alerts),
    )

    try:
        for step_output in workflow.stream(
            initial_state,
            config={"recursion_limit": GRAPH_RECURSION_LIMIT},
        ):
            # step_output is a dict: {node_name: partial_state_dict}
            for node_name, partial_state in step_output.items():
                logger.debug("Streamed node: %s", node_name)
                yield node_name, partial_state
    except Exception as exc:
        logger.exception("Workflow streaming failed: %s", exc)
        yield "error", {"errors": [str(exc)], "agent_trace": [f"Stream failed: {exc}"]}
