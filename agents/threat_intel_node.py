"""Threat Intelligence Agent Node (Agent 3 — LangGraph wrapper).

Wraps the existing ThreatIntelAgent (Phase 3) as a LangGraph node.
Reads extracted_indicators from state, runs reputation lookups,
and stores enriched results + narrative summary back into state.
"""

import logging
from typing import List, Optional

from agents.threat_intel_agent import ThreatIntelAgent
from models.schemas import ThreatIntelResult
from tools.reputation import ThreatIntelService
from graph.state import SOCState

logger = logging.getLogger(__name__)

NODE_NAME = "threat_intel_node"


def threat_intel_node(state: SOCState) -> SOCState:
    """LangGraph node: Threat Intelligence Enrichment Agent.

    Reads: extracted_indicators
    Writes: threat_intel_results, threat_intel_summary, agent_trace
    """
    trace = list(state.get("agent_trace", []))
    errors = list(state.get("errors", []))
    trace.append(f"[{NODE_NAME}] started")

    indicators: List[str] = state.get("extracted_indicators", [])

    # Also pull IPs directly from selected alert if no indicators extracted yet
    selected_alert = state.get("selected_alert")
    if not indicators and selected_alert and selected_alert.source_ip:
        indicators = [selected_alert.source_ip]

    if not indicators:
        msg = f"[{NODE_NAME}] No indicators to enrich — skipping threat intel."
        logger.info(msg)
        trace.append(f"[{NODE_NAME}] skipped (no indicators)")
        return {
            **state,
            "threat_intel_results": [],
            "threat_intel_summary": "No external indicators identified for threat intelligence enrichment.",
            "agent_trace": trace,
            "errors": errors,
            "current_node": NODE_NAME,
        }

    try:
        service = ThreatIntelService()
        agent = ThreatIntelAgent(service=service)
        analysis = agent.analyze_indicators(indicators)

        results: List[ThreatIntelResult] = analysis.get("results", [])
        summary: str = analysis.get("summary", "")
        severity: str = analysis.get("threat_severity", "UNKNOWN")

        trace.append(
            f"[{NODE_NAME}] completed — {len(results)} indicators enriched "
            f"(malicious={analysis.get('malicious_count', 0)}, "
            f"suspicious={analysis.get('suspicious_count', 0)}, "
            f"internal={analysis.get('internal_count', 0)}), "
            f"threat_severity={severity}"
        )
        logger.info("[%s] %s", NODE_NAME, trace[-1])

        return {
            **state,
            "threat_intel_results": results,
            "threat_intel_summary": summary,
            "agent_trace": trace,
            "errors": errors,
            "current_node": NODE_NAME,
        }
    except Exception as exc:
        msg = f"[{NODE_NAME}] Threat intel enrichment failed: {exc}"
        logger.exception(msg)
        errors.append(msg)
        trace.append(f"[{NODE_NAME}] FAILED — proceeding without threat intel")
        return {
            **state,
            "threat_intel_results": [],
            "threat_intel_summary": "Threat intelligence enrichment failed; no reputation data available.",
            "agent_trace": trace,
            "errors": errors,
            "current_node": NODE_NAME,
        }
