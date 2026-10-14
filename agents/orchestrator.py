"""Orchestrator Agent (Agent 0) — LangGraph entrypoint node.

Responsibilities:
- Receive the list of detected alerts and select the highest-priority one.
- Build an investigation plan (priority order, routing context).
- Determine the next node via conditional routing.
- Serve as the graph's START node, setting case_id and initializing meta fields.
"""

import logging
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

from models.schemas import (
    DetectionAlert,
    ReviewStatus,
    SeverityLevel,
)
from graph.state import SOCState

logger = logging.getLogger(__name__)

NODE_NAME = "orchestrator"

# Severity priority order (highest = 0)
SEVERITY_PRIORITY = {
    SeverityLevel.CRITICAL: 0,
    SeverityLevel.HIGH: 1,
    SeverityLevel.MEDIUM: 2,
    SeverityLevel.LOW: 3,
}


class Orchestrator:
    """Determines investigation priority and routing plan from a list of alerts."""

    def plan(
        self,
        alerts: List[DetectionAlert],
        normalized_event_count: int,
    ) -> Dict[str, Any]:
        """Select the highest-priority alert and build an investigation plan.

        Priority ordering:
        1. CRITICAL severity alerts first.
        2. Within same severity: prefer RULE-AUTH-002 (credential compromise) > 001 (brute force) > 003 (enumeration).
        3. Tie-break by number of triggering events (more evidence = higher priority).

        Returns:
            Dict with 'selected_alert', 'investigation_plan', 'case_id'.
        """
        if not alerts:
            return {
                "selected_alert": None,
                "investigation_plan": {
                    "decision": "no_alerts",
                    "reason": "No detection alerts to investigate.",
                    "alert_count": 0,
                },
                "case_id": f"CASE-{uuid.uuid4().hex[:8].upper()}",
            }

        rule_priority = {
            "RULE-AUTH-002": 0,  # Credential compromise (highest risk)
            "RULE-AUTH-001": 1,  # Brute force
            "RULE-AUTH-003": 2,  # User enumeration
            "RULE-ML-002": 3,    # ML Supervised Attack Classification
            "RULE-ML-001": 4,    # ML Unsupervised Anomaly Detection
        }

        def sort_key(a: DetectionAlert):
            sev = SEVERITY_PRIORITY.get(a.severity, 99)
            rule = rule_priority.get(a.rule_id, 99)
            evidence_count = len(a.triggering_event_ids)
            return (sev, rule, -evidence_count)

        sorted_alerts = sorted(alerts, key=sort_key)
        selected = sorted_alerts[0]

        case_id = f"CASE-{uuid.uuid4().hex[:8].upper()}"

        plan = {
            "decision": "investigate",
            "case_id": case_id,
            "selected_alert_id": selected.alert_id,
            "selected_rule": selected.rule_id,
            "selected_severity": selected.severity.value,
            "total_alerts": len(alerts),
            "other_alert_ids": [a.alert_id for a in sorted_alerts[1:]],
            "total_events_in_case": normalized_event_count,
            "investigation_rationale": (
                f"Alert {selected.alert_id} selected as highest-priority investigation target. "
                f"Severity: {selected.severity.value} | Rule: {selected.rule_name} | "
                f"Evidence: {len(selected.triggering_event_ids)} triggering events. "
                f"Total alerts in case: {len(alerts)}."
            ),
        }

        logger.info(
            "[%s] Investigation plan: %s | Alert: %s | Rule: %s | Severity: %s",
            NODE_NAME, plan["decision"], selected.alert_id, selected.rule_id, selected.severity.value,
        )

        return {
            "selected_alert": selected,
            "investigation_plan": plan,
            "case_id": case_id,
        }


def orchestrator_node(state: SOCState) -> SOCState:
    """LangGraph node: Orchestrator — selects highest-priority alert and initializes case.

    Reads: alerts, normalized_events
    Writes: selected_alert, investigation_plan, case_id, created_at,
            errors, agent_trace, review_status, current_node
    """
    alerts: List[DetectionAlert] = state.get("alerts", [])
    events = state.get("normalized_events", [])
    case_id_existing = state.get("case_id")

    orch = Orchestrator()
    result = orch.plan(alerts, len(events))

    case_id = case_id_existing or result["case_id"]
    trace = [f"[{NODE_NAME}] Investigation initialized | Case: {case_id} | Alerts: {len(alerts)}"]

    if result["selected_alert"]:
        trace.append(
            f"[{NODE_NAME}] Selected alert: {result['selected_alert'].alert_id} "
            f"({result['selected_alert'].severity.value})"
        )

    return {
        **state,
        "case_id": case_id,
        "created_at": datetime.utcnow().isoformat(),
        "selected_alert": result["selected_alert"],
        "investigation_plan": result["investigation_plan"],
        "errors": state.get("errors", []),
        "agent_trace": trace,
        "review_status": ReviewStatus.PENDING,
        "current_node": NODE_NAME,
    }


def route_after_orchestrator(state: SOCState) -> str:
    """Conditional edge function: decide next step after Orchestrator.

    Returns 'log_agent' if a valid alert was selected,
    or 'end' if no alerts exist to investigate.
    """
    selected = state.get("selected_alert")
    if selected is None:
        logger.info("[router] No alert selected — routing to END.")
        return "end"
    logger.info("[router] Alert selected — routing to log_agent.")
    return "log_agent"
