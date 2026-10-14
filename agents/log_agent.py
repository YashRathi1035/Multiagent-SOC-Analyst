"""Log Analysis Agent (Agent 1) — LangGraph node.

Responsibilities:
- Inspect the normalized events correlated with the selected alert.
- Build a precise authentication timeline grouped by source IP.
- Detect behavioral patterns: failure bursts, user-switching, privilege targeting.
- Extract all Indicators of Compromise (IP addresses, usernames).
- Produce structured findings consumed by downstream agents.
"""

import logging
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Set

from models.schemas import DetectionAlert, EventOutcome, LogEvent
from graph.state import SOCState

logger = logging.getLogger(__name__)

NODE_NAME = "log_agent"


class LogAnalysisAgent:
    """Specialist agent for deep authentication log behavioral analysis."""

    def analyze(
        self,
        alert: DetectionAlert,
        events: List[LogEvent],
    ) -> Dict[str, Any]:
        """Run full behavioral analysis on events correlated with the alert.

        Returns a structured findings dict ready to be merged into SOCState.
        """
        # Filter to alert-relevant events (by triggering IDs or source IP)
        triggering_ids: Set[str] = set(alert.triggering_event_ids)
        related = [e for e in events if e.event_id in triggering_ids]
        if not related and alert.source_ip:
            related = [e for e in events if e.source_ip == alert.source_ip][:30]

        sorted_events = sorted(related, key=lambda e: e.timestamp)

        # ── Extract IOCs ──────────────────────────────────────────────────
        indicators: Set[str] = set()
        if alert.source_ip:
            indicators.add(alert.source_ip)
        for e in sorted_events:
            if e.source_ip:
                indicators.add(e.source_ip)

        # ── Build Authentication Timeline ─────────────────────────────────
        timeline: List[Dict[str, Any]] = []
        for e in sorted_events:
            timeline.append({
                "event_id": e.event_id,
                "timestamp": e.timestamp.isoformat(),
                "username": e.username or "N/A",
                "source_ip": e.source_ip or "N/A",
                "event_type": e.event_type,
                "outcome": e.outcome.value,
                "message": e.message[:120],
            })

        # ── Failure Burst Analysis ────────────────────────────────────────
        ip_failures: Dict[str, List[LogEvent]] = defaultdict(list)
        ip_successes: Dict[str, List[LogEvent]] = defaultdict(list)
        for e in sorted_events:
            if e.source_ip:
                if e.outcome == EventOutcome.FAILURE:
                    ip_failures[e.source_ip].append(e)
                elif e.outcome == EventOutcome.SUCCESS:
                    ip_successes[e.source_ip].append(e)

        burst_analysis: Dict[str, Any] = {}
        for ip, fails in ip_failures.items():
            successes = ip_successes.get(ip, [])
            targeted_users = list({e.username for e in fails if e.username})
            has_privileged = any(u.lower() in ("root", "admin", "administrator") for u in targeted_users)
            burst_analysis[ip] = {
                "total_failures": len(fails),
                "total_successes": len(successes),
                "targeted_users": targeted_users[:10],
                "targets_privileged_accounts": has_privileged,
                "earliest_failure": fails[0].timestamp.isoformat() if fails else None,
                "latest_event": (fails[-1].timestamp if fails else datetime.utcnow()).isoformat(),
                "compromise_suspected": len(successes) > 0 and len(fails) >= 2,
            }

        # ── Behavioral Pattern Classification ─────────────────────────────
        patterns: List[str] = []
        for ip, data in burst_analysis.items():
            if data["total_failures"] >= 5:
                patterns.append(f"Brute-force burst from {ip}: {data['total_failures']} failures")
            if data["compromise_suspected"]:
                patterns.append(
                    f"Possible credential compromise: {ip} had {data['total_failures']} failures "
                    f"then {data['total_successes']} success(es)"
                )
            if data["targets_privileged_accounts"]:
                patterns.append(
                    f"Privileged account targeting from {ip}: {data['targeted_users']}"
                )
            if len(data["targeted_users"]) >= 3:
                patterns.append(
                    f"User enumeration / spraying from {ip}: {len(data['targeted_users'])} distinct accounts"
                )

        # ── Narrative Summary ─────────────────────────────────────────────
        total_events = len(sorted_events)
        total_failures = sum(1 for e in sorted_events if e.outcome == EventOutcome.FAILURE)
        total_successes = sum(1 for e in sorted_events if e.outcome == EventOutcome.SUCCESS)

        narrative = (
            f"Log Agent analyzed {total_events} correlated events for alert {alert.alert_id} "
            f"(Rule: {alert.rule_name}). "
            f"Observed {total_failures} failures and {total_successes} successes. "
            f"Detected {len(patterns)} behavioral patterns across {len(ip_failures)} source IPs."
        )

        return {
            "extracted_indicators": sorted(list(indicators)),
            "log_analysis_findings": {
                "alert_id": alert.alert_id,
                "rule_id": alert.rule_id,
                "total_events_analyzed": total_events,
                "total_failures": total_failures,
                "total_successes": total_successes,
                "behavioral_patterns": patterns,
                "burst_analysis_by_ip": burst_analysis,
                "authentication_timeline": timeline,
                "narrative": narrative,
            },
        }


def log_agent_node(state: SOCState) -> SOCState:
    """LangGraph node: Log Analysis Agent.

    Reads: normalized_events, selected_alert
    Writes: extracted_indicators, log_analysis_findings, agent_trace
    """
    trace = list(state.get("agent_trace", []))
    errors = list(state.get("errors", []))
    trace.append(f"[{NODE_NAME}] started")

    selected_alert: Optional[DetectionAlert] = state.get("selected_alert")
    events: List[LogEvent] = state.get("normalized_events", [])

    if not selected_alert:
        msg = f"[{NODE_NAME}] No selected_alert in state — skipping log analysis."
        logger.warning(msg)
        errors.append(msg)
        trace.append(f"[{NODE_NAME}] skipped (no alert)")
        return {**state, "errors": errors, "agent_trace": trace, "current_node": NODE_NAME}

    try:
        agent = LogAnalysisAgent()
        result = agent.analyze(selected_alert, events)
        trace.append(
            f"[{NODE_NAME}] completed — {len(result['extracted_indicators'])} IOCs, "
            f"{len(result['log_analysis_findings']['behavioral_patterns'])} patterns"
        )
        logger.info("[%s] Analysis complete: %s", NODE_NAME, result["log_analysis_findings"]["narrative"])
        return {
            **state,
            "extracted_indicators": result["extracted_indicators"],
            "log_analysis_findings": result["log_analysis_findings"],
            "agent_trace": trace,
            "errors": errors,
            "current_node": NODE_NAME,
        }
    except Exception as exc:
        msg = f"[{NODE_NAME}] Error during analysis: {exc}"
        logger.exception(msg)
        errors.append(msg)
        trace.append(f"[{NODE_NAME}] FAILED")
        return {
            **state,
            "extracted_indicators": list({state.get("selected_alert").source_ip} if state.get("selected_alert") and state.get("selected_alert").source_ip else []),
            "log_analysis_findings": {"error": str(exc)},
            "agent_trace": trace,
            "errors": errors,
            "current_node": NODE_NAME,
        }
