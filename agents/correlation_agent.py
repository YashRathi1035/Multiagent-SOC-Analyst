"""Correlation Agent (Agent 4) — LangGraph node.

Responsibilities:
- Receive log findings, threat intel results, and retrieved knowledge.
- Build a chronological forensic timeline linking events, IPs, users.
- Propose candidate MITRE ATT&CK technique mappings based on evidence.
- Cross-correlate internal observations with external reputation scores.
- Produce a structured correlation summary consumed by the Report Agent.
"""

import logging
from typing import Any, Dict, List, Optional

from models.schemas import (
    DetectionAlert,
    EventOutcome,
    LogEvent,
    MitreTechniqueMapping,
    ThreatIntelResult,
)
from graph.state import SOCState

logger = logging.getLogger(__name__)

NODE_NAME = "correlation_agent"

# MITRE ATT&CK technique signal map — maps observable evidence keywords to techniques
TECHNIQUE_SIGNALS: List[Dict[str, Any]] = [
    {
        "technique_id": "T1110.001",
        "technique_name": "Brute Force: Password Guessing",
        "keywords": ["brute", "failed login", "repeated fail", "password guess", "RULE-AUTH-001"],
        "min_failures": 5,
    },
    {
        "technique_id": "T1110.003",
        "technique_name": "Brute Force: Password Spraying",
        "keywords": ["spraying", "user enumeration", "multiple accounts", "RULE-AUTH-003"],
        "distinct_users": 3,
    },
    {
        "technique_id": "T1078",
        "technique_name": "Valid Accounts",
        "keywords": ["successful login", "credential compromise", "RULE-AUTH-002", "succeeded"],
        "requires_success": True,
    },
    {
        "technique_id": "T1021.004",
        "technique_name": "Remote Services: SSH",
        "keywords": ["ssh", "openssh", "port 22", "sshd"],
        "always_check": True,
    },
    {
        "technique_id": "T1087.001",
        "technique_name": "Account Discovery: Local Accounts",
        "keywords": ["invalid user", "unknown user", "no such user", "RULE-AUTH-003"],
    },
]


class CorrelationAgent:
    """Specialist agent for evidence correlation, timeline construction, and MITRE mapping."""

    def correlate(
        self,
        alert: DetectionAlert,
        events: List[LogEvent],
        log_findings: Dict[str, Any],
        threat_intel_results: List[ThreatIntelResult],
        retrieved_knowledge: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Build forensic timeline and propose MITRE ATT&CK technique mappings.

        Returns:
            Dict with 'timeline', 'candidate_mitre_mappings', 'correlation_summary'
        """
        # ── Build Chronological Timeline ──────────────────────────────────
        timeline: List[Dict[str, Any]] = self._build_timeline(alert, events, threat_intel_results)

        # ── MITRE ATT&CK Mapping ──────────────────────────────────────────
        mitre_mappings = self._map_mitre_techniques(alert, log_findings)

        # Supplement with knowledge-grounded technique IDs from RAG
        known_mitre_ids = {m.technique_id for m in mitre_mappings}
        for chunk in retrieved_knowledge:
            tech_id = chunk.get("technique_id")
            title = chunk.get("title", "")
            if tech_id and tech_id not in known_mitre_ids:
                mitre_mappings.append(
                    MitreTechniqueMapping(
                        technique_id=tech_id,
                        technique_name=title.replace(f"{tech_id}: ", "")[:80],
                        evidence=f"Retrieved from RAG knowledge base (similarity: {chunk.get('similarity_score', 0):.2f})",
                    )
                )
                known_mitre_ids.add(tech_id)

        # ── Threat Intel Cross-Correlation ────────────────────────────────
        malicious_ips = [r.indicator for r in threat_intel_results if r.is_malicious]
        suspicious_ips = [r.indicator for r in threat_intel_results if not r.is_malicious and r.reputation_score >= 20.0]

        # ── Correlation Narrative ─────────────────────────────────────────
        patterns = log_findings.get("behavioral_patterns", [])
        total_events = log_findings.get("total_events_analyzed", len(events))
        total_failures = log_findings.get("total_failures", 0)
        total_successes = log_findings.get("total_successes", 0)

        corr_lines = [
            f"Correlation Agent synthesized {total_events} events for alert {alert.alert_id}.",
            f"Identified {len(mitre_mappings)} MITRE ATT&CK technique candidates.",
            f"Timeline contains {len(timeline)} entries.",
        ]
        if malicious_ips:
            corr_lines.append(
                f"CONFIRMED MALICIOUS IPs from external threat intelligence: {', '.join(malicious_ips)}."
            )
        if suspicious_ips:
            corr_lines.append(
                f"SUSPICIOUS IPs flagged with moderate reputation scores: {', '.join(suspicious_ips)}."
            )
        if total_successes > 0 and total_failures >= 2:
            corr_lines.append(
                f"CREDENTIAL COMPROMISE SIGNAL: {total_failures} failures followed by {total_successes} success(es)."
            )
        if patterns:
            corr_lines.append(f"Behavioral patterns confirmed: {'; '.join(patterns[:3])}.")

        correlation_summary = " ".join(corr_lines)

        return {
            "timeline": timeline,
            "candidate_mitre_mappings": mitre_mappings,
            "correlation_summary": correlation_summary,
        }

    def _build_timeline(
        self,
        alert: DetectionAlert,
        events: List[LogEvent],
        threat_intel_results: List[ThreatIntelResult],
    ) -> List[Dict[str, Any]]:
        """Build a chronological forensic timeline enriched with reputation flags."""
        ti_lookup: Dict[str, ThreatIntelResult] = {r.indicator: r for r in threat_intel_results}
        triggering_ids = set(alert.triggering_event_ids)

        sorted_events = sorted(events, key=lambda e: e.timestamp)
        # Filter to relevant events
        related = [e for e in sorted_events if e.event_id in triggering_ids or e.source_ip == alert.source_ip]

        timeline = []
        for e in related[:50]:  # cap at 50 for display
            ti_info = ti_lookup.get(e.source_ip or "", None)
            entry: Dict[str, Any] = {
                "timestamp": e.timestamp.isoformat(),
                "event_id": e.event_id,
                "actor_ip": e.source_ip or "N/A",
                "username": e.username or "N/A",
                "action": e.event_type,
                "outcome": e.outcome.value,
                "is_triggering": e.event_id in triggering_ids,
                "message_snippet": e.message[:100],
            }
            if ti_info:
                entry["threat_intel"] = {
                    "reputation_score": ti_info.reputation_score,
                    "is_malicious": ti_info.is_malicious,
                    "category": ti_info.threat_category or "N/A",
                    "provider": ti_info.provider,
                }
            timeline.append(entry)

        return timeline

    def _map_mitre_techniques(
        self,
        alert: DetectionAlert,
        log_findings: Dict[str, Any],
    ) -> List[MitreTechniqueMapping]:
        """Map observed evidence patterns to MITRE ATT&CK techniques."""
        mappings: List[MitreTechniqueMapping] = []
        seen_ids: set = set()

        # Build evidence text corpus for signal matching
        evidence_corpus = " ".join([
            alert.rule_id,
            alert.rule_name,
            alert.description,
            alert.severity_rationale,
            " ".join(alert.mitre_candidates),
            " ".join(log_findings.get("behavioral_patterns", [])),
        ]).lower()

        burst = log_findings.get("burst_analysis_by_ip", {})
        total_failures = log_findings.get("total_failures", 0)
        total_successes = log_findings.get("total_successes", 0)
        distinct_users = max(
            (len(b.get("targeted_users", [])) for b in burst.values()),
            default=0,
        )

        for signal in TECHNIQUE_SIGNALS:
            tid = signal["technique_id"]
            if tid in seen_ids:
                continue

            # Always-check techniques (e.g. SSH)
            always = signal.get("always_check", False)

            # Keyword match
            keyword_match = any(kw.lower() in evidence_corpus for kw in signal["keywords"])

            # Quantitative thresholds
            failure_threshold = signal.get("min_failures", 0)
            user_threshold = signal.get("distinct_users", 0)
            requires_success = signal.get("requires_success", False)

            matched = (
                always
                or keyword_match
                or (total_failures >= failure_threshold and failure_threshold > 0)
                or (distinct_users >= user_threshold and user_threshold > 0)
                or (requires_success and total_successes > 0)
            )

            if matched:
                # Build a specific evidence string
                if tid == "T1110.001":
                    evidence = f"{total_failures} authentication failures detected for {alert.source_ip or 'source IP'}."
                elif tid == "T1110.003":
                    evidence = f"{distinct_users} distinct usernames targeted from {alert.source_ip or 'source IP'}."
                elif tid == "T1078":
                    evidence = f"Authentication succeeded after {total_failures} failures — potential credential compromise."
                elif tid == "T1021.004":
                    evidence = "Events sourced from SSH daemon (sshd) log stream."
                elif tid == "T1087.001":
                    evidence = "Invalid / unknown usernames observed in failure log entries."
                else:
                    evidence = f"Keyword signals matched in alert evidence: {', '.join(signal['keywords'][:3])}."

                mappings.append(
                    MitreTechniqueMapping(
                        technique_id=tid,
                        technique_name=signal["technique_name"],
                        evidence=evidence,
                    )
                )
                seen_ids.add(tid)

        return mappings


def correlation_agent_node(state: SOCState) -> SOCState:
    """LangGraph node: Correlation Agent.

    Reads: selected_alert, normalized_events, log_analysis_findings,
           threat_intel_results, retrieved_knowledge
    Writes: timeline, candidate_mitre_mappings, correlation_summary, agent_trace
    """
    trace = list(state.get("agent_trace", []))
    errors = list(state.get("errors", []))
    trace.append(f"[{NODE_NAME}] started")

    selected_alert: Optional[DetectionAlert] = state.get("selected_alert")
    events: List[LogEvent] = state.get("normalized_events", [])
    log_findings: Dict[str, Any] = state.get("log_analysis_findings", {})
    ti_results: List[ThreatIntelResult] = state.get("threat_intel_results", [])
    knowledge: List[Dict[str, Any]] = state.get("retrieved_knowledge", [])

    if not selected_alert:
        msg = f"[{NODE_NAME}] No selected_alert — skipping correlation."
        logger.warning(msg)
        errors.append(msg)
        trace.append(f"[{NODE_NAME}] skipped (no alert)")
        return {
            **state,
            "timeline": [],
            "candidate_mitre_mappings": [],
            "correlation_summary": "No alert selected; correlation skipped.",
            "agent_trace": trace,
            "errors": errors,
            "current_node": NODE_NAME,
        }

    try:
        agent = CorrelationAgent()
        result = agent.correlate(
            alert=selected_alert,
            events=events,
            log_findings=log_findings,
            threat_intel_results=ti_results,
            retrieved_knowledge=knowledge,
        )
        trace.append(
            f"[{NODE_NAME}] completed — {len(result['candidate_mitre_mappings'])} MITRE techniques, "
            f"{len(result['timeline'])} timeline entries"
        )
        logger.info("[%s] %s", NODE_NAME, result["correlation_summary"][:150])
        return {
            **state,
            "timeline": result["timeline"],
            "candidate_mitre_mappings": result["candidate_mitre_mappings"],
            "correlation_summary": result["correlation_summary"],
            "agent_trace": trace,
            "errors": errors,
            "current_node": NODE_NAME,
        }
    except Exception as exc:
        msg = f"[{NODE_NAME}] Correlation failed: {exc}"
        logger.exception(msg)
        errors.append(msg)
        trace.append(f"[{NODE_NAME}] FAILED")
        return {
            **state,
            "timeline": [],
            "candidate_mitre_mappings": [],
            "correlation_summary": f"Correlation failed: {exc}",
            "agent_trace": trace,
            "errors": errors,
            "current_node": NODE_NAME,
        }
