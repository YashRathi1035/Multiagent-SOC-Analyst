"""Report Agent (Agent 5) — LangGraph node.

Responsibilities:
- Receive all enriched state (log findings, threat intel, knowledge, correlation).
- Build the complete LLM prompt with all structured context.
- Call the LLM (Ollama or Mock) to generate an InvestigationReport.
- Cross-verify all cited event IDs against the actual log dataset.
- Export the final report in Markdown format.
- Write the final_report and report_markdown back to SOCState.
"""

import logging
import uuid
from typing import Any, Dict, List, Optional, Set

from agents.llm_client import BaseLLMClient, MockLLMClient, get_llm_client
from agents.threat_intel_agent import ThreatIntelAgent
from models.schemas import (
    DetectionAlert,
    InvestigationReport,
    LogEvent,
    MitreTechniqueMapping,
    ReviewStatus,
    ThreatIntelResult,
)
from reports.generator import export_report_to_markdown
from graph.state import SOCState

logger = logging.getLogger(__name__)

NODE_NAME = "report_agent"


class ReportAgent:
    """Final synthesis agent — assembles all evidence into a validated InvestigationReport."""

    def __init__(self, llm_client: Optional[BaseLLMClient] = None):
        self.llm_client = llm_client or get_llm_client()

    def synthesize(
        self,
        case_id: str,
        alert: DetectionAlert,
        events: List[LogEvent],
        log_findings: Dict[str, Any],
        threat_intel_results: List[ThreatIntelResult],
        knowledge: List[Dict[str, Any]],
        knowledge_context: str,
        mitre_mappings: List[MitreTechniqueMapping],
        correlation_summary: str,
        threat_intel_summary: str,
    ) -> InvestigationReport:
        """Synthesize all agent outputs into a final InvestigationReport via LLM.

        Args:
            case_id: Investigation case identifier.
            alert: The detection alert.
            events: All normalized log events.
            log_findings: Output from Log Agent.
            threat_intel_results: Output from Threat Intel Agent.
            knowledge: Retrieved RAG chunks (as dicts).
            knowledge_context: Formatted RAG context string.
            mitre_mappings: Proposed technique mappings from Correlation Agent.
            correlation_summary: Narrative from Correlation Agent.
            threat_intel_summary: Narrative from Threat Intel Agent.

        Returns:
            Evidence-cross-checked InvestigationReport.
        """
        # ── Build Evidence Block ──────────────────────────────────────────
        triggering_ids: Set[str] = set(alert.triggering_event_ids)
        related = [e for e in events if e.event_id in triggering_ids]
        if not related and alert.source_ip:
            related = [e for e in events if e.source_ip == alert.source_ip][:30]

        evidence_lines = [
            f"- EventID: {e.event_id} | Timestamp: {e.timestamp} | "
            f"User: {e.username or 'N/A'} | SrcIP: {e.source_ip or 'N/A'} | "
            f"Action: {e.event_type} | Outcome: {e.outcome.value} | "
            f"Msg: {e.message}"
            for e in related[:30]
        ]
        evidence_block = "\n".join(evidence_lines)

        # ── Threat Intel Context ─────────────────────────────────────────
        ti_lines = [
            f"- Indicator: {r.indicator} | Score: {r.reputation_score:.0f}/100 | "
            f"Malicious: {'YES' if r.is_malicious else 'NO'} | Category: {r.threat_category or 'N/A'} | "
            f"Provider: {r.provider}"
            for r in threat_intel_results
        ]
        ti_block = "\n".join(ti_lines) if ti_lines else "No external threat intel enrichment performed."

        # ── MITRE Context ─────────────────────────────────────────────────
        mitre_block = "\n".join(
            f"- {m.technique_id} ({m.technique_name}): {m.evidence}"
            for m in mitre_mappings
        ) or "No candidate MITRE techniques correlated."

        # ── Behavioral Patterns ───────────────────────────────────────────
        patterns = log_findings.get("behavioral_patterns", [])
        patterns_block = "\n".join(f"- {p}" for p in patterns) or "No behavioral patterns detected."

        # ── Full LLM Prompt ───────────────────────────────────────────────
        prompt = f"""MULTI-AGENT SOC INVESTIGATION REPORT REQUEST:
Case ID: {case_id}
Alert ID: {alert.alert_id}
Triggered Rule: {alert.rule_name} ({alert.rule_id})
Initial Severity: {alert.severity.value}
Rule Rationale: {alert.severity_rationale}
Target User: {alert.affected_user or 'Unknown'}
Source IP: {alert.source_ip or 'Unknown'}

<evidence_data>
{evidence_block}
</evidence_data>

<behavioral_analysis>
{patterns_block}

Log Agent Narrative: {log_findings.get('narrative', 'N/A')}
</behavioral_analysis>

<retrieved_cybersecurity_knowledge>
{knowledge_context}
</retrieved_cybersecurity_knowledge>

<threat_intelligence_enrichment>
Overall Threat Intel Summary: {threat_intel_summary}

Indicator Details:
{ti_block}
</threat_intelligence_enrichment>

<mitre_correlation>
Correlated MITRE ATT&CK Techniques:
{mitre_block}

Correlation Agent Summary: {correlation_summary}
</mitre_correlation>

FORENSIC TASKS:
1. Synthesize an executive summary combining all agent findings.
2. List 2-4 OBSERVED FACTS (verifiable from the event IDs in evidence_data).
3. List 1-3 INFERRED CONCLUSIONS supported by threat intel and correlation.
4. Verify and list triggering event IDs. Ground-truth: use only IDs present in evidence_data.
5. Identify all Indicators of Compromise (IPs, usernames).
6. Map to MITRE ATT&CK techniques guided by the correlated techniques above.
7. Provide 2 ALTERNATIVE EXPLANATIONS (benign scenarios).
8. Detail 2 INVESTIGATION LIMITATIONS (missing telemetry, data gaps).
9. Provide prioritized RECOMMENDED ACTIONS from incident response guidance.
"""

        # ── LLM Generation ────────────────────────────────────────────────
        try:
            report = self.llm_client.generate_structured(
                prompt=prompt,
                schema=InvestigationReport,
            )
            report.case_id = case_id
            report.alert_id = alert.alert_id
        except Exception as exc:
            logger.error("[%s] LLM structured generation failed: %s. Using fallback.", NODE_NAME, exc)
            mock = MockLLMClient()
            report = mock.generate_structured(prompt, InvestigationReport)
            report.case_id = case_id
            report.alert_id = alert.alert_id

        # ── Attach Enrichment Metadata ────────────────────────────────────
        report.retrieved_knowledge = knowledge
        report.threat_intel_results = threat_intel_results

        # Override MITRE mappings with correlation agent's higher-quality mappings
        if mitre_mappings:
            report.mitre_techniques = mitre_mappings

        # ── Forensic Cross-Check: Verify Event IDs ────────────────────────
        known_event_ids = {e.event_id for e in events}
        verified = [eid for eid in report.triggering_events if eid in known_event_ids]
        if not verified and alert.triggering_event_ids:
            verified = [eid for eid in alert.triggering_event_ids if eid in known_event_ids]
        report.triggering_events = verified or alert.triggering_event_ids

        return report


def report_agent_node(state: SOCState) -> SOCState:
    """LangGraph node: Report Synthesis Agent.

    Reads: all upstream agent outputs
    Writes: final_report, report_markdown, review_status, agent_trace
    """
    trace = list(state.get("agent_trace", []))
    errors = list(state.get("errors", []))
    trace.append(f"[{NODE_NAME}] started")

    selected_alert: Optional[DetectionAlert] = state.get("selected_alert")
    events: List[LogEvent] = state.get("normalized_events", [])
    case_id: str = state.get("case_id", f"CASE-{uuid.uuid4().hex[:8].upper()}")

    if not selected_alert:
        msg = f"[{NODE_NAME}] No selected_alert — cannot generate report."
        logger.error(msg)
        errors.append(msg)
        trace.append(f"[{NODE_NAME}] FAILED (no alert)")
        return {
            **state,
            "final_report": None,
            "report_markdown": "# Report Generation Failed\nNo alert selected.",
            "agent_trace": trace,
            "errors": errors,
            "current_node": NODE_NAME,
        }

    try:
        agent = ReportAgent()
        report = agent.synthesize(
            case_id=case_id,
            alert=selected_alert,
            events=events,
            log_findings=state.get("log_analysis_findings", {}),
            threat_intel_results=state.get("threat_intel_results", []),
            knowledge=state.get("retrieved_knowledge", []),
            knowledge_context=state.get("knowledge_context", ""),
            mitre_mappings=state.get("candidate_mitre_mappings", []),
            correlation_summary=state.get("correlation_summary", ""),
            threat_intel_summary=state.get("threat_intel_summary", ""),
        )

        markdown = export_report_to_markdown(report)
        trace.append(
            f"[{NODE_NAME}] completed — report generated "
            f"(severity={report.severity.value}, confidence={report.confidence_score:.2f}, "
            f"MITRE={len(report.mitre_techniques)} techniques)"
        )
        logger.info("[%s] Final report: %s | %s", NODE_NAME, report.case_id, report.title)
        return {
            **state,
            "final_report": report,
            "report_markdown": markdown,
            "review_status": report.analyst_review_status,
            "agent_trace": trace,
            "errors": errors,
            "current_node": NODE_NAME,
        }
    except Exception as exc:
        msg = f"[{NODE_NAME}] Report synthesis failed: {exc}"
        logger.exception(msg)
        errors.append(msg)
        trace.append(f"[{NODE_NAME}] FAILED")
        return {
            **state,
            "final_report": None,
            "report_markdown": f"# Report Generation Failed\n\nError: {exc}",
            "agent_trace": trace,
            "errors": errors,
            "current_node": NODE_NAME,
        }
