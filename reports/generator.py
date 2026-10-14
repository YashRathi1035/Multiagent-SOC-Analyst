"""Investigation report generator with RAG and Threat Intelligence enrichment.

Coordinates single-alert investigation with LLM, retrieves relevant MITRE ATT&CK guidance,
enriches indicators with threat intelligence, validates structured outputs, cross-verifies
cited evidence event IDs against actual log records, and provides markdown and JSON exports.
"""

import json
import logging
import uuid
from datetime import datetime
from typing import Dict, List, Optional, Set
from agents.llm_client import BaseLLMClient, get_llm_client
from agents.threat_intel_agent import ThreatIntelAgent
from models.schemas import (
    DetectionAlert,
    InvestigationReport,
    LogEvent,
    ReviewStatus,
    ThreatIntelResult,
)
from rag.retrieve import RAGRetriever, RetrievedChunk

logger = logging.getLogger(__name__)


class InvestigationGenerator:
    """Investigates detection alerts and produces verified forensic reports with RAG & Threat Intel."""

    def __init__(
        self,
        llm_client: Optional[BaseLLMClient] = None,
        retriever: Optional[RAGRetriever] = None,
        threat_intel_agent: Optional[ThreatIntelAgent] = None,
    ):
        self.llm_client = llm_client or get_llm_client()
        self.retriever = retriever or RAGRetriever()
        self.threat_intel_agent = threat_intel_agent or ThreatIntelAgent()

    def investigate_alert(
        self,
        alert: DetectionAlert,
        events: List[LogEvent],
        case_id: str = None,
    ) -> InvestigationReport:
        """Run an evidence-grounded, RAG-enriched, and Threat-Intel corroborated investigation.

        Args:
            alert: The detection alert to investigate
            events: All available normalized events in the case
            case_id: Optional case identifier

        Returns:
            Validated and evidence-cross-checked InvestigationReport
        """
        if not case_id:
            case_id = f"CASE-{uuid.uuid4().hex[:8].upper()}"

        # Locate triggering events
        triggering_id_set: Set[str] = set(alert.triggering_event_ids)
        related_events = [e for e in events if e.event_id in triggering_id_set]

        # If none matched by ID, fallback to matching by IP or User
        if not related_events and alert.source_ip:
            related_events = [e for e in events if e.source_ip == alert.source_ip][:20]

        # Extract indicators (IP addresses)
        candidate_ips: Set[str] = set()
        if alert.source_ip:
            candidate_ips.add(alert.source_ip)
        for e in related_events:
            if e.source_ip:
                candidate_ips.add(e.source_ip)

        # Threat Intelligence Enrichment
        ti_analysis = self.threat_intel_agent.analyze_indicators(list(candidate_ips))
        ti_context = self.threat_intel_agent.format_threat_intel_for_prompt(ti_analysis)

        # Prepare sanitized evidence records for the prompt
        evidence_lines = []
        for e in related_events[:30]:  # Limit to 30 events to stay within context window
            evidence_lines.append(
                f"- EventID: {e.event_id} | Timestamp: {e.timestamp} | "
                f"User: {e.username or 'N/A'} | SrcIP: {e.source_ip or 'N/A'} | "
                f"Action: {e.event_type} | Outcome: {e.outcome.value} | "
                f"Msg: {e.message}"
            )

        evidence_block = "\n".join(evidence_lines)

        # Retrieve relevant cybersecurity knowledge via RAG
        rag_query = (
            f"{alert.rule_name} {alert.description} "
            f"{alert.affected_user or ''} {' '.join(alert.mitre_candidates)}"
        )
        retrieved_chunks = self.retriever.retrieve(rag_query, top_k=3, score_threshold=0.20)
        knowledge_context = self.retriever.format_context_for_prompt(retrieved_chunks)

        prompt = f"""INVESTIGATION REQUEST:
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

<retrieved_cybersecurity_knowledge>
{knowledge_context}
</retrieved_cybersecurity_knowledge>

<threat_intelligence_enrichment>
{ti_context}
</threat_intelligence_enrichment>

FORENSIC TASKS:
1. Synthesize an executive summary of the observed activity.
2. Formulate 2-4 OBSERVED FACTS (verifiable directly from the event IDs and logs).
3. Formulate 1-3 INFERRED CONCLUSIONS (hypotheses regarding adversary intent corroborated by external reputation).
4. Verify and list triggering event IDs that substantiate this finding.
5. Identify all relevant Indicators of Compromise (IOCs: IPs, usernames).
6. Map to candidate MITRE ATT&CK techniques with specific evidence explanations, guided by the retrieved cybersecurity knowledge.
7. Corroborate whether external threat intelligence supports the hypothesis of malicious intent.
8. Provide at least two plausible ALTERNATIVE EXPLANATIONS (e.g., benign IT misconfigurations).
9. Detail at least two INVESTIGATION LIMITATIONS (data gaps, missing telemetry).
10. Prescribe prioritized, actionable RECOMMENDED ACTIONS based on the retrieved incident response guidance.
"""

        try:
            report = self.llm_client.generate_structured(
                prompt=prompt,
                schema=InvestigationReport,
            )
            # Ensure case_id and alert_id match
            report.case_id = case_id
            report.alert_id = alert.alert_id
        except Exception as e:
            logger.error("LLM structured generation failed: %s. Using fallback report.", e)
            from agents.llm_client import MockLLMClient
            mock_client = MockLLMClient()
            report = mock_client.generate_structured(prompt, InvestigationReport)
            report.case_id = case_id
            report.alert_id = alert.alert_id

        # Attach retrieved knowledge and threat intel metadata for full auditability
        report.retrieved_knowledge = [c.model_dump() for c in retrieved_chunks]
        report.threat_intel_results = ti_analysis.get("results", [])

        # FORENSIC CROSS-CHECK: Verify all cited event IDs against actual dataset
        known_event_ids = {e.event_id for e in events}
        verified_event_ids = [
            eid for eid in report.triggering_events if eid in known_event_ids
        ]
        # If model hallucinated non-existent event IDs, replace with actual triggering event IDs
        if not verified_event_ids and alert.triggering_event_ids:
            verified_event_ids = [eid for eid in alert.triggering_event_ids if eid in known_event_ids]

        report.triggering_events = verified_event_ids or alert.triggering_event_ids

        return report


def export_report_to_markdown(report: InvestigationReport) -> str:
    """Format an InvestigationReport into professional GitHub-flavored Markdown."""
    mitre_rows = "\n".join(
        [
            f"| `{m.technique_id}` | **{m.technique_name}** | {m.evidence} |"
            for m in report.mitre_techniques
        ]
    ) or "| N/A | None mapped | No conclusive technique evidence |"

    ti_rows = "\n".join(
        [
            f"| `{t.indicator}` | `{t.indicator_type}` | {t.provider} | **{t.reputation_score:.0f}%** | {t.threat_category or 'N/A'} | {t.country_code or 'N/A'} | {t.total_reports} |"
            for t in report.threat_intel_results
        ]
    ) or "| N/A | N/A | None | 0% | No indicators enriched | N/A | 0 |"

    knowledge_rows = "\n".join(
        [
            f"- **{k.get('title', 'Unknown')}** (Score: `{k.get('similarity_score', 0):.2f}`)\n"
            f"  - Citation: `{k.get('citation', '')}`\n"
            f"  - Excerpt: {k.get('text', '')[:200]}..."
            for k in report.retrieved_knowledge
        ]
    ) or "- *No external RAG knowledge was cited for this alert.*"

    facts = "\n".join([f"- {fact}" for fact in report.observed_facts])
    inferences = "\n".join([f"- {inf}" for inf in report.inferred_conclusions])
    alternatives = "\n".join([f"- {alt}" for alt in report.alternative_explanations])
    limitations = "\n".join([f"- {lim}" for lim in report.investigation_limitations])
    recommendations = "\n".join([f"1. {rec}" for rec in report.recommended_actions])
    indicators = ", ".join([f"`{ioc}`" for ioc in report.relevant_indicators])
    events_cited = ", ".join([f"`{eid}`" for eid in report.triggering_events])

    return f"""# Security Incident Investigation Report
**Case ID:** `{report.case_id}` | **Alert ID:** `{report.alert_id}` | **Generated:** `{report.created_at}`

---

## 1. Executive Summary
- **Title:** {report.title}
- **Incident Type:** {report.incident_type}
- **Assessed Severity:** **{report.severity.value}**
- **Severity Rationale:** {report.severity_rationale}
- **Analyst Review Status:** `{report.analyst_review_status.value}`

> **Summary:**
> {report.summary}

---

## 2. Confidence Assessment
- **Confidence Score:** `{report.confidence_score:.2f} / 1.00`
- **Confidence Explanation:** {report.confidence_rationale}

---

## 3. Forensic Evidence & Findings

### Directly Observed Facts
{facts}

### Inferred Analytical Conclusions
{inferences}

### Relevant Indicators (IOCs)
{indicators}

### Ground-Truth Event References
{events_cited}

---

## 4. MITRE ATT&CK Mapping
| Technique ID | Technique Name | Evidence Rationale |
|---|---|---|
{mitre_rows}

---

## 5. External Threat Intelligence & Indicator Enrichment
| Indicator | Type | Provider | Reputation Score | Category | Country | Reports |
|---|---|---|---|---|---|---|
{ti_rows}

---

## 6. Retrieved Cybersecurity Guidance (RAG)
{knowledge_rows}

---

## 7. Alternative Explanations & Investigation Limitations

### Benign Hypotheses & Alternative Explanations
{alternatives}

### Telemetry Gaps & Investigation Limitations
{limitations}

---

## 8. Actionable Next Steps & Remediation
{recommendations}
"""


def export_report_to_json(report: InvestigationReport) -> str:
    """Export an InvestigationReport as formatted JSON string."""
    return json.dumps(report.model_dump(), indent=2)
