"""Threat Intelligence Agent (Agent 3).

Specialized agent responsible for extracting indicators of compromise (IOCs),
performing reputation lookups across configured or mock providers,
and synthesizing external threat intelligence findings to corroborate local log evidence.
"""

import logging
from typing import Any, Dict, List, Optional
from models.schemas import ThreatIntelResult
from tools.reputation import ThreatIntelService, extract_indicators_from_text, is_private_ip

logger = logging.getLogger(__name__)


class ThreatIntelAgent:
    """Specialist agent for external indicator enrichment and threat reputation analysis."""

    def __init__(self, service: Optional[ThreatIntelService] = None):
        self.service = service or ThreatIntelService()

    def analyze_indicators(self, indicators: List[str]) -> Dict[str, Any]:
        """Enrich a list of IP indicators and produce structured forensic intelligence.

        Args:
            indicators: List of IP strings, hostnames, or IOCs

        Returns:
            Dictionary containing enriched ThreatIntelResults, categorized IOCs, and executive summary
        """
        # Deduplicate and strip indicators
        unique_ips = sorted(list({ip.strip() for ip in indicators if ip and ip.strip()}))

        enriched_results: List[ThreatIntelResult] = self.service.enrich_indicators(unique_ips)

        malicious: List[ThreatIntelResult] = []
        suspicious: List[ThreatIntelResult] = []
        clean: List[ThreatIntelResult] = []
        internal: List[ThreatIntelResult] = []

        for res in enriched_results:
            if is_private_ip(res.indicator):
                internal.append(res)
            elif res.is_malicious or res.reputation_score >= 50.0:
                malicious.append(res)
            elif res.reputation_score >= 20.0:
                suspicious.append(res)
            else:
                clean.append(res)

        # Synthesize analytical narrative
        summary_lines = []
        if malicious:
            for m in malicious:
                summary_lines.append(
                    f"CRITICAL REPUTATION: IP {m.indicator} has an abuse confidence score of "
                    f"{m.reputation_score:.0f}% ({m.total_reports} community reports). "
                    f"Known category: '{m.threat_category or 'Malicious'}'. Provider: {m.provider}."
                )
        if suspicious:
            for s in suspicious:
                summary_lines.append(
                    f"SUSPICIOUS REPUTATION: IP {s.indicator} flagged with moderate risk score "
                    f"({s.reputation_score:.0f}%). Provider: {s.provider}."
                )
        if internal:
            summary_lines.append(
                f"INTERNAL TELEMETRY: {len(internal)} IP(s) ({', '.join([i.indicator for i in internal])}) "
                f"belong to private RFC1918 space and were excluded from external public queries."
            )
        if clean and not malicious and not suspicious:
            summary_lines.append(
                f"BENIGN REPUTATION: External reputation checks returned zero malicious reports "
                f"for queried hosts ({', '.join([c.indicator for c in clean])})."
            )

        overall_threat = "HIGH" if malicious else ("MEDIUM" if suspicious else "LOW")

        return {
            "threat_severity": overall_threat,
            "total_indicators_queried": len(unique_ips),
            "malicious_count": len(malicious),
            "suspicious_count": len(suspicious),
            "clean_count": len(clean),
            "internal_count": len(internal),
            "results": enriched_results,
            "summary": " ".join(summary_lines) or "No actionable external threat intelligence.",
            "malicious_ips": [m.indicator for m in malicious],
        }

    def format_threat_intel_for_prompt(self, analysis: Dict[str, Any]) -> str:
        """Format threat intelligence findings into structured context for LLM prompt injection."""
        results: List[ThreatIntelResult] = analysis.get("results", [])
        if not results:
            return "No external threat intelligence indicators identified for this alert."

        lines = [
            f"Overall Threat Reputation: {analysis.get('threat_severity', 'UNKNOWN')}",
            f"Summary: {analysis.get('summary', '')}",
            "\nIndicator Reputation Details:",
        ]

        for r in results:
            lines.append(
                f"- Indicator: {r.indicator} ({r.indicator_type}) | Provider: {r.provider} | "
                f"Reputation Score: {r.reputation_score:.0f}/100 | "
                f"Category: {r.threat_category or 'N/A'} | "
                f"Malicious: {'YES' if r.is_malicious else 'NO'} | "
                f"Reports: {r.total_reports} | ISP: {r.isp or 'Unknown'} | Country: {r.country_code or 'Unknown'}"
            )

        return "\n".join(lines)
