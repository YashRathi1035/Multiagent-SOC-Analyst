"""Unit tests for individual Phase-4 agent nodes.

Tests:
1. test_orchestrator_selects_highest_priority_alert
2. test_orchestrator_no_alerts
3. test_log_agent_extracts_indicators
4. test_log_agent_detects_brute_force_pattern
5. test_log_agent_no_alert
6. test_correlation_agent_maps_mitre_techniques
7. test_correlation_agent_builds_timeline
8. test_threat_intel_node_enriches_indicators
9. test_report_agent_synthesizes_report
"""

import pytest
from datetime import datetime, timedelta
from unittest.mock import MagicMock

from models.schemas import (
    DetectionAlert,
    EventOutcome,
    InvestigationReport,
    LogEvent,
    MitreTechniqueMapping,
    ReviewStatus,
    SeverityLevel,
    ThreatIntelResult,
)
from agents.orchestrator import Orchestrator, orchestrator_node, route_after_orchestrator
from agents.log_agent import LogAnalysisAgent, log_agent_node
from agents.correlation_agent import CorrelationAgent, correlation_agent_node
from agents.report_agent import ReportAgent
from agents.llm_client import MockLLMClient


# ─── Fixtures ──────────────────────────────────────────────────────────────────

def make_event(
    idx: int,
    outcome: EventOutcome = EventOutcome.FAILURE,
    username: str = "admin",
    source_ip: str = "10.0.0.1",
    ts_offset_seconds: int = 0,
) -> LogEvent:
    """Create a synthetic log event for testing."""
    return LogEvent(
        event_id=f"EVT-{idx:04d}-AABBCCDD",
        timestamp=datetime(2024, 1, 10, 8, 0, 0) + timedelta(seconds=ts_offset_seconds),
        source_type="auth_openssh",
        username=username,
        source_ip=source_ip,
        hostname="server01",
        event_type="failed_login" if outcome == EventOutcome.FAILURE else "successful_login",
        outcome=outcome,
        message=f"Auth {'failed' if outcome == EventOutcome.FAILURE else 'succeeded'} for user {username} from {source_ip}",
        original_record=f"raw line {idx}",
    )


def make_alert(
    rule_id: str = "RULE-AUTH-001",
    severity: SeverityLevel = SeverityLevel.HIGH,
    source_ip: str = "10.0.0.1",
    event_ids: list = None,
) -> DetectionAlert:
    return DetectionAlert(
        alert_id=f"ALT-TEST-{rule_id[-3:]}",
        rule_id=rule_id,
        rule_name={
            "RULE-AUTH-001": "Repeated Authentication Failures (Brute-Force)",
            "RULE-AUTH-002": "Failed Logins Followed by Successful Login",
            "RULE-AUTH-003": "User Enumeration / Account Spraying",
        }.get(rule_id, "Test Rule"),
        severity=severity,
        description=f"Test alert for {rule_id}",
        triggering_event_ids=event_ids or [f"EVT-{i:04d}-AABBCCDD" for i in range(1, 6)],
        affected_user="admin",
        source_ip=source_ip,
        severity_rationale=f"Threshold exceeded for {rule_id}",
        evidence_summary={"attempt_count": 5},
        mitre_candidates=["T1110.001 - Password Guessing"],
    )


# ─── Orchestrator Tests ────────────────────────────────────────────────────────

class TestOrchestrator:

    def test_selects_highest_priority_alert(self):
        """Orchestrator should prefer CRITICAL > HIGH and compromise > brute force."""
        brute_alert = make_alert("RULE-AUTH-001", SeverityLevel.HIGH)
        compromise_alert = make_alert("RULE-AUTH-002", SeverityLevel.CRITICAL)
        enum_alert = make_alert("RULE-AUTH-003", SeverityLevel.MEDIUM)

        orch = Orchestrator()
        result = orch.plan([brute_alert, compromise_alert, enum_alert], 100)

        assert result["selected_alert"] is not None
        assert result["selected_alert"].alert_id == compromise_alert.alert_id
        assert result["investigation_plan"]["total_alerts"] == 3

    def test_no_alerts_returns_none(self):
        """Orchestrator with empty alert list should set selected_alert to None."""
        orch = Orchestrator()
        result = orch.plan([], 50)
        assert result["selected_alert"] is None
        assert result["investigation_plan"]["decision"] == "no_alerts"

    def test_orchestrator_node_initializes_state(self):
        """orchestrator_node should set case_id, created_at, and agent_trace."""
        events = [make_event(i) for i in range(1, 6)]
        alert = make_alert()
        state = {
            "normalized_events": events,
            "alerts": [alert],
        }
        out = orchestrator_node(state)
        assert out["case_id"].startswith("CASE-")
        assert out["created_at"] is not None
        assert len(out["agent_trace"]) >= 1
        assert out["selected_alert"] is not None
        assert out["review_status"] == ReviewStatus.PENDING

    def test_route_after_orchestrator_with_alert(self):
        """Router should return 'log_agent' when alert is selected."""
        state = {"selected_alert": make_alert()}
        assert route_after_orchestrator(state) == "log_agent"

    def test_route_after_orchestrator_no_alert(self):
        """Router should return 'end' when no alert is selected."""
        state = {"selected_alert": None}
        assert route_after_orchestrator(state) == "end"


# ─── Log Agent Tests ────────────────────────────────────────────────────────────

class TestLogAgent:

    def test_extracts_ip_indicators(self):
        """Log agent should extract all unique source IPs as indicators."""
        events = [make_event(i, source_ip="203.0.113.88") for i in range(1, 8)]
        alert = make_alert(source_ip="203.0.113.88")
        agent = LogAnalysisAgent()
        result = agent.analyze(alert, events)
        assert "203.0.113.88" in result["extracted_indicators"]

    def test_detects_brute_force_pattern(self):
        """Log agent should detect burst pattern from repeated failures."""
        events = [make_event(i, outcome=EventOutcome.FAILURE) for i in range(1, 8)]
        alert = make_alert()
        agent = LogAnalysisAgent()
        result = agent.analyze(alert, events)
        patterns = result["log_analysis_findings"]["behavioral_patterns"]
        assert any("burst" in p.lower() or "brute" in p.lower() for p in patterns)

    def test_detects_compromise_pattern(self):
        """Log agent should flag compromise when failures are followed by success."""
        failures = [make_event(i, outcome=EventOutcome.FAILURE) for i in range(1, 5)]
        success = make_event(5, outcome=EventOutcome.SUCCESS, ts_offset_seconds=300)
        alert = make_alert()
        agent = LogAnalysisAgent()
        result = agent.analyze(alert, failures + [success])
        patterns = result["log_analysis_findings"]["behavioral_patterns"]
        assert any("compromise" in p.lower() for p in patterns)

    def test_log_agent_node_no_alert_graceful(self):
        """log_agent_node should handle missing selected_alert without crashing."""
        state = {"normalized_events": [], "errors": [], "agent_trace": []}
        out = log_agent_node(state)
        assert "errors" in out
        assert any("no alert" in e.lower() or "no selected" in e.lower() for e in out["errors"])

    def test_log_agent_node_writes_to_state(self):
        """log_agent_node should write extracted_indicators and log_analysis_findings."""
        events = [make_event(i) for i in range(1, 7)]
        alert = make_alert(event_ids=[e.event_id for e in events])
        state = {
            "normalized_events": events,
            "selected_alert": alert,
            "errors": [],
            "agent_trace": [],
        }
        out = log_agent_node(state)
        assert "extracted_indicators" in out
        assert "log_analysis_findings" in out
        assert isinstance(out["extracted_indicators"], list)


# ─── Correlation Agent Tests ───────────────────────────────────────────────────

class TestCorrelationAgent:

    def test_maps_brute_force_mitre_technique(self):
        """Correlation agent should map T1110.001 for brute force patterns."""
        events = [make_event(i) for i in range(1, 8)]
        alert = make_alert("RULE-AUTH-001")
        log_findings = {
            "behavioral_patterns": ["Brute-force burst from 10.0.0.1: 7 failures"],
            "total_failures": 7,
            "total_successes": 0,
            "burst_analysis_by_ip": {
                "10.0.0.1": {"total_failures": 7, "total_successes": 0,
                             "targeted_users": ["admin"], "targets_privileged_accounts": True,
                             "earliest_failure": None, "latest_event": None, "compromise_suspected": False}
            },
        }
        agent = CorrelationAgent()
        result = agent.correlate(alert, events, log_findings, [], [])
        tech_ids = [m.technique_id for m in result["candidate_mitre_mappings"]]
        assert "T1110.001" in tech_ids

    def test_builds_non_empty_timeline(self):
        """Correlation agent should build a timeline from related events."""
        events = [make_event(i) for i in range(1, 6)]
        alert = make_alert(event_ids=[e.event_id for e in events])
        log_findings = {"behavioral_patterns": [], "total_failures": 5, "total_successes": 0,
                        "burst_analysis_by_ip": {}}
        agent = CorrelationAgent()
        result = agent.correlate(alert, events, log_findings, [], [])
        assert len(result["timeline"]) >= 1

    def test_maps_valid_accounts_technique_on_success(self):
        """Correlation agent should map T1078 when successes follow failures."""
        events = [make_event(i, outcome=EventOutcome.FAILURE) for i in range(1, 5)]
        events += [make_event(5, outcome=EventOutcome.SUCCESS)]
        alert = make_alert("RULE-AUTH-002", SeverityLevel.CRITICAL)
        log_findings = {
            "behavioral_patterns": ["Credential compromise suspected"],
            "total_failures": 4,
            "total_successes": 1,
            "burst_analysis_by_ip": {},
        }
        agent = CorrelationAgent()
        result = agent.correlate(alert, events, log_findings, [], [])
        tech_ids = [m.technique_id for m in result["candidate_mitre_mappings"]]
        assert "T1078" in tech_ids


# ─── Report Agent Tests ────────────────────────────────────────────────────────

class TestReportAgent:

    def test_synthesizes_report_with_mock_llm(self):
        """ReportAgent with MockLLMClient should return a validated InvestigationReport."""
        events = [make_event(i) for i in range(1, 6)]
        alert = make_alert(event_ids=[e.event_id for e in events])

        agent = ReportAgent(llm_client=MockLLMClient())
        report = agent.synthesize(
            case_id="CASE-TEST-0001",
            alert=alert,
            events=events,
            log_findings={"behavioral_patterns": [], "narrative": "Test.", "total_failures": 5, "total_successes": 0},
            threat_intel_results=[],
            knowledge=[],
            knowledge_context="No knowledge retrieved.",
            mitre_mappings=[MitreTechniqueMapping(technique_id="T1110.001",
                                                   technique_name="Password Guessing",
                                                   evidence="5 failures from 10.0.0.1")],
            correlation_summary="Test correlation.",
            threat_intel_summary="No malicious IPs.",
        )
        assert isinstance(report, InvestigationReport)
        assert report.case_id == "CASE-TEST-0001"
        assert report.alert_id == alert.alert_id
        assert report.confidence_score >= 0.0
        assert report.confidence_score <= 1.0

    def test_report_cross_checks_event_ids(self):
        """ReportAgent should discard hallucinated event IDs not in the actual log."""
        events = [make_event(i) for i in range(1, 4)]
        alert = make_alert(event_ids=[e.event_id for e in events])

        agent = ReportAgent(llm_client=MockLLMClient())
        report = agent.synthesize(
            case_id="CASE-XVR-0002",
            alert=alert,
            events=events,
            log_findings={"behavioral_patterns": [], "narrative": "", "total_failures": 3, "total_successes": 0},
            threat_intel_results=[],
            knowledge=[],
            knowledge_context="",
            mitre_mappings=[],
            correlation_summary="",
            threat_intel_summary="",
        )
        # All triggering_events must be real event IDs
        real_ids = {e.event_id for e in events}
        for eid in report.triggering_events:
            assert eid in real_ids or eid in {e.event_id for e in events}, \
                f"Hallucinated event ID in report: {eid}"
