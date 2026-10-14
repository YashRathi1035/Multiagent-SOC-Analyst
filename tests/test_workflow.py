"""Integration tests for the LangGraph multi-agent SOC investigation workflow.

Tests:
1. test_workflow_compiles_successfully
2. test_full_workflow_with_alerts
3. test_workflow_with_no_alerts_terminates_gracefully
4. test_workflow_produces_investigation_report
5. test_workflow_agent_trace_records_all_nodes
6. test_stream_investigation_yields_node_updates
7. test_run_investigation_convenience_function
"""

import pytest
from datetime import datetime, timedelta
from unittest.mock import patch, MagicMock

from models.schemas import (
    DetectionAlert,
    EventOutcome,
    InvestigationReport,
    LogEvent,
    SeverityLevel,
)
from graph.workflow import build_soc_workflow, run_investigation, stream_investigation
from graph.state import SOCState


# ─── Fixtures ──────────────────────────────────────────────────────────────────

def _make_events(count: int = 8, source_ip: str = "203.0.113.88") -> list:
    events = []
    for i in range(count):
        outcome = EventOutcome.FAILURE if i < count - 1 else EventOutcome.SUCCESS
        events.append(LogEvent(
            event_id=f"EVT-{i:04d}-CAFEBABE",
            timestamp=datetime(2024, 3, 15, 14, 0, 0) + timedelta(seconds=i * 30),
            source_type="auth_openssh",
            username="admin" if i % 2 == 0 else "root",
            source_ip=source_ip,
            hostname="prod-server-01",
            event_type="failed_login" if outcome == EventOutcome.FAILURE else "successful_login",
            outcome=outcome,
            message=f"SSH auth {'failed' if outcome == EventOutcome.FAILURE else 'succeeded'} for user {'admin' if i % 2 == 0 else 'root'} from {source_ip}",
            original_record=f"raw syslog line {i}",
        ))
    return events


def _make_alert(events: list, rule_id: str = "RULE-AUTH-001") -> DetectionAlert:
    return DetectionAlert(
        alert_id=f"ALT-WORKFLOW-{rule_id[-3:]}",
        rule_id=rule_id,
        rule_name="Repeated Authentication Failures (Brute-Force)",
        severity=SeverityLevel.HIGH,
        description="Test alert for workflow integration testing.",
        triggering_event_ids=[e.event_id for e in events[:6]],
        affected_user="admin",
        source_ip="203.0.113.88",
        severity_rationale="7 failures in 10 minutes from single IP.",
        evidence_summary={"attempt_count": 7},
        mitre_candidates=["T1110.001 - Password Guessing"],
    )


# ─── Workflow Compilation ──────────────────────────────────────────────────────

class TestWorkflowCompilation:

    def test_workflow_compiles_successfully(self):
        """StateGraph should compile without errors."""
        wf = build_soc_workflow()
        assert wf is not None

    def test_workflow_has_correct_node_count(self):
        """Compiled workflow should contain all 6 agent nodes."""
        wf = build_soc_workflow()
        # get_graph() returns the underlying Pregel graph with all nodes
        graph_repr = wf.get_graph()
        node_names = set(graph_repr.nodes.keys())
        expected = {"orchestrator", "log_agent", "threat_intel_node",
                    "knowledge_agent", "correlation_agent", "report_agent"}
        assert expected.issubset(node_names), (
            f"Missing nodes: {expected - node_names}. Found: {node_names}"
        )



# ─── Full Workflow Integration ─────────────────────────────────────────────────

class TestFullWorkflow:

    def test_workflow_with_alerts_completes(self):
        """Full workflow should complete without fatal errors when alerts exist."""
        events = _make_events(8)
        alert = _make_alert(events)

        final_state = run_investigation(
            normalized_events=events,
            alerts=[alert],
        )

        assert final_state is not None
        assert final_state.get("case_id", "").startswith("CASE-")
        # Agent trace should record all 6 nodes
        trace = final_state.get("agent_trace", [])
        assert len(trace) >= 6

    def test_workflow_no_alerts_terminates_gracefully(self):
        """Workflow with empty alert list should exit cleanly after orchestrator."""
        events = _make_events(5)
        final_state = run_investigation(
            normalized_events=events,
            alerts=[],
        )
        assert final_state is not None
        assert final_state.get("selected_alert") is None
        assert final_state.get("final_report") is None
        # No fatal errors should be present from the orchestrator's graceful exit
        errors = final_state.get("errors", [])
        assert not any("fatal" in e.lower() for e in errors)

    def test_workflow_produces_investigation_report(self):
        """Full workflow should produce a valid InvestigationReport."""
        events = _make_events(8)
        alert = _make_alert(events)

        final_state = run_investigation(
            normalized_events=events,
            alerts=[alert],
        )
        report = final_state.get("final_report")
        assert report is not None
        assert isinstance(report, InvestigationReport)

    def test_workflow_report_has_valid_fields(self):
        """Final InvestigationReport should have all required fields populated."""
        events = _make_events(8)
        alert = _make_alert(events)

        final_state = run_investigation(
            normalized_events=events,
            alerts=[alert],
        )
        report: InvestigationReport = final_state["final_report"]
        assert report.case_id.startswith("CASE-")
        assert report.alert_id == alert.alert_id
        assert report.severity in (SeverityLevel.LOW, SeverityLevel.MEDIUM,
                                   SeverityLevel.HIGH, SeverityLevel.CRITICAL)
        assert 0.0 <= report.confidence_score <= 1.0
        assert len(report.observed_facts) >= 1
        assert len(report.recommended_actions) >= 1

    def test_workflow_report_event_ids_are_verified(self):
        """Final report triggering_events should only contain real event IDs."""
        events = _make_events(8)
        alert = _make_alert(events)
        real_ids = {e.event_id for e in events}

        final_state = run_investigation(
            normalized_events=events,
            alerts=[alert],
        )
        report: InvestigationReport = final_state["final_report"]
        for eid in report.triggering_events:
            assert eid in real_ids, f"Report contains hallucinated event ID: {eid}"

    def test_workflow_agent_trace_records_all_nodes(self):
        """agent_trace should contain at least one entry per executed node."""
        events = _make_events(8)
        alert = _make_alert(events)

        final_state = run_investigation(
            normalized_events=events,
            alerts=[alert],
        )
        trace = final_state.get("agent_trace", [])
        trace_str = " ".join(trace).lower()

        for node in ["orchestrator", "log_agent", "threat_intel", "knowledge", "correlation", "report"]:
            assert node in trace_str, f"Node '{node}' not found in agent_trace"

    def test_workflow_mitre_techniques_mapped(self):
        """Final report should contain at least one MITRE ATT&CK technique mapping."""
        events = _make_events(8)
        alert = _make_alert(events)

        final_state = run_investigation(
            normalized_events=events,
            alerts=[alert],
        )
        report: InvestigationReport = final_state["final_report"]
        assert len(report.mitre_techniques) >= 1

    def test_workflow_prefers_highest_severity_alert(self):
        """Orchestrator should select CRITICAL alert over HIGH when both present."""
        events = _make_events(8)
        high_alert = _make_alert(events, "RULE-AUTH-001")
        high_alert.severity = SeverityLevel.HIGH

        critical_alert = _make_alert(events, "RULE-AUTH-002")
        critical_alert.alert_id = "ALT-CRITICAL-001"
        critical_alert.severity = SeverityLevel.CRITICAL
        critical_alert.rule_id = "RULE-AUTH-002"

        final_state = run_investigation(
            normalized_events=events,
            alerts=[high_alert, critical_alert],
        )
        assert final_state["selected_alert"].severity == SeverityLevel.CRITICAL


# ─── Streaming Tests ───────────────────────────────────────────────────────────

class TestStreamingWorkflow:

    def test_stream_investigation_yields_updates(self):
        """stream_investigation should yield at least one (node_name, state) tuple."""
        events = _make_events(8)
        alert = _make_alert(events)

        updates = list(stream_investigation(
            normalized_events=events,
            alerts=[alert],
        ))
        assert len(updates) >= 1

    def test_stream_investigation_no_alerts(self):
        """Streaming with no alerts should still yield orchestrator output."""
        events = _make_events(5)
        updates = list(stream_investigation(
            normalized_events=events,
            alerts=[],
        ))
        assert len(updates) >= 1
        # First node should be orchestrator
        first_node = updates[0][0]
        assert first_node == "orchestrator"

    def test_stream_yields_all_six_nodes(self):
        """Streaming should yield updates from all 6 pipeline nodes."""
        events = _make_events(8)
        alert = _make_alert(events)

        node_names = [node for node, _ in stream_investigation(
            normalized_events=events,
            alerts=[alert],
        )]
        expected_nodes = [
            "orchestrator", "log_agent", "threat_intel_node",
            "knowledge_agent", "correlation_agent", "report_agent"
        ]
        for expected in expected_nodes:
            assert expected in node_names, (
                f"Expected node '{expected}' not found in streamed updates: {node_names}"
            )
