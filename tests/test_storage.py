"""Unit tests for SQLite Case Persistence and Management (Phase 6).

Verifies:
1. SQLite schema initialization
2. Case saving and retrieval (with InvestigationReport deserialization)
3. Case updates and human-in-the-loop status transitions
4. Filtering, metrics calculation, and case deletion
"""

from datetime import datetime
import pytest

from models.schemas import (
    InvestigationReport,
    MitreTechniqueMapping,
    ReviewStatus,
    SeverityLevel,
)
from storage.database import DatabaseManager
from storage.models import CaseRecord


@pytest.fixture
def test_db():
    """Create an in-memory SQLite DatabaseManager for testing."""
    return DatabaseManager(db_url="sqlite:///:memory:")


@pytest.fixture
def sample_report():
    """Create a valid sample InvestigationReport for persistence tests."""
    return InvestigationReport(
        case_id="CASE-TEST-001",
        alert_id="ALT-BRUTE-001",
        title="Automated SSH Brute Force Incident",
        incident_type="SSH Brute-Force",
        severity=SeverityLevel.HIGH,
        severity_rationale="Over 15 failed authentication attempts within 3 minutes.",
        confidence_score=0.92,
        confidence_rationale="Corroborated by high rate of failures and RFC1918 threat intel.",
        summary="An external IP 198.51.100.42 attempted systematic brute-force password guessing against user admin.",
        observed_facts=[
            "18 failed login attempts recorded between 10:00 and 10:03 UTC",
            "Target account: admin",
            "Source IP: 198.51.100.42",
        ],
        inferred_conclusions=[
            "High probability of automated credential guessing bot",
        ],
        triggering_events=["EVT-01", "EVT-02", "EVT-03"],
        relevant_indicators=["198.51.100.42", "admin"],
        mitre_techniques=[
            MitreTechniqueMapping(
                technique_id="T1110.001",
                technique_name="Password Guessing",
                evidence="18 failed logins in 3 minutes",
            )
        ],
        recommended_actions=[
            "Block IP 198.51.100.42 on perimeter firewall",
            "Verify admin password complexity and enforce MFA",
        ],
        analyst_notes="Initial investigation completed by Multi-Agent Swarm.",
    )


class TestStorageDatabase:
    """Test suite for DatabaseManager operations."""

    def test_db_initialization(self, test_db):
        assert test_db.engine is not None
        assert test_db.get_case_count() == 0

    def test_save_case_and_retrieve(self, test_db, sample_report):
        rec = test_db.save_case(
            case_id="CASE-TEST-001",
            report=sample_report,
            raw_filename="auth.log",
        )
        assert rec is not None
        assert rec.case_id == "CASE-TEST-001"
        assert rec.severity == "HIGH"
        assert rec.title == "Automated SSH Brute Force Incident"
        assert rec.source_ip == "198.51.100.42"
        assert rec.affected_user == "admin"
        assert rec.status == ReviewStatus.PENDING.value

        # Retrieve and verify deserialized report
        retrieved = test_db.get_case("CASE-TEST-001")
        assert retrieved is not None
        assert retrieved.case_id == "CASE-TEST-001"

        deserialized = retrieved.get_report()
        assert deserialized is not None
        assert deserialized.case_id == "CASE-TEST-001"
        assert deserialized.confidence_score == 0.92
        assert len(deserialized.triggering_events) == 3

    def test_save_case_updates_existing(self, test_db, sample_report):
        test_db.save_case(case_id="CASE-TEST-001", report=sample_report)

        # Update report title and confidence
        updated_report = sample_report.model_copy(
            update={"title": "Updated Title After Correlation", "confidence_score": 0.98}
        )
        test_db.save_case(case_id="CASE-TEST-001", report=updated_report)

        retrieved = test_db.get_case("CASE-TEST-001")
        assert retrieved.title == "Updated Title After Correlation"
        assert retrieved.confidence_score == 0.98
        assert test_db.get_case_count() == 1  # No duplicate record created

    def test_list_cases_and_filters(self, test_db, sample_report):
        # Create 3 cases with varying severities and statuses
        r1 = sample_report.model_copy(update={"case_id": "CASE-01", "severity": SeverityLevel.CRITICAL})
        r2 = sample_report.model_copy(update={"case_id": "CASE-02", "severity": SeverityLevel.HIGH})
        r3 = sample_report.model_copy(update={"case_id": "CASE-03", "severity": SeverityLevel.MEDIUM})

        test_db.save_case("CASE-01", r1, status=ReviewStatus.PENDING)
        test_db.save_case("CASE-02", r2, status=ReviewStatus.APPROVED)
        test_db.save_case("CASE-03", r3, status=ReviewStatus.FALSE_POSITIVE)

        assert test_db.get_case_count() == 3

        # Filter by severity
        crit_cases = test_db.list_cases(severity="CRITICAL")
        assert len(crit_cases) == 1
        assert crit_cases[0].case_id == "CASE-01"

        # Filter by status
        approved_cases = test_db.list_cases(status="APPROVED")
        assert len(approved_cases) == 1
        assert approved_cases[0].case_id == "CASE-02"

        # All cases
        all_cases = test_db.list_cases(severity="ALL", status="ALL")
        assert len(all_cases) == 3

    def test_update_case_status_and_notes(self, test_db, sample_report):
        test_db.save_case("CASE-TEST-001", sample_report)

        success = test_db.update_case_status(
            case_id="CASE-TEST-001",
            status=ReviewStatus.ESCALATED,
            notes="Escalated to Tier-3 team for active IP isolation.",
        )
        assert success is True

        retrieved = test_db.get_case("CASE-TEST-001")
        assert retrieved.status == ReviewStatus.ESCALATED.value
        assert "Escalated to Tier-3" in retrieved.analyst_notes

    def test_delete_case(self, test_db, sample_report):
        test_db.save_case("CASE-TEST-001", sample_report)
        assert test_db.get_case_count() == 1

        deleted = test_db.delete_case("CASE-TEST-001")
        assert deleted is True
        assert test_db.get_case_count() == 0
        assert test_db.get_case("CASE-TEST-001") is None

        # Deleting nonexistent returns False
        assert test_db.delete_case("CASE-NONEXISTENT") is False

    def test_get_metrics(self, test_db, sample_report):
        r1 = sample_report.model_copy(update={"case_id": "CASE-01", "severity": SeverityLevel.CRITICAL})
        r2 = sample_report.model_copy(update={"case_id": "CASE-02", "severity": SeverityLevel.HIGH})
        r3 = sample_report.model_copy(update={"case_id": "CASE-03", "severity": SeverityLevel.LOW})

        test_db.save_case("CASE-01", r1, status=ReviewStatus.PENDING)
        test_db.save_case("CASE-02", r2, status=ReviewStatus.ESCALATED)
        test_db.save_case("CASE-03", r3, status=ReviewStatus.FALSE_POSITIVE)

        metrics = test_db.get_metrics()
        assert metrics["total_cases"] == 3
        assert metrics["pending_cases"] == 1
        assert metrics["escalated_cases"] == 1
        assert metrics["false_positives"] == 1
        assert metrics["false_positive_rate"] == 33.3
        assert metrics["critical_cases"] == 1
        assert metrics["high_cases"] == 1

    def test_case_record_to_dict(self, test_db, sample_report):
        rec = test_db.save_case("CASE-TEST-001", sample_report)
        d = rec.to_dict()
        assert d["case_id"] == "CASE-TEST-001"
        assert d["severity"] == "HIGH"
        assert d["confidence_score"] == 0.92
        assert "created_at" in d
