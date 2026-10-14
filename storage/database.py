"""Database manager for SQLite Case Persistence (Phase 6).

Provides thread-safe persistence, retrieval, status updates, and metrics
for SOC investigation cases using SQLAlchemy.
"""

from datetime import datetime
import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional
from sqlalchemy import create_engine, desc, select
from sqlalchemy.orm import Session, sessionmaker

from config.settings import settings
from models.schemas import InvestigationReport, ReviewStatus
from storage.models import Base, CaseRecord

logger = logging.getLogger("storage.database")


class DatabaseManager:
    """Manages SQLite database connections and case record operations."""

    def __init__(self, db_url: Optional[str] = None):
        self.db_url = db_url or settings.DATABASE_URL

        # Ensure sqlite parent directory exists if using file path
        if self.db_url.startswith("sqlite:///"):
            file_path = self.db_url.replace("sqlite:///", "")
            if file_path != ":memory:":
                Path(file_path).parent.mkdir(parents=True, exist_ok=True)

        self.engine = create_engine(
            self.db_url,
            connect_args={"check_same_thread": False} if self.db_url.startswith("sqlite") else {},
            echo=False,
        )
        self.SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=self.engine)

        # Initialize schema tables
        Base.metadata.create_all(bind=self.engine)
        logger.info("Initialized SOC database schema at %s", self.db_url)

    def get_session(self) -> Session:
        """Provide a new SQLAlchemy session."""
        return self.SessionLocal()

    def save_case(
        self,
        case_id: str,
        report: InvestigationReport,
        raw_filename: Optional[str] = None,
        state: Optional[Dict[str, Any]] = None,
        status: ReviewStatus = ReviewStatus.PENDING,
        analyst_notes: Optional[str] = None,
    ) -> CaseRecord:
        """Insert or update an investigation case record."""
        with self.get_session() as session:
            # Check for existing record
            record = session.get(CaseRecord, case_id)

            # Determine source IP and affected user from report indicators
            source_ip = None
            affected_user = None
            if report.relevant_indicators:
                for ind in report.relevant_indicators:
                    # Simple IPv4 check
                    parts = ind.split(".")
                    if len(parts) == 4 and all(p.isdigit() for p in parts):
                        if not source_ip:
                            source_ip = ind
                    elif not affected_user and len(ind) < 64:
                        affected_user = ind

            # Check state for more exact data if available
            event_count = len(report.triggering_events)
            if state:
                if state.get("normalized_events"):
                    event_count = len(state["normalized_events"])
                if state.get("selected_alert"):
                    alert = state["selected_alert"]
                    if getattr(alert, "source_ip", None):
                        source_ip = alert.source_ip
                    if getattr(alert, "affected_user", None):
                        affected_user = alert.affected_user

            state_json = json.dumps(
                {
                    "log_findings": state.get("log_analysis_findings", {}),
                    "knowledge_count": len(state.get("retrieved_knowledge", [])),
                    "timeline_length": len(state.get("timeline", [])),
                    "errors": state.get("errors", []),
                }
            ) if state else None

            if record is None:
                record = CaseRecord(
                    case_id=case_id,
                    created_at=datetime.utcnow(),
                    updated_at=datetime.utcnow(),
                    raw_filename=raw_filename,
                    alert_id=report.alert_id,
                    rule_id=getattr(report, "rule_id", "RULE-AUTH-001"),
                    severity=report.severity.value,
                    incident_type=report.incident_type,
                    title=report.title,
                    confidence_score=report.confidence_score,
                    status=status.value if isinstance(status, ReviewStatus) else str(status),
                    analyst_notes=analyst_notes,
                    source_ip=source_ip,
                    affected_user=affected_user,
                    event_count=event_count,
                    report_json=report.model_dump_json(indent=2),
                    soc_state_json=state_json,
                )
                session.add(record)
            else:
                record.updated_at = datetime.utcnow()
                record.raw_filename = raw_filename or record.raw_filename
                record.alert_id = report.alert_id
                record.severity = report.severity.value
                record.incident_type = report.incident_type
                record.title = report.title
                record.confidence_score = report.confidence_score
                record.source_ip = source_ip or record.source_ip
                record.affected_user = affected_user or record.affected_user
                record.event_count = event_count
                record.report_json = report.model_dump_json(indent=2)
                if analyst_notes is not None:
                    record.analyst_notes = analyst_notes
                if state_json is not None:
                    record.soc_state_json = state_json

            session.commit()
            session.refresh(record)
            logger.info("Successfully persisted case %s (Status: %s)", case_id, record.status)
            return record

    def get_case(self, case_id: str) -> Optional[CaseRecord]:
        """Retrieve a specific case by case_id."""
        with self.get_session() as session:
            record = session.get(CaseRecord, case_id)
            if record:
                session.expunge(record)
            return record

    def list_cases(
        self,
        limit: int = 100,
        severity: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[CaseRecord]:
        """List cases ordered by creation date descending with optional filtering."""
        with self.get_session() as session:
            stmt = select(CaseRecord).order_by(desc(CaseRecord.created_at)).limit(limit)

            if severity and severity.upper() != "ALL":
                stmt = stmt.where(CaseRecord.severity == severity.upper())

            if status and status.upper() != "ALL":
                stmt = stmt.where(CaseRecord.status == status.upper())

            records = list(session.scalars(stmt).all())
            for r in records:
                session.expunge(r)
            return records

    def update_case_status(
        self,
        case_id: str,
        status: ReviewStatus,
        notes: Optional[str] = None,
    ) -> bool:
        """Update review status and append/set analyst notes for a case."""
        with self.get_session() as session:
            record = session.get(CaseRecord, case_id)
            if not record:
                return False

            record.status = status.value if isinstance(status, ReviewStatus) else str(status)
            record.updated_at = datetime.utcnow()
            if notes is not None:
                record.analyst_notes = notes

            session.commit()
            logger.info("Updated case %s to status %s", case_id, record.status)
            return True

    def delete_case(self, case_id: str) -> bool:
        """Delete a case by case_id."""
        with self.get_session() as session:
            record = session.get(CaseRecord, case_id)
            if not record:
                return False

            session.delete(record)
            session.commit()
            logger.info("Deleted case %s", case_id)
            return True

    def get_case_count(self) -> int:
        """Return total count of cases in database."""
        with self.get_session() as session:
            return session.query(CaseRecord).count()

    def get_metrics(self) -> Dict[str, Any]:
        """Compute aggregated metrics across stored cases."""
        with self.get_session() as session:
            records = session.scalars(select(CaseRecord)).all()
            total = len(records)
            pending = sum(1 for r in records if r.status == ReviewStatus.PENDING.value)
            approved = sum(1 for r in records if r.status == ReviewStatus.APPROVED.value)
            escalated = sum(1 for r in records if r.status == ReviewStatus.ESCALATED.value)
            false_positives = sum(1 for r in records if r.status == ReviewStatus.FALSE_POSITIVE.value)

            critical = sum(1 for r in records if r.severity == "CRITICAL")
            high = sum(1 for r in records if r.severity == "HIGH")

            fp_rate = (false_positives / total * 100) if total > 0 else 0.0

            return {
                "total_cases": total,
                "pending_cases": pending,
                "approved_cases": approved,
                "escalated_cases": escalated,
                "false_positives": false_positives,
                "false_positive_rate": round(fp_rate, 1),
                "critical_cases": critical,
                "high_cases": high,
            }


# Global singleton instance
_default_db: Optional[DatabaseManager] = None


def get_db(db_url: Optional[str] = None) -> DatabaseManager:
    """Get or create singleton DatabaseManager instance."""
    global _default_db
    if db_url is not None:
        return DatabaseManager(db_url)
    if _default_db is None:
        _default_db = DatabaseManager()
    return _default_db
