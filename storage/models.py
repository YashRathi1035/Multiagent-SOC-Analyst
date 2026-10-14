"""SQLAlchemy ORM models for SQLite Case Persistence (Phase 6).

Defines the CaseRecord schema for storing investigation cases, detection alerts,
full LLM reports, analyst notes, and human-in-the-loop review statuses.
"""

from datetime import datetime
import json
from typing import Any, Dict, Optional
from sqlalchemy import DateTime, Float, Integer, String, Text, func
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from models.schemas import InvestigationReport, ReviewStatus, SeverityLevel


class Base(DeclarativeBase):
    """Base class for all SQLAlchemy ORM models."""
    pass


class CaseRecord(Base):
    """Database record representing an investigated SOC case."""

    __tablename__ = "soc_cases"

    case_id: Mapped[str] = mapped_column(String(64), primary_key=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow
    )
    raw_filename: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    alert_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    rule_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    severity: Mapped[str] = mapped_column(String(32), index=True)
    incident_type: Mapped[str] = mapped_column(String(128))
    title: Mapped[str] = mapped_column(String(255))
    confidence_score: Mapped[float] = mapped_column(Float, default=0.0)
    status: Mapped[str] = mapped_column(String(32), default=ReviewStatus.PENDING.value, index=True)
    analyst_notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    source_ip: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    affected_user: Mapped[Optional[str]] = mapped_column(String(128), nullable=True, index=True)
    event_count: Mapped[int] = mapped_column(Integer, default=0)
    report_json: Mapped[str] = mapped_column(Text, comment="Serialized InvestigationReport JSON")
    soc_state_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True, comment="Serialized SOCState JSON")

    def to_dict(self) -> Dict[str, Any]:
        """Convert record to dictionary for display and DataFrame consumption."""
        return {
            "case_id": self.case_id,
            "created_at": self.created_at.strftime("%Y-%m-%d %H:%M:%S") if self.created_at else "",
            "raw_filename": self.raw_filename or "N/A",
            "alert_id": self.alert_id or "N/A",
            "rule_id": self.rule_id or "N/A",
            "severity": self.severity,
            "incident_type": self.incident_type,
            "title": self.title,
            "confidence_score": round(self.confidence_score, 2),
            "status": self.status,
            "analyst_notes": self.analyst_notes or "",
            "source_ip": self.source_ip or "N/A",
            "affected_user": self.affected_user or "N/A",
            "event_count": self.event_count,
        }

    def get_report(self) -> Optional[InvestigationReport]:
        """Deserialize stored report_json into a validated InvestigationReport object."""
        try:
            data = json.loads(self.report_json)
            return InvestigationReport.model_validate(data)
        except Exception:
            return None
