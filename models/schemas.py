"""Core Pydantic models for the Multi-Agent SOC Analyst.

Defines schemas for normalized security events, rule-based alerts,
investigation findings, and structured incident reports.
"""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class EventOutcome(str, Enum):
    """Normalized outcome of a security event."""
    SUCCESS = "success"
    FAILURE = "failure"
    UNKNOWN = "unknown"


class SeverityLevel(str, Enum):
    """Standardized SOC severity levels."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ReviewStatus(str, Enum):
    """Status of analyst human-in-the-loop review."""
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    ESCALATED = "ESCALATED"
    FALSE_POSITIVE = "FALSE_POSITIVE"


class LogEvent(BaseModel):
    """Normalized security log event."""
    event_id: str = Field(..., description="Unique identifier for the normalized event")
    timestamp: datetime = Field(..., description="Timestamp of the event in UTC or local timezone")
    source_type: str = Field(..., description="Origin format: auth_openssh, auth_csv, auth_json")
    username: Optional[str] = Field(None, description="Username associated with the event")
    source_ip: Optional[str] = Field(None, description="Source IP address")
    destination_ip: Optional[str] = Field(None, description="Destination IP address")
    hostname: Optional[str] = Field(None, description="Hostname where event occurred")
    event_type: str = Field(
        ...,
        description="Categorized event type (e.g., failed_login, successful_login, invalid_user)",
    )
    outcome: EventOutcome = Field(
        default=EventOutcome.UNKNOWN,
        description="Outcome of the event: success, failure, or unknown",
    )
    message: str = Field(..., description="Sanitized original message content")
    original_record: str = Field(..., description="Raw unmodified log line for forensic audit")
    source_file: Optional[str] = Field(None, description="Source file name or origin")


class DetectionAlert(BaseModel):
    """Structured security alert emitted by rule-based or ML detectors."""
    alert_id: str = Field(..., description="Unique alert identifier")
    rule_id: str = Field(..., description="Identifier of the triggering rule (e.g., RULE-001)")
    rule_name: str = Field(..., description="Human-readable rule name")
    severity: SeverityLevel = Field(..., description="Assessed severity level")
    description: str = Field(..., description="Summary of the detected behavior")
    triggering_event_ids: List[str] = Field(
        default_factory=list,
        description="Exact IDs of log events that satisfied the rule logic",
    )
    affected_user: Optional[str] = Field(None, description="Targeted or affected username")
    source_ip: Optional[str] = Field(None, description="Originating source IP address")
    detection_timestamp: datetime = Field(
        default_factory=datetime.utcnow,
        description="Timestamp when detection triggered",
    )
    severity_rationale: str = Field(..., description="Deterministic justification for the severity")
    evidence_summary: Dict[str, Any] = Field(
        default_factory=dict,
        description="Summary metrics (e.g., attempt count, time window, distinct IPs)",
    )
    mitre_candidates: List[str] = Field(
        default_factory=list,
        description="Initial MITRE ATT&CK technique IDs associated with this rule",
    )


class MitreTechniqueMapping(BaseModel):
    """Mapping of an observed behavior to a MITRE ATT&CK technique."""
    technique_id: str = Field(..., description="Technique ID (e.g., T1110.001)")
    technique_name: str = Field(..., description="Technique name (e.g., Password Guessing)")
    evidence: str = Field(..., description="Specific observed evidence supporting this mapping")


class ThreatIntelResult(BaseModel):
    """External reputation intelligence for an indicator of compromise."""
    indicator: str = Field(..., description="IP address, domain, or hash")
    indicator_type: str = Field(..., description="'ipv4', 'ipv6', 'domain', 'sha256'")
    provider: str = Field(..., description="Source provider name ('MockThreatIntel', 'AbuseIPDB', 'VirusTotal')")
    reputation_score: float = Field(
        default=0.0, ge=0.0, le=100.0, description="Abuse confidence or malicious percentage (0-100)"
    )
    is_malicious: bool = Field(default=False, description="Flag indicating high likelihood of malicious reputation")
    threat_category: Optional[str] = Field(
        None, description="Category: 'Brute-Force', 'Botnet', 'Scanner', 'Clean', 'Private Network'"
    )
    total_reports: int = Field(default=0, description="Number of malicious reports logged by community")
    last_reported_at: Optional[str] = Field(None, description="ISO timestamp of last reported attack")
    country_code: Optional[str] = Field(None, description="Origin country code")
    isp: Optional[str] = Field(None, description="Internet Service Provider or ASN")
    source_url: Optional[str] = Field(None, description="Link to provider intelligence page")
    retrieval_timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    error_message: Optional[str] = Field(None, description="Error details if lookup failed")

class MLAnomalyResult(BaseModel):
    """Structured result from machine learning anomaly detection or attack classification."""
    entity: str = Field(..., description="Target entity evaluated (e.g., source IP, username, or session ID)")
    is_anomaly: bool = Field(..., description="True if IsolationForest or model flags the behavior as anomalous")
    anomaly_score: float = Field(..., description="Continuous anomaly score (0.0=normal, 1.0=extreme anomaly)")
    predicted_class: str = Field(default="normal", description="Predicted classification (e.g., 'normal', 'brute_force', 'compromise')")
    confidence: float = Field(default=0.0, ge=0.0, le=1.0, description="Confidence of the predicted class")
    algorithm: str = Field(default="IsolationForest", description="Algorithm used ('IsolationForest', 'RandomForest')")
    contributing_features: Dict[str, float] = Field(default_factory=dict, description="Key features contributing to the anomaly score")
    triggering_event_ids: List[str] = Field(default_factory=list, description="IDs of events associated with this entity/session")


class InvestigationReport(BaseModel):
    """Evidence-grounded structured incident report validated by Pydantic."""
    case_id: str = Field(..., description="Unique identifier for the investigation case")
    alert_id: str = Field(..., description="Associated detection alert ID")
    title: str = Field(..., description="Executive title of the incident report")
    incident_type: str = Field(..., description="Classification of incident (e.g., SSH Brute-Force)")
    severity: SeverityLevel = Field(..., description="Final incident severity")
    severity_rationale: str = Field(..., description="Evidence-backed rationale for severity")
    confidence_score: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Confidence between 0.0 (unsubstantiated) and 1.0 (verified factual)",
    )
    confidence_rationale: str = Field(..., description="Meaning and bounds of the confidence score")
    summary: str = Field(..., description="Executive summary of the investigation findings")
    observed_facts: List[str] = Field(
        default_factory=list,
        description="Directly observed facts tied to verifiable log records",
    )
    inferred_conclusions: List[str] = Field(
        default_factory=list,
        description="Analytical hypotheses and deductions derived from facts",
    )
    triggering_events: List[str] = Field(
        default_factory=list,
        description="Verified event IDs supporting this finding",
    )
    relevant_indicators: List[str] = Field(
        default_factory=list,
        description="Extracted IOCs (IPs, usernames, hostnames)",
    )
    mitre_techniques: List[MitreTechniqueMapping] = Field(
        default_factory=list,
        description="Applicable MITRE ATT&CK techniques with supporting evidence",
    )
    retrieved_knowledge: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Retrieved cybersecurity knowledge excerpts and citations used during investigation",
    )
    threat_intel_results: List[ThreatIntelResult] = Field(
        default_factory=list,
        description="External threat intelligence enrichment records for case indicators",
    )
    alternative_explanations: List[str] = Field(
        default_factory=list,
        description="Benign or alternate possibilities (e.g., user misconfiguration, admin automation)",
    )
    investigation_limitations: List[str] = Field(
        default_factory=list,
        description="Known visibility gaps or missing telemetry",
    )
    recommended_actions: List[str] = Field(
        default_factory=list,
        description="Actionable containment, eradication, and verification steps",
    )
    analyst_review_status: ReviewStatus = Field(
        default=ReviewStatus.PENDING,
        description="Current review status by human security analyst",
    )
    created_at: str = Field(
        default_factory=lambda: datetime.utcnow().isoformat(),
        description="ISO timestamp of report creation",
    )


class InvestigationState(BaseModel):
    """Shared investigation state for multi-agent orchestration."""
    case_id: str
    created_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    raw_filename: Optional[str] = None
    normalized_events: List[LogEvent] = Field(default_factory=list)
    alerts: List[DetectionAlert] = Field(default_factory=list)
    selected_alert: Optional[DetectionAlert] = None
    extracted_indicators: List[str] = Field(default_factory=list)
    log_analysis_findings: Dict[str, Any] = Field(default_factory=dict)
    threat_intel_results: Dict[str, Any] = Field(default_factory=dict)
    retrieved_knowledge: List[Dict[str, Any]] = Field(default_factory=list)
    candidate_mitre_mappings: List[MitreTechniqueMapping] = Field(default_factory=list)
    timeline: List[Dict[str, Any]] = Field(default_factory=list)
    final_report: Optional[InvestigationReport] = None
    errors: List[str] = Field(default_factory=list)
    review_status: ReviewStatus = ReviewStatus.PENDING
