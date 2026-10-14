"""Deterministic detection rules for authentication security logs.

Implements core cybersecurity detection logic using sliding time windows:
1. RULE-AUTH-001: Repeated Failed Logins (Brute Force / Password Guessing)
2. RULE-AUTH-002: Failed Login Followed by Successful Login (Potential Credential Compromise)
3. RULE-AUTH-003: User Enumeration / Multi-Account Spraying
"""

import uuid
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Dict, List, Set
from config.settings import settings
from models.schemas import DetectionAlert, EventOutcome, LogEvent, SeverityLevel


class DetectionEngine:
    """Deterministic rule-based detector for normalized security events."""

    def __init__(
        self,
        brute_force_threshold: int = settings.BRUTE_FORCE_THRESHOLD,
        brute_force_window_minutes: int = settings.BRUTE_FORCE_WINDOW_MINUTES,
        failed_then_success_window_minutes: int = settings.FAILED_THEN_SUCCESS_WINDOW_MINUTES,
        user_enumeration_threshold: int = settings.USER_ENUMERATION_THRESHOLD,
    ):
        self.brute_force_threshold = brute_force_threshold
        self.brute_force_window = timedelta(minutes=brute_force_window_minutes)
        self.failed_then_success_window = timedelta(minutes=failed_then_success_window_minutes)
        self.user_enumeration_threshold = user_enumeration_threshold

    def run_all_rules(self, events: List[LogEvent], include_ml: bool = False) -> List[DetectionAlert]:
        """Execute all configured detection rules against normalized events."""
        alerts: List[DetectionAlert] = []

        if not events:
            return alerts

        # Sort events chronologically to support sliding window analysis
        sorted_events = sorted(events, key=lambda e: e.timestamp)

        alerts.extend(self._detect_brute_force(sorted_events))
        alerts.extend(self._detect_failed_then_success(sorted_events))
        alerts.extend(self._detect_user_enumeration(sorted_events))

        if include_ml:
            alerts.extend(self.run_ml_detection(sorted_events))

        return alerts

    def run_ml_detection(self, events: List[LogEvent]) -> List[DetectionAlert]:
        """Execute machine learning anomaly detection and attack classification."""
        try:
            from ml.detector import MLDetector
            detector = MLDetector()
            return detector.detect_alerts(events)
        except Exception as e:
            import logging
            logging.getLogger("detection_engine").warning("ML detection error: %s", e)
            return []

    def _detect_brute_force(self, events: List[LogEvent]) -> List[DetectionAlert]:
        """Detect repeated failed authentication attempts from the same source IP."""
        alerts: List[DetectionAlert] = []

        # Group failures by source IP
        ip_failures: Dict[str, List[LogEvent]] = defaultdict(list)
        for event in events:
            if event.outcome == EventOutcome.FAILURE and event.source_ip:
                ip_failures[event.source_ip].append(event)

        for src_ip, fail_events in ip_failures.items():
            if len(fail_events) < self.brute_force_threshold:
                continue

            # Sliding window over failures
            i = 0
            while i < len(fail_events):
                window_start = fail_events[i].timestamp
                window_end = window_start + self.brute_force_window

                window_events = [e for e in fail_events[i:] if e.timestamp <= window_end]

                if len(window_events) >= self.brute_force_threshold:
                    target_users = list({e.username for e in window_events if e.username})
                    event_ids = [e.event_id for e in window_events]
                    attempt_count = len(window_events)

                    # Assess severity
                    has_privileged = any(
                        u.lower() in ("root", "admin", "administrator") for u in target_users
                    )
                    if attempt_count >= 15 or has_privileged:
                        severity = SeverityLevel.HIGH
                        rationale = (
                            f"{attempt_count} failed login attempts from {src_ip} within "
                            f"{self.brute_force_window.total_seconds() / 60:.0f}m, "
                            f"targeting {'privileged user ' + ', '.join(target_users) if has_privileged else 'users'}. High threat severity."
                        )
                    else:
                        severity = SeverityLevel.MEDIUM
                        rationale = (
                            f"{attempt_count} failed login attempts from {src_ip} within "
                            f"{self.brute_force_window.total_seconds() / 60:.0f}m exceeds threshold of {self.brute_force_threshold}."
                        )

                    alert = DetectionAlert(
                        alert_id=f"ALT-{uuid.uuid4().hex[:8].upper()}",
                        rule_id="RULE-AUTH-001",
                        rule_name="Repeated Authentication Failures (Brute-Force)",
                        severity=severity,
                        description=f"Detected {attempt_count} authentication failures originating from IP {src_ip}.",
                        triggering_event_ids=event_ids,
                        affected_user=target_users[0] if len(target_users) == 1 else "multiple_users",
                        source_ip=src_ip,
                        detection_timestamp=datetime.utcnow(),
                        severity_rationale=rationale,
                        evidence_summary={
                            "attempt_count": attempt_count,
                            "targeted_users": target_users,
                            "window_minutes": self.brute_force_window.total_seconds() / 60,
                            "first_seen": window_events[0].timestamp.isoformat(),
                            "last_seen": window_events[-1].timestamp.isoformat(),
                        },
                        mitre_candidates=["T1110.001 - Password Guessing", "T1110 - Brute Force"],
                    )
                    alerts.append(alert)
                    # Advance past this cluster
                    i += len(window_events)
                else:
                    i += 1

        return alerts

    def _detect_failed_then_success(self, events: List[LogEvent]) -> List[DetectionAlert]:
        """Detect one or more failed logins followed by a successful login for the same user or IP."""
        alerts: List[DetectionAlert] = []

        # Group events by user and by source IP
        user_timeline: Dict[str, List[LogEvent]] = defaultdict(list)
        for event in events:
            if event.username:
                user_timeline[event.username].append(event)

        for user, u_events in user_timeline.items():
            recent_failures: List[LogEvent] = []

            for event in u_events:
                if event.outcome == EventOutcome.FAILURE:
                    recent_failures.append(event)
                elif event.outcome == EventOutcome.SUCCESS:
                    # Check if there were recent failures within the window
                    valid_failures = [
                        f
                        for f in recent_failures
                        if (event.timestamp - f.timestamp) <= self.failed_then_success_window
                    ]

                    if len(valid_failures) >= 2:
                        # Prior failures succeeded! High probability of credential compromise
                        all_event_ids = [f.event_id for f in valid_failures] + [event.event_id]
                        src_ip = event.source_ip or (valid_failures[0].source_ip if valid_failures else None)

                        is_admin = user.lower() in ("root", "admin", "administrator")
                        severity = SeverityLevel.CRITICAL if is_admin else SeverityLevel.HIGH

                        rationale = (
                            f"{len(valid_failures)} failed login attempts followed by a successful login for "
                            f"account '{user}' from {src_ip} within {self.failed_then_success_window.total_seconds() / 60:.0f}m. "
                            f"Strong indicator of successful password cracking or unauthorized access."
                        )

                        alert = DetectionAlert(
                            alert_id=f"ALT-{uuid.uuid4().hex[:8].upper()}",
                            rule_id="RULE-AUTH-002",
                            rule_name="Failed Logins Followed by Successful Login",
                            severity=severity,
                            description=f"Account '{user}' suffered {len(valid_failures)} failed logins before succeeding.",
                            triggering_event_ids=all_event_ids,
                            affected_user=user,
                            source_ip=src_ip,
                            detection_timestamp=datetime.utcnow(),
                            severity_rationale=rationale,
                            evidence_summary={
                                "failed_attempts_before_success": len(valid_failures),
                                "successful_event_id": event.event_id,
                                "success_timestamp": event.timestamp.isoformat(),
                                "first_failure_timestamp": valid_failures[0].timestamp.isoformat(),
                                "compromised_user": user,
                            },
                            mitre_candidates=[
                                "T1078 - Valid Accounts",
                                "T1110.001 - Password Guessing",
                            ],
                        )
                        alerts.append(alert)

                    # Reset failures after a successful event
                    recent_failures = []

        return alerts

    def _detect_user_enumeration(self, events: List[LogEvent]) -> List[DetectionAlert]:
        """Detect a single source IP attempting logins across multiple distinct usernames."""
        alerts: List[DetectionAlert] = []

        ip_events: Dict[str, List[LogEvent]] = defaultdict(list)
        for event in events:
            if event.source_ip and event.outcome == EventOutcome.FAILURE:
                ip_events[event.source_ip].append(event)

        for src_ip, fail_events in ip_events.items():
            # Check unique users targeted in sliding window
            i = 0
            while i < len(fail_events):
                window_start = fail_events[i].timestamp
                window_end = window_start + self.brute_force_window

                window_events = [e for e in fail_events[i:] if e.timestamp <= window_end]
                unique_users: Set[str] = {
                    e.username for e in window_events if e.username and e.username.strip()
                }

                if len(unique_users) >= self.user_enumeration_threshold:
                    event_ids = [e.event_id for e in window_events]
                    alert = DetectionAlert(
                        alert_id=f"ALT-{uuid.uuid4().hex[:8].upper()}",
                        rule_id="RULE-AUTH-003",
                        rule_name="User Enumeration / Account Spraying",
                        severity=SeverityLevel.MEDIUM,
                        description=(
                            f"Source IP {src_ip} targeted {len(unique_users)} distinct usernames "
                            f"in a single time window."
                        ),
                        triggering_event_ids=event_ids,
                        affected_user="multiple_accounts",
                        source_ip=src_ip,
                        detection_timestamp=datetime.utcnow(),
                        severity_rationale=(
                            f"IP {src_ip} attempted authentication across {len(unique_users)} distinct accounts "
                            f"({', '.join(list(unique_users)[:5])}), indicating systematic username discovery or spraying."
                        ),
                        evidence_summary={
                            "distinct_user_count": len(unique_users),
                            "targeted_users": list(unique_users),
                            "attempt_count": len(window_events),
                        },
                        mitre_candidates=[
                            "T1110.003 - Password Spraying",
                            "T1087.001 - Account Discovery: Local Accounts",
                        ],
                    )
                    alerts.append(alert)
                    i += len(window_events)
                else:
                    i += 1

        return alerts
