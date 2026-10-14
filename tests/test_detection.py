"""Unit tests for rule-based detection engine."""

from data.test_cases.scenarios import (
    SYNTHETIC_BENIGN_LOG,
    SYNTHETIC_BRUTE_FORCE_LOG,
    SYNTHETIC_FAILED_THEN_SUCCESS_LOG,
)
from detection.rules import DetectionEngine
from ingestion.parsers import parse_openssh_log
from ingestion.normalize import normalize_events
from models.schemas import SeverityLevel


def test_brute_force_detection():
    records, _ = parse_openssh_log(SYNTHETIC_BRUTE_FORCE_LOG, year=2026)
    events, _ = normalize_events(records)

    engine = DetectionEngine(brute_force_threshold=5, brute_force_window_minutes=10)
    alerts = engine.run_all_rules(events)

    # Should detect brute force on root
    bf_alerts = [a for a in alerts if a.rule_id == "RULE-AUTH-001"]
    assert len(bf_alerts) >= 1
    alert = bf_alerts[0]
    assert alert.source_ip == "198.51.100.99"
    assert alert.severity == SeverityLevel.HIGH  # root account triggers HIGH
    assert len(alert.triggering_event_ids) >= 5
    assert "T1110.001 - Password Guessing" in alert.mitre_candidates


def test_failed_then_success_detection():
    records, _ = parse_openssh_log(SYNTHETIC_FAILED_THEN_SUCCESS_LOG, year=2026)
    events, _ = normalize_events(records)

    engine = DetectionEngine()
    alerts = engine.run_all_rules(events)

    fts_alerts = [a for a in alerts if a.rule_id == "RULE-AUTH-002"]
    assert len(fts_alerts) >= 1
    alert = fts_alerts[0]
    assert alert.affected_user == "bob"
    assert alert.source_ip == "192.0.2.77"
    assert len(alert.triggering_event_ids) == 3  # 2 fails + 1 success


def test_benign_traffic_no_alerts():
    records, _ = parse_openssh_log(SYNTHETIC_BENIGN_LOG, year=2026)
    events, _ = normalize_events(records)

    engine = DetectionEngine()
    alerts = engine.run_all_rules(events)

    assert len(alerts) == 0


def test_user_enumeration_detection():
    log = (
        "Dec 10 10:00:00 srv sshd[1]: Failed password for invalid user u1 from 192.168.5.5 port 10 ssh2\n"
        "Dec 10 10:00:02 srv sshd[2]: Failed password for invalid user u2 from 192.168.5.5 port 11 ssh2\n"
        "Dec 10 10:00:04 srv sshd[3]: Failed password for invalid user u3 from 192.168.5.5 port 12 ssh2\n"
    )
    records, _ = parse_openssh_log(log, year=2026)
    events, _ = normalize_events(records)

    engine = DetectionEngine(user_enumeration_threshold=3)
    alerts = engine.run_all_rules(events)

    enum_alerts = [a for a in alerts if a.rule_id == "RULE-AUTH-003"]
    assert len(enum_alerts) >= 1
    assert enum_alerts[0].source_ip == "192.168.5.5"
    assert enum_alerts[0].evidence_summary["distinct_user_count"] == 3
