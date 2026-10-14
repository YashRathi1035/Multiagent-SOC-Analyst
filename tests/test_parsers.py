"""Unit tests for log parsing and normalization modules."""

import pytest
from ingestion.parsers import (
    IngestionError,
    parse_csv_log,
    parse_json_log,
    parse_openssh_log,
    validate_file_size,
)
from ingestion.normalize import normalize_events, sanitize_text
from models.schemas import EventOutcome


def test_parse_openssh_valid_lines():
    sample = (
        "Dec 10 06:55:46 combo sshd[24206]: Failed password for invalid user admin from 187.141.143.180 port 48312 ssh2\n"
        "Dec 10 07:07:38 combo sshd[24245]: Accepted password for fztu from 116.231.72.68 port 51179 ssh2\n"
        "Dec 10 09:32:00 combo sshd[24649]: Invalid user test from 192.168.1.100\n"
    )
    records, warnings = parse_openssh_log(sample, year=2026)

    assert len(records) == 3
    assert records[0]["event_type"] == "failed_login"
    assert records[0]["username"] == "admin"
    assert records[0]["source_ip"] == "187.141.143.180"
    assert records[0]["outcome"] == "failure"

    assert records[1]["event_type"] == "successful_login"
    assert records[1]["username"] == "fztu"
    assert records[1]["source_ip"] == "116.231.72.68"
    assert records[1]["outcome"] == "success"

    assert records[2]["event_type"] == "invalid_user"
    assert records[2]["username"] == "test"
    assert records[2]["source_ip"] == "192.168.1.100"


def test_parse_openssh_empty_and_garbage():
    with pytest.raises(IngestionError):
        parse_openssh_log("")

    # Unrecognized lines should produce warnings, not crash
    garbage = "This is a random line not matching sshd format\nAnother line"
    records, warnings = parse_openssh_log(garbage, year=2026)
    assert len(records) == 0
    assert len(warnings) == 2


def test_parse_csv_log():
    csv_data = (
        "timestamp,username,source_ip,event_type,outcome,message\n"
        "2026-10-13 12:00:00,alice,10.0.0.1,login,success,Login OK\n"
        "2026-10-13 12:01:00,bob,10.0.0.2,login,failure,Password bad\n"
    )
    records, warnings = parse_csv_log(csv_data)
    assert len(records) == 2
    assert records[0]["username"] == "alice"
    assert records[0]["outcome"] == "success"
    assert records[1]["username"] == "bob"
    assert records[1]["outcome"] == "failure"


def test_parse_json_log():
    json_data = (
        '[{"timestamp": "2026-10-13T12:00:00Z", "username": "admin", "source_ip": "1.2.3.4", '
        '"event_type": "auth", "outcome": "failure", "message": "Denied"}]'
    )
    records, warnings = parse_json_log(json_data)
    assert len(records) == 1
    assert records[0]["username"] == "admin"
    assert records[0]["source_ip"] == "1.2.3.4"


def test_normalize_events_and_sanitize():
    raw = [{
        "timestamp": "2026-10-13 12:00:00",
        "username": "admin\r\n; DROP TABLE users; ",
        "source_ip": "192.168.1.1",
        "event_type": "failed_login",
        "outcome": "failure",
        "message": "Failed password\nwith injected newline",
        "original_record": "raw log",
        "source_type": "auth_test",
    }]
    events, warnings = normalize_events(raw)
    assert len(events) == 1
    evt = events[0]
    assert evt.event_id.startswith("EVT-")
    assert "\r" not in evt.username
    assert "\n" not in evt.username
    assert "\n" not in evt.message
    assert evt.outcome == EventOutcome.FAILURE


def test_validate_file_size():
    with pytest.raises(IngestionError):
        validate_file_size(b"")

    large_bytes = b"X" * (11 * 1024 * 1024)  # 11 MB
    with pytest.raises(IngestionError):
        validate_file_size(large_bytes, max_mb=10)
