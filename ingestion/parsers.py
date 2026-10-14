"""Log parsers for authentication logs, CSV, and JSON files.

Supports OpenSSH/Linux auth syslog format, structured JSON/JSONL, and CSV.
Includes defense-in-depth checks: file size bounds, record limits, and safe error handling.
"""

import csv
import io
import json
import logging
import re
from datetime import datetime
from typing import Any, Dict, List, Tuple
from config.settings import settings

logger = logging.getLogger(__name__)

# Regular expression for OpenSSH syslog lines
# Example: Dec 10 06:55:46 combo sshd[24206]: Failed password for invalid user admin from 192.168.1.50 port 48312 ssh2
OPENSSH_REGEX = re.compile(
    r"^(?P<month>[A-Za-z]{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<hostname>\S+)\s+"
    r"sshd(?:\[(?P<pid>\d+)\])?:\s+"
    r"(?P<message>.+)$"
)

# Patterns inside the OpenSSH message
PATTERN_FAILED_PWD = re.compile(
    r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3}|[a-fA-F0-9:]+) port (?P<port>\d+)"
)
PATTERN_ACCEPTED_PWD = re.compile(
    r"Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3}|[a-fA-F0-9:]+) port (?P<port>\d+)"
)
PATTERN_INVALID_USER = re.compile(
    r"Invalid user (?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3}|[a-fA-F0-9:]+)"
)
PATTERN_DISCONNECT = re.compile(
    r"(?:Disconnected from|Connection closed by) (?P<ip>\d{1,3}(?:\.\d{1,3}){3}|[a-fA-F0-9:]+)"
)


class IngestionError(Exception):
    """Raised when log ingestion fails due to format or constraint errors."""
    pass


def validate_file_size(content_bytes: bytes, max_mb: int = settings.MAX_FILE_SIZE_MB) -> None:
    """Validate that uploaded content does not exceed allowed file size limits."""
    size_mb = len(content_bytes) / (1024 * 1024)
    if size_mb > max_mb:
        raise IngestionError(
            f"File size ({size_mb:.2f} MB) exceeds maximum allowed limit ({max_mb} MB)."
        )
    if len(content_bytes) == 0:
        raise IngestionError("Uploaded file is empty (0 bytes).")


def parse_openssh_log(
    content: str, source_file: str = "openssh.log", year: int = None
) -> Tuple[List[Dict[str, Any]], List[str]]:
    """Parse raw OpenSSH syslog text into intermediate dictionaries.

    Returns:
        Tuple of (parsed_records, warnings)
    """
    if not year:
        year = datetime.utcnow().year

    records: List[Dict[str, Any]] = []
    warnings: List[str] = []
    lines = content.splitlines()

    if not lines:
        raise IngestionError("Log file contains no lines.")

    for line_num, line in enumerate(lines, start=1):
        line_str = line.strip()
        if not line_str:
            continue

        if len(records) >= settings.MAX_RECORDS_PER_FILE:
            warnings.append(
                f"Truncated ingestion after reaching max limit of {settings.MAX_RECORDS_PER_FILE} records."
            )
            break

        match = OPENSSH_REGEX.match(line_str)
        if not match:
            # Fallback for generic lines that may not match standard syslog header
            warnings.append(f"Line {line_num}: Unrecognized syslog format: '{line_str[:60]}...'")
            continue

        data = match.groupdict()
        month_str = data["month"]
        day_str = data["day"]
        time_str = data["time"]
        hostname = data["hostname"]
        raw_msg = data["message"]

        # Parse timestamp
        timestamp_str = f"{year} {month_str} {day_str.zfill(2)} {time_str}"
        try:
            dt = datetime.strptime(timestamp_str, "%Y %b %d %H:%M:%S")
        except ValueError:
            dt = datetime.utcnow()

        event_type = "generic_ssh"
        outcome = "unknown"
        user = None
        source_ip = None

        m_failed = PATTERN_FAILED_PWD.search(raw_msg)
        m_accepted = PATTERN_ACCEPTED_PWD.search(raw_msg)
        m_invalid = PATTERN_INVALID_USER.search(raw_msg)
        m_disconnect = PATTERN_DISCONNECT.search(raw_msg)

        if m_failed:
            event_type = "failed_login"
            outcome = "failure"
            user = m_failed.group("user")
            source_ip = m_failed.group("ip")
        elif m_accepted:
            event_type = "successful_login"
            outcome = "success"
            user = m_accepted.group("user")
            source_ip = m_accepted.group("ip")
        elif m_invalid:
            event_type = "invalid_user"
            outcome = "failure"
            user = m_invalid.group("user")
            source_ip = m_invalid.group("ip")
        elif m_disconnect:
            event_type = "disconnect"
            outcome = "unknown"
            source_ip = m_disconnect.group("ip")

        records.append({
            "timestamp": dt,
            "source_type": "auth_openssh",
            "hostname": hostname,
            "username": user,
            "source_ip": source_ip,
            "event_type": event_type,
            "outcome": outcome,
            "message": raw_msg,
            "original_record": line_str,
            "source_file": source_file,
            "line_number": line_num,
        })

    return records, warnings


def parse_csv_log(
    content: str, source_file: str = "events.csv"
) -> Tuple[List[Dict[str, Any]], List[str]]:
    """Parse CSV authentication or security log.

    Expects headers or attempts mapping for:
    timestamp, username, source_ip, event_type, outcome, message, hostname.
    """
    records: List[Dict[str, Any]] = []
    warnings: List[str] = []

    f = io.StringIO(content.strip())
    reader = csv.DictReader(f)

    if not reader.fieldnames:
        raise IngestionError("CSV file has no header columns.")

    # Normalize fieldnames to lowercase
    header_map = {fn.strip().lower(): fn for fn in reader.fieldnames}

    for row_num, row in enumerate(reader, start=1):
        if len(records) >= settings.MAX_RECORDS_PER_FILE:
            warnings.append(f"Reached record limit of {settings.MAX_RECORDS_PER_FILE}.")
            break

        def get_val(key_candidates: List[str], default: Any = None) -> Any:
            for c in key_candidates:
                if c in header_map and row.get(header_map[c]):
                    return row[header_map[c]].strip()
            return default

        ts_raw = get_val(["timestamp", "time", "date", "datetime"])
        user = get_val(["username", "user", "account", "src_user"])
        src_ip = get_val(["source_ip", "src_ip", "ip", "client_ip"])
        dest_ip = get_val(["destination_ip", "dest_ip", "dst_ip", "target_ip"])
        hostname = get_val(["hostname", "host", "computer_name"])
        event_type = get_val(["event_type", "type", "action", "event"], "auth_event")
        outcome = get_val(["outcome", "status", "result"], "unknown")
        msg = get_val(["message", "msg", "description"], "CSV security event")

        # Parse timestamp
        dt = None
        if ts_raw:
            for fmt in (
                "%Y-%m-%d %H:%M:%S",
                "%Y-%m-%dT%H:%M:%S",
                "%Y-%m-%dT%H:%M:%SZ",
                "%Y-%m-%d %H:%M:%S.%f",
            ):
                try:
                    dt = datetime.strptime(ts_raw, fmt)
                    break
                except ValueError:
                    continue
        if dt is None:
            dt = datetime.utcnow()
            warnings.append(f"Row {row_num}: Missing/unparseable timestamp. Used UTC now.")

        records.append({
            "timestamp": dt,
            "source_type": "auth_csv",
            "hostname": hostname,
            "username": user,
            "source_ip": src_ip,
            "destination_ip": dest_ip,
            "event_type": event_type.lower(),
            "outcome": outcome.lower(),
            "message": msg,
            "original_record": str(row),
            "source_file": source_file,
            "line_number": row_num,
        })

    return records, warnings


def parse_json_log(
    content: str, source_file: str = "events.json"
) -> Tuple[List[Dict[str, Any]], List[str]]:
    """Parse JSON or JSON Lines (NDJSON) security records."""
    records: List[Dict[str, Any]] = []
    warnings: List[str] = []
    content_clean = content.strip()

    if not content_clean:
        raise IngestionError("JSON content is empty.")

    raw_items = []
    # Check if standard JSON array
    if content_clean.startswith("[") and content_clean.endswith("]"):
        try:
            raw_items = json.loads(content_clean)
        except json.JSONDecodeError as e:
            raise IngestionError(f"Malformed JSON array: {e}")
    else:
        # Try JSON Lines (NDJSON)
        for idx, line in enumerate(content_clean.splitlines(), start=1):
            line_str = line.strip()
            if not line_str:
                continue
            try:
                raw_items.append(json.loads(line_str))
            except json.JSONDecodeError:
                warnings.append(f"Line {idx}: Skipped malformed JSON line.")

    for idx, item in enumerate(raw_items, start=1):
        if not isinstance(item, dict):
            warnings.append(f"Record {idx}: Item is not a JSON object.")
            continue

        ts_raw = item.get("timestamp") or item.get("time") or item.get("datetime")
        dt = None
        if ts_raw and isinstance(ts_raw, str):
            for fmt in (
                "%Y-%m-%d %H:%M:%S",
                "%Y-%m-%dT%H:%M:%S",
                "%Y-%m-%dT%H:%M:%SZ",
                "%Y-%m-%d %H:%M:%S.%f",
            ):
                try:
                    dt = datetime.strptime(ts_raw, fmt)
                    break
                except ValueError:
                    continue
        if dt is None:
            dt = datetime.utcnow()

        records.append({
            "timestamp": dt,
            "source_type": "auth_json",
            "hostname": item.get("hostname"),
            "username": item.get("username") or item.get("user"),
            "source_ip": item.get("source_ip") or item.get("src_ip"),
            "destination_ip": item.get("destination_ip") or item.get("dest_ip"),
            "event_type": str(item.get("event_type") or item.get("action") or "json_event").lower(),
            "outcome": str(item.get("outcome") or item.get("status") or "unknown").lower(),
            "message": str(item.get("message") or item.get("msg") or "JSON event"),
            "original_record": json.dumps(item),
            "source_file": source_file,
            "line_number": idx,
        })

    return records, warnings
