"""Event normalization pipeline.

Transforms parsed dictionary records into validated, strongly typed
LogEvent objects, sanitizing fields to prevent delimiter escape and prompt injection.
"""

import hashlib
import logging
import re
from typing import Any, Dict, List, Set, Tuple
from models.schemas import EventOutcome, LogEvent

logger = logging.getLogger(__name__)

# Disallowed control characters and potential delimiter breaking sequences
CONTROL_CHARS_PATTERN = re.compile(r"[\r\n\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def sanitize_text(text: Any, max_length: int = 500) -> str:
    """Sanitize raw text strings to prevent delimiter escapes and control character abuse."""
    if text is None:
        return ""
    s = str(text)
    # Remove raw carriage returns, newlines, null bytes
    s = CONTROL_CHARS_PATTERN.sub(" ", s)
    # Collapse multiple whitespaces
    s = re.sub(r"\s+", " ", s).strip()
    return s[:max_length]


def generate_event_id(record: Dict[str, Any], index: int) -> str:
    """Generate a consistent event identifier.

    Uses a deterministic prefix and hash or sequence for reproducible investigations.
    """
    ts_str = str(record.get("timestamp", ""))
    msg = str(record.get("message", ""))
    raw = str(record.get("original_record", ""))
    seed = f"{ts_str}|{msg}|{raw}|{index}".encode("utf-8")
    short_hash = hashlib.sha256(seed).hexdigest()[:6].upper()
    return f"EVT-{index:04d}-{short_hash}"


def normalize_events(
    raw_records: List[Dict[str, Any]], deduplicate: bool = True
) -> Tuple[List[LogEvent], List[str]]:
    """Normalize and validate a list of parsed records into LogEvent instances.

    Args:
        raw_records: Dictionaries output by log parsers
        deduplicate: Whether to filter out exact identical raw records

    Returns:
        Tuple of (validated_log_events, normalization_warnings)
    """
    normalized_events: List[LogEvent] = []
    warnings: List[str] = []
    seen_hashes: Set[str] = set()

    for idx, r in enumerate(raw_records, start=1):
        raw_record_str = sanitize_text(r.get("original_record", ""), max_length=1000)

        if deduplicate and raw_record_str:
            rec_hash = hashlib.md5(raw_record_str.encode("utf-8")).hexdigest()
            if rec_hash in seen_hashes:
                warnings.append(f"Skipped duplicate record at index {idx}.")
                continue
            seen_hashes.add(rec_hash)

        # Normalize outcome
        raw_outcome = str(r.get("outcome", "")).lower().strip()
        if "success" in raw_outcome or "accepted" in raw_outcome or "pass" in raw_outcome:
            outcome = EventOutcome.SUCCESS
        elif "fail" in raw_outcome or "error" in raw_outcome or "invalid" in raw_outcome or "denied" in raw_outcome:
            outcome = EventOutcome.FAILURE
        else:
            outcome = EventOutcome.UNKNOWN

        # Sanitize string fields
        clean_user = sanitize_text(r.get("username"), max_length=100) or None
        clean_src_ip = sanitize_text(r.get("source_ip"), max_length=50) or None
        clean_dst_ip = sanitize_text(r.get("destination_ip"), max_length=50) or None
        clean_hostname = sanitize_text(r.get("hostname"), max_length=100) or None
        clean_event_type = sanitize_text(r.get("event_type"), max_length=50) or "auth_event"
        clean_message = sanitize_text(r.get("message"), max_length=500)
        clean_source_file = sanitize_text(r.get("source_file"), max_length=100) or "uploaded_log"

        evt_id = generate_event_id(r, idx)

        try:
            event = LogEvent(
                event_id=evt_id,
                timestamp=r["timestamp"],
                source_type=str(r.get("source_type", "unknown")),
                username=clean_user,
                source_ip=clean_src_ip,
                destination_ip=clean_dst_ip,
                hostname=clean_hostname,
                event_type=clean_event_type,
                outcome=outcome,
                message=clean_message,
                original_record=raw_record_str,
                source_file=clean_source_file,
            )
            normalized_events.append(event)
        except Exception as e:
            warnings.append(f"Record {idx} failed validation: {str(e)}")

    return normalized_events, warnings
