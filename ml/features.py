"""Feature engineering pipeline for cybersecurity log events.

Transforms raw LogEvent sequences into structured numerical feature matrices
for unsupervised anomaly detection (Isolation Forest) and supervised attack
classification (Random Forest).
"""

from collections import defaultdict
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple
import numpy as np
import pandas as pd

from models.schemas import EventOutcome, LogEvent

# Standardized feature column names used across all models
FEATURE_COLUMNS = [
    "total_events",
    "failed_count",
    "success_count",
    "failure_ratio",
    "unique_users_targeted",
    "duration_seconds",
    "events_per_minute",
    "mean_inter_arrival",
    "std_inter_arrival",
    "privileged_user_targeted",
    "off_hours_ratio",
    "weekend_ratio",
    "invalid_user_count",
]

PRIVILEGED_ACCOUNTS = {"root", "admin", "administrator", "system", "postgres", "wheel"}


def compute_entity_session_features(
    events: List[LogEvent],
    entity_key: str = "source_ip",
) -> Tuple[pd.DataFrame, Dict[str, List[str]]]:
    """Extract aggregated behavioral features grouped by entity (e.g. source_ip or username).

    Args:
        events: List of normalized LogEvent objects.
        entity_key: 'source_ip' or 'username' to group sessions by.

    Returns:
        Tuple of:
          - DataFrame where each row corresponds to an entity's feature vector.
          - Dictionary mapping entity identifier to its list of triggering event_ids.
    """
    if not events:
        empty_df = pd.DataFrame(columns=["entity"] + FEATURE_COLUMNS)
        return empty_df, {}

    # Group events by entity
    entity_groups: Dict[str, List[LogEvent]] = defaultdict(list)
    for event in events:
        val = getattr(event, entity_key, None)
        key = val if val else "UNKNOWN"
        entity_groups[key].append(event)

    records = []
    entity_event_ids: Dict[str, List[str]] = {}

    for entity, group in entity_groups.items():
        sorted_group = sorted(group, key=lambda e: e.timestamp)
        event_ids = [e.event_id for e in sorted_group]
        entity_event_ids[entity] = event_ids

        total = len(sorted_group)
        failed = sum(1 for e in sorted_group if e.outcome == EventOutcome.FAILURE)
        success = sum(1 for e in sorted_group if e.outcome == EventOutcome.SUCCESS)
        fail_ratio = float(failed / total) if total > 0 else 0.0

        users = {e.username.lower() for e in sorted_group if e.username}
        unique_users = len(users)

        # Time metrics
        t_first = sorted_group[0].timestamp
        t_last = sorted_group[-1].timestamp
        duration = max(0.0, (t_last - t_first).total_seconds())
        duration_mins = max(1.0, duration / 60.0)
        events_per_min = float(total / duration_mins)

        # Inter-arrival metrics
        if total > 1:
            deltas = [
                max(0.0, (sorted_group[i].timestamp - sorted_group[i - 1].timestamp).total_seconds())
                for i in range(1, total)
            ]
            mean_delta = float(np.mean(deltas))
            std_delta = float(np.std(deltas))
        else:
            mean_delta = 0.0
            std_delta = 0.0

        # Privileged account targeted
        has_priv = 1.0 if any(u in PRIVILEGED_ACCOUNTS for u in users) else 0.0

        # Temporal patterns
        off_hours_count = sum(1 for e in sorted_group if e.timestamp.hour < 8 or e.timestamp.hour >= 18)
        off_hours_ratio = float(off_hours_count / total) if total > 0 else 0.0

        weekend_count = sum(1 for e in sorted_group if e.timestamp.weekday() >= 5)
        weekend_ratio = float(weekend_count / total) if total > 0 else 0.0

        # Invalid user attempts
        invalid_count = sum(
            1 for e in sorted_group if "invalid" in e.event_type.lower() or "invalid" in e.message.lower()
        )

        records.append({
            "entity": entity,
            "total_events": float(total),
            "failed_count": float(failed),
            "success_count": float(success),
            "failure_ratio": fail_ratio,
            "unique_users_targeted": float(unique_users),
            "duration_seconds": float(duration),
            "events_per_minute": events_per_min,
            "mean_inter_arrival": mean_delta,
            "std_inter_arrival": std_delta,
            "privileged_user_targeted": has_priv,
            "off_hours_ratio": off_hours_ratio,
            "weekend_ratio": weekend_ratio,
            "invalid_user_count": float(invalid_count),
        })

    df = pd.DataFrame(records)
    return df, entity_event_ids


def get_feature_matrix(df: pd.DataFrame) -> np.ndarray:
    """Extract numerical matrix matching FEATURE_COLUMNS from DataFrame."""
    if df.empty:
        return np.empty((0, len(FEATURE_COLUMNS)))
    
    # Ensure all required columns exist with 0.0 default
    for col in FEATURE_COLUMNS:
        if col not in df.columns:
            df[col] = 0.0
            
    return df[FEATURE_COLUMNS].to_numpy(dtype=np.float32)
