"""Dataset generation and loading utilities for ML intrusion detection.

Provides synthetic baseline cybersecurity event distributions modeling:
1. Normal enterprise user behavior (single/occasional logins, business hours, low failure rate)
2. Brute-force attacks (high rate, repeated failures, low jitter)
3. User enumeration/spraying (many distinct usernames)
4. Credential compromise (repeated failures culminating in success)
"""

from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, Tuple
import numpy as np
import pandas as pd

from config.settings import settings
from ml.features import FEATURE_COLUMNS


def generate_synthetic_feature_dataset(
    n_normal: int = 400,
    n_brute_force: int = 60,
    n_spraying: int = 40,
    n_compromise: int = 30,
    random_seed: int = 42,
) -> pd.DataFrame:
    """Generate a realistic labeled feature dataset for training ML models."""
    rng = np.random.default_rng(random_seed)
    records = []

    # 1. Normal User Behavior
    for i in range(n_normal):
        total = int(rng.integers(1, 8))
        failed = int(rng.choice([0, 1, 2], p=[0.85, 0.12, 0.03]))
        failed = min(failed, total)
        success = total - failed
        fail_ratio = float(failed / total)
        unique_users = 1.0
        duration = float(rng.uniform(10.0, 3600.0))
        events_per_min = float(total / max(1.0, duration / 60.0))
        mean_delta = float(duration / max(1, total - 1)) if total > 1 else 0.0
        std_delta = float(rng.uniform(5.0, 60.0)) if total > 2 else 0.0
        has_priv = float(rng.choice([0.0, 1.0], p=[0.92, 0.08]))
        off_hours = float(rng.choice([0.0, 0.2, 0.5], p=[0.80, 0.15, 0.05]))
        weekend = float(rng.choice([0.0, 1.0], p=[0.90, 0.10]))
        invalid = 0.0

        records.append({
            "entity": f"192.168.1.{rng.integers(10, 250)}",
            "total_events": float(total),
            "failed_count": float(failed),
            "success_count": float(success),
            "failure_ratio": fail_ratio,
            "unique_users_targeted": unique_users,
            "duration_seconds": duration,
            "events_per_minute": events_per_min,
            "mean_inter_arrival": mean_delta,
            "std_inter_arrival": std_delta,
            "privileged_user_targeted": has_priv,
            "off_hours_ratio": off_hours,
            "weekend_ratio": weekend,
            "invalid_user_count": invalid,
            "label": "normal",
            "is_anomaly": 0,
        })

    # 2. Brute Force Attacks
    for i in range(n_brute_force):
        total = int(rng.integers(15, 80))
        failed = total
        success = 0
        fail_ratio = 1.0
        unique_users = float(rng.choice([1, 2], p=[0.85, 0.15]))
        duration = float(rng.uniform(30.0, 300.0))  # Rapid burst
        events_per_min = float(total / (duration / 60.0))
        mean_delta = float(rng.uniform(0.5, 3.0))
        std_delta = float(rng.uniform(0.1, 1.0))  # Automated bot: low jitter
        has_priv = float(rng.choice([0.0, 1.0], p=[0.40, 0.60]))
        off_hours = float(rng.choice([0.5, 1.0], p=[0.30, 0.70]))
        weekend = float(rng.choice([0.0, 1.0], p=[0.50, 0.50]))
        invalid = float(rng.integers(0, 5))

        records.append({
            "entity": f"203.0.113.{rng.integers(10, 200)}",
            "total_events": float(total),
            "failed_count": float(failed),
            "success_count": float(success),
            "failure_ratio": fail_ratio,
            "unique_users_targeted": unique_users,
            "duration_seconds": duration,
            "events_per_minute": events_per_min,
            "mean_inter_arrival": mean_delta,
            "std_inter_arrival": std_delta,
            "privileged_user_targeted": has_priv,
            "off_hours_ratio": off_hours,
            "weekend_ratio": weekend,
            "invalid_user_count": invalid,
            "label": "brute_force",
            "is_anomaly": 1,
        })

    # 3. User Enumeration / Password Spraying
    for i in range(n_spraying):
        unique_users = float(rng.integers(5, 25))
        total = int(unique_users * rng.integers(1, 3))
        failed = total
        success = 0
        fail_ratio = 1.0
        duration = float(rng.uniform(60.0, 600.0))
        events_per_min = float(total / (duration / 60.0))
        mean_delta = float(rng.uniform(2.0, 10.0))
        std_delta = float(rng.uniform(0.5, 3.0))
        has_priv = 1.0  # Enumerates admin/root etc
        off_hours = float(rng.choice([0.4, 0.8, 1.0]))
        weekend = float(rng.choice([0.0, 1.0], p=[0.60, 0.40]))
        invalid = float(rng.integers(3, int(unique_users)))

        records.append({
            "entity": f"198.51.100.{rng.integers(10, 200)}",
            "total_events": float(total),
            "failed_count": float(failed),
            "success_count": float(success),
            "failure_ratio": fail_ratio,
            "unique_users_targeted": unique_users,
            "duration_seconds": duration,
            "events_per_minute": events_per_min,
            "mean_inter_arrival": mean_delta,
            "std_inter_arrival": std_delta,
            "privileged_user_targeted": has_priv,
            "off_hours_ratio": off_hours,
            "weekend_ratio": weekend,
            "invalid_user_count": invalid,
            "label": "user_enumeration",
            "is_anomaly": 1,
        })

    # 4. Credential Compromise (Repeated fails then successful login)
    for i in range(n_compromise):
        failed = int(rng.integers(6, 20))
        success = int(rng.integers(1, 3))
        total = failed + success
        fail_ratio = float(failed / total)
        unique_users = float(rng.choice([1, 2], p=[0.9, 0.1]))
        duration = float(rng.uniform(60.0, 500.0))
        events_per_min = float(total / (duration / 60.0))
        mean_delta = float(rng.uniform(1.0, 5.0))
        std_delta = float(rng.uniform(0.5, 2.5))
        has_priv = 1.0
        off_hours = float(rng.choice([0.6, 1.0]))
        weekend = float(rng.choice([0.0, 1.0], p=[0.50, 0.50]))
        invalid = float(rng.integers(0, 3))

        records.append({
            "entity": f"198.51.100.{rng.integers(201, 254)}",
            "total_events": float(total),
            "failed_count": float(failed),
            "success_count": float(success),
            "failure_ratio": fail_ratio,
            "unique_users_targeted": unique_users,
            "duration_seconds": duration,
            "events_per_minute": events_per_min,
            "mean_inter_arrival": mean_delta,
            "std_inter_arrival": std_delta,
            "privileged_user_targeted": has_priv,
            "off_hours_ratio": off_hours,
            "weekend_ratio": weekend,
            "invalid_user_count": invalid,
            "label": "credential_compromise",
            "is_anomaly": 1,
        })

    df = pd.DataFrame(records)
    # Shuffle rows
    df = df.sample(frac=1.0, random_state=random_seed).reset_index(drop=True)
    return df


def get_or_create_dataset(output_path: Optional[Path] = None) -> pd.DataFrame:
    """Load existing dataset CSV or generate and save a fresh synthetic baseline."""
    csv_path = output_path or (settings.SAMPLES_DIR / "ml_baseline_dataset.csv")
    csv_path.parent.mkdir(parents=True, exist_ok=True)

    if csv_path.exists():
        try:
            return pd.read_csv(csv_path)
        except Exception:
            pass

    df = generate_synthetic_feature_dataset()
    df.to_csv(csv_path, index=False)
    return df
