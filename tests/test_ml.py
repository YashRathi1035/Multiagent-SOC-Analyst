"""Unit and integration tests for ML Intrusion and Anomaly Detection (Phase 5).

Verifies:
1. Feature extraction from LogEvent sequences
2. Synthetic dataset generation
3. Isolation Forest and Random Forest fitting, persistence, and inference
4. Alert generation and integration with DetectionEngine
"""

import tempfile
from datetime import datetime, timedelta
from pathlib import Path
import pytest

from detection.rules import DetectionEngine
from ml.dataset import generate_synthetic_feature_dataset, get_or_create_dataset
from ml.detector import MLDetector
from ml.features import FEATURE_COLUMNS, compute_entity_session_features, get_feature_matrix
from models.schemas import EventOutcome, LogEvent, SeverityLevel


def _create_sample_event(
    event_id: str,
    timestamp: datetime,
    source_ip: str = "192.168.1.50",
    username: str = "user1",
    outcome: EventOutcome = EventOutcome.FAILURE,
    event_type: str = "failed_login",
) -> LogEvent:
    return LogEvent(
        event_id=event_id,
        timestamp=timestamp,
        source_type="auth_openssh",
        username=username,
        source_ip=source_ip,
        destination_ip="10.0.0.1",
        hostname="prod-srv-01",
        event_type=event_type,
        outcome=outcome,
        message=f"{event_type} for {username} from {source_ip}",
        original_record=f"RAW: {event_type} for {username}",
    )


class TestFeatureEngineering:
    """Tests for ml/features.py."""

    def test_compute_features_empty_list(self):
        df, event_ids = compute_entity_session_features([])
        assert df.empty
        assert event_ids == {}

    def test_compute_features_normal_session(self):
        base_time = datetime(2026, 3, 15, 10, 0, 0)
        events = [
            _create_sample_event("EVT-01", base_time, outcome=EventOutcome.SUCCESS, event_type="successful_login"),
            _create_sample_event("EVT-02", base_time + timedelta(seconds=120), outcome=EventOutcome.SUCCESS, event_type="successful_login"),
        ]
        df, event_ids = compute_entity_session_features(events, entity_key="source_ip")
        assert len(df) == 1
        assert "192.168.1.50" in event_ids
        assert len(event_ids["192.168.1.50"]) == 2

        row = df.iloc[0]
        assert row["total_events"] == 2.0
        assert row["failed_count"] == 0.0
        assert row["success_count"] == 2.0
        assert row["failure_ratio"] == 0.0
        assert row["unique_users_targeted"] == 1.0
        assert row["privileged_user_targeted"] == 0.0

    def test_compute_features_brute_force_session(self):
        base_time = datetime(2026, 3, 15, 23, 0, 0)  # Off hours
        events = [
            _create_sample_event(
                f"EVT-{i:02d}",
                base_time + timedelta(seconds=i * 2),
                source_ip="203.0.113.88",
                username="root" if i % 2 == 0 else "admin",
                outcome=EventOutcome.FAILURE,
            )
            for i in range(10)
        ]
        df, event_ids = compute_entity_session_features(events, entity_key="source_ip")
        assert len(df) == 1
        row = df.iloc[0]

        assert row["total_events"] == 10.0
        assert row["failed_count"] == 10.0
        assert row["failure_ratio"] == 1.0
        assert row["unique_users_targeted"] == 2.0
        assert row["privileged_user_targeted"] == 1.0
        assert row["off_hours_ratio"] == 1.0
        assert row["events_per_minute"] >= 10.0

    def test_get_feature_matrix_shape(self):
        base_time = datetime(2026, 3, 15, 10, 0, 0)
        events = [_create_sample_event("EVT-01", base_time)]
        df, _ = compute_entity_session_features(events)
        X = get_feature_matrix(df)
        assert X.shape == (1, len(FEATURE_COLUMNS))


class TestSyntheticDataset:
    """Tests for ml/dataset.py."""

    def test_generate_dataset_structure(self):
        df = generate_synthetic_feature_dataset(
            n_normal=50,
            n_brute_force=20,
            n_spraying=10,
            n_compromise=10,
            random_seed=42,
        )
        assert len(df) == 90
        assert "label" in df.columns
        assert "is_anomaly" in df.columns
        for col in FEATURE_COLUMNS:
            assert col in df.columns

        labels = set(df["label"].unique())
        assert labels == {"normal", "brute_force", "user_enumeration", "credential_compromise"}

    def test_get_or_create_dataset_caching(self, tmp_path):
        csv_file = tmp_path / "test_dataset.csv"
        df1 = get_or_create_dataset(output_path=csv_file)
        assert csv_file.exists()
        assert len(df1) > 0

        # Load from disk
        df2 = get_or_create_dataset(output_path=csv_file)
        assert len(df2) == len(df1)


class TestMLDetector:
    """Tests for ml/detector.py."""

    @pytest.fixture
    def trained_detector(self, tmp_path):
        # Create a fast detector trained on small dataset
        df = generate_synthetic_feature_dataset(
            n_normal=80,
            n_brute_force=30,
            n_spraying=20,
            n_compromise=15,
            random_seed=123,
        )
        detector = MLDetector(model_dir=tmp_path, auto_train=False)
        detector.fit(df)
        return detector

    def test_detector_training_and_persistence(self, trained_detector, tmp_path):
        assert trained_detector.is_fitted
        trained_detector.save(tmp_path)

        # Verify joblib files exist
        assert (tmp_path / "isolation_forest.joblib").exists()
        assert (tmp_path / "random_forest.joblib").exists()

        # Load into new instance
        new_detector = MLDetector(model_dir=tmp_path, auto_train=False)
        assert new_detector.is_fitted

    def test_analyze_events_normal_vs_attack(self, trained_detector):
        base_time = datetime(2026, 3, 15, 12, 0, 0)

        # 1. Normal single login
        normal_events = [
            _create_sample_event(
                "EVT-N1",
                base_time,
                source_ip="192.168.1.100",
                username="alice",
                outcome=EventOutcome.SUCCESS,
            )
        ]
        normal_results = trained_detector.analyze_events(normal_events)
        assert len(normal_results) == 1
        assert normal_results[0].predicted_class == "normal"
        assert not normal_results[0].is_anomaly or normal_results[0].anomaly_score < 0.65

        # 2. Aggressive brute force burst
        attack_events = [
            _create_sample_event(
                f"EVT-A{i}",
                base_time + timedelta(seconds=i * 2),
                source_ip="45.33.32.156",
                username="root",
                outcome=EventOutcome.FAILURE,
            )
            for i in range(25)
        ]
        attack_results = trained_detector.analyze_events(attack_events)
        assert len(attack_results) == 1
        res = attack_results[0]
        assert res.is_anomaly
        assert res.anomaly_score >= 0.50
        assert res.predicted_class in ("brute_force", "credential_compromise")
        assert len(res.triggering_event_ids) == 25
        assert "failure_ratio" in res.contributing_features or "failed_count" in res.contributing_features

    def test_detect_alerts_output(self, trained_detector):
        base_time = datetime(2026, 3, 15, 12, 0, 0)
        attack_events = [
            _create_sample_event(
                f"EVT-ATK-{i}",
                base_time + timedelta(seconds=i * 2),
                source_ip="198.51.100.99",
                username="admin",
                outcome=EventOutcome.FAILURE,
            )
            for i in range(20)
        ]

        alerts = trained_detector.detect_alerts(attack_events)
        assert len(alerts) >= 1
        alert = alerts[0]
        assert alert.alert_id.startswith("ALT-ML-")
        assert alert.rule_id in ("RULE-ML-001", "RULE-ML-002")
        assert alert.source_ip == "198.51.100.99"
        assert alert.affected_user == "admin"
        assert alert.severity in (SeverityLevel.HIGH, SeverityLevel.CRITICAL)
        assert len(alert.triggering_event_ids) == 20
        assert "T1110" in alert.mitre_candidates[0]


class TestDetectionEngineIntegration:
    """Test DetectionEngine integration with ML detector."""

    def test_detection_engine_with_ml_toggle(self):
        engine = DetectionEngine()
        base_time = datetime(2026, 3, 15, 12, 0, 0)

        # 12 failed events (triggers RULE-AUTH-001 and ML detector)
        events = [
            _create_sample_event(
                f"EVT-E{i}",
                base_time + timedelta(seconds=i * 3),
                source_ip="203.0.113.111",
                username="ubuntu",
                outcome=EventOutcome.FAILURE,
            )
            for i in range(12)
        ]

        # Without ML
        rule_only_alerts = engine.run_all_rules(events, include_ml=False)
        assert any(a.rule_id == "RULE-AUTH-001" for a in rule_only_alerts)
        assert not any(a.rule_id.startswith("RULE-ML-") for a in rule_only_alerts)

        # With ML
        all_alerts = engine.run_all_rules(events, include_ml=True)
        assert any(a.rule_id == "RULE-AUTH-001" for a in all_alerts)
        assert any(a.rule_id.startswith("RULE-ML-") for a in all_alerts)
