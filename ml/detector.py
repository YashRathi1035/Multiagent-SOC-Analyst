"""Machine Learning Intrusion and Anomaly Detection Engine.

Implements dual-layer ML detection:
1. Unsupervised Anomaly Detection via Isolation Forest (detects novel outliers and behavioral shifts)
2. Supervised Attack Classification via Random Forest (classifies brute force, spraying, compromise)
"""

import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier

from config.settings import settings
from ml.dataset import get_or_create_dataset
from ml.features import FEATURE_COLUMNS, compute_entity_session_features, get_feature_matrix
from models.schemas import DetectionAlert, LogEvent, MLAnomalyResult, SeverityLevel

logger = logging.getLogger("ml_detector")

# Mapping of classified attacks to MITRE ATT&CK candidate technique IDs
ATTACK_MITRE_MAP = {
    "brute_force": ["T1110", "T1110.001"],
    "user_enumeration": ["T1087.001", "T1110.003"],
    "credential_compromise": ["T1110", "T1078"],
}


class MLDetector:
    """Intrusion and Anomaly Detection Engine powered by Scikit-Learn."""

    def __init__(
        self,
        model_dir: Optional[Path] = None,
        contamination: float = settings.ML_ANOMALY_CONTAMINATION,
        score_threshold: float = settings.ML_ANOMALY_SCORE_THRESHOLD,
        auto_train: bool = True,
    ):
        self.model_dir = model_dir or settings.ML_MODEL_DIR
        self.model_dir.mkdir(parents=True, exist_ok=True)
        self.contamination = contamination
        self.score_threshold = score_threshold

        self.iso_forest: Optional[IsolationForest] = None
        self.rf_classifier: Optional[RandomForestClassifier] = None
        self.is_fitted = False

        # Attempt to load existing weights or auto-train baseline
        if not self.load():
            if auto_train:
                self.train_baseline()

    def train_baseline(self) -> None:
        """Train models using synthetic baseline enterprise cybersecurity data."""
        logger.info("Training ML models on baseline enterprise cybersecurity dataset...")
        df = get_or_create_dataset()
        self.fit(df)
        self.save()

    def fit(self, df: pd.DataFrame) -> None:
        """Fit Isolation Forest and Random Forest models on training DataFrame."""
        if df.empty:
            raise ValueError("Cannot train ML models on empty DataFrame.")

        X = get_feature_matrix(df)
        y = df["label"].values if "label" in df.columns else np.array(["normal"] * len(df))

        # 1. Isolation Forest (Unsupervised)
        self.iso_forest = IsolationForest(
            n_estimators=100,
            contamination=self.contamination,
            random_state=42,
            n_jobs=-1,
        )
        self.iso_forest.fit(X)

        # 2. Random Forest (Supervised Classification)
        self.rf_classifier = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            random_state=42,
            class_weight="balanced",
            n_jobs=-1,
        )
        self.rf_classifier.fit(X, y)

        self.is_fitted = True
        logger.info("ML models successfully trained. Classes: %s", list(self.rf_classifier.classes_))

    def save(self, model_dir: Optional[Path] = None) -> None:
        """Persist trained models to disk."""
        target_dir = model_dir or self.model_dir
        target_dir.mkdir(parents=True, exist_ok=True)

        if self.iso_forest:
            joblib.dump(self.iso_forest, target_dir / "isolation_forest.joblib")
        if self.rf_classifier:
            joblib.dump(self.rf_classifier, target_dir / "random_forest.joblib")
        logger.info("Saved ML models to %s", target_dir)

    def load(self, model_dir: Optional[Path] = None) -> bool:
        """Load trained models from disk if present."""
        target_dir = model_dir or self.model_dir
        iso_path = target_dir / "isolation_forest.joblib"
        rf_path = target_dir / "random_forest.joblib"

        if iso_path.exists() and rf_path.exists():
            try:
                self.iso_forest = joblib.load(iso_path)
                self.rf_classifier = joblib.load(rf_path)
                self.is_fitted = True
                logger.info("Loaded trained ML models from %s", target_dir)
                return True
            except Exception as e:
                logger.warning("Failed to load ML models from disk: %s", e)
        return False

    def analyze_events(
        self,
        events: List[LogEvent],
        entity_key: str = "source_ip",
    ) -> List[MLAnomalyResult]:
        """Analyze normalized events and return detailed ML evaluation for each entity."""
        if not events:
            return []

        if not self.is_fitted:
            self.train_baseline()

        df, entity_event_ids = compute_entity_session_features(events, entity_key=entity_key)
        if df.empty:
            return []

        X = get_feature_matrix(df)
        results: List[MLAnomalyResult] = []

        # 1. Isolation Forest scoring
        dec_scores = self.iso_forest.decision_function(X)  # type: ignore
        iso_preds = self.iso_forest.predict(X)  # type: ignore

        # 2. Random Forest probabilities
        rf_classes = list(self.rf_classifier.classes_)  # type: ignore
        rf_probs = self.rf_classifier.predict_proba(X)  # type: ignore

        for i, row in df.iterrows():
            entity = str(row["entity"])
            event_ids = entity_event_ids.get(entity, [])

            dec_val = float(dec_scores[i])
            # Calibrated anomaly score: decision_function > 0 is inlier (score < 0.5), < 0 is outlier (score >= 0.5)
            norm_anomaly_score = float(np.clip(0.5 - (dec_val / 0.25) * 0.5, 0.0, 1.0))

            is_iso_anomaly = bool(iso_preds[i] == -1 or norm_anomaly_score >= self.score_threshold)

            # Supervised attack prediction
            prob_dist = rf_probs[i]
            best_idx = int(np.argmax(prob_dist))
            predicted_class = rf_classes[best_idx]
            confidence = float(prob_dist[best_idx])

            # Anomaly if flagged by IsolationForest OR classified as attack by RandomForest
            is_anomaly = is_iso_anomaly or (predicted_class != "normal" and confidence >= 0.60)
            if predicted_class == "normal" and not is_iso_anomaly and norm_anomaly_score < 0.50:
                is_anomaly = False

            # Identify top contributing behavioral features for analyst interpretability
            contributing = {}
            if float(row.get("failure_ratio", 0)) > 0.5:
                contributing["failure_ratio"] = round(float(row["failure_ratio"]), 2)
            if float(row.get("events_per_minute", 0)) > 5.0:
                contributing["events_per_minute"] = round(float(row["events_per_minute"]), 1)
            if float(row.get("unique_users_targeted", 0)) > 2:
                contributing["unique_users_targeted"] = int(row["unique_users_targeted"])
            if float(row.get("privileged_user_targeted", 0)) > 0:
                contributing["privileged_account"] = 1.0
            if float(row.get("failed_count", 0)) >= 5:
                contributing["failed_count"] = int(row["failed_count"])

            results.append(
                MLAnomalyResult(
                    entity=entity,
                    is_anomaly=is_anomaly,
                    anomaly_score=round(norm_anomaly_score, 3),
                    predicted_class=predicted_class,
                    confidence=round(confidence, 3),
                    algorithm="Ensemble (IsolationForest + RandomForest)",
                    contributing_features=contributing,
                    triggering_event_ids=event_ids,
                )
            )

        return results

    def detect_alerts(
        self,
        events: List[LogEvent],
        entity_key: str = "source_ip",
    ) -> List[DetectionAlert]:
        """Run ML analysis and transform detected anomalies into structured DetectionAlerts."""
        ml_results = self.analyze_events(events, entity_key=entity_key)
        alerts: List[DetectionAlert] = []

        for res in ml_results:
            if not res.is_anomaly:
                continue

            # Determine severity
            if res.predicted_class == "credential_compromise" or res.anomaly_score >= 0.85:
                severity = SeverityLevel.CRITICAL
            elif res.predicted_class in ("brute_force", "user_enumeration") or res.anomaly_score >= 0.70:
                severity = SeverityLevel.HIGH
            else:
                severity = SeverityLevel.MEDIUM

            # Associate MITRE techniques
            mitre_candidates = ATTACK_MITRE_MAP.get(
                res.predicted_class, ["T1110"]
            )

            # Determine affected user if entity is user, or find in triggering events
            affected_user = None
            src_ip = None
            if entity_key == "source_ip":
                src_ip = res.entity if res.entity != "UNKNOWN" else None
                # Check for primary user targeted in triggering events
                user_counts: Dict[str, int] = {}
                for e in events:
                    if e.event_id in res.triggering_event_ids and e.username:
                        user_counts[e.username] = user_counts.get(e.username, 0) + 1
                if user_counts:
                    affected_user = max(user_counts, key=user_counts.get)
            else:
                affected_user = res.entity if res.entity != "UNKNOWN" else None

            # Generate alert
            import uuid
            alert_id = f"ALT-ML-{uuid.uuid4().hex[:8].upper()}"

            rule_name = (
                f"ML Attack Classification ({res.predicted_class.replace('_', ' ').title()})"
                if res.predicted_class != "normal"
                else "ML Behavioral Anomaly Detection (Statistical Outlier)"
            )

            description = (
                f"Machine learning detector identified suspicious activity from {res.entity}. "
                f"Classified as '{res.predicted_class}' with {int(res.confidence * 100)}% confidence "
                f"(anomaly score: {res.anomaly_score:.2f})."
            )

            severity_rationale = (
                f"Assessed {severity.value} due to ML anomaly score of {res.anomaly_score:.2f} "
                f"and predicted attack profile '{res.predicted_class}' "
                f"(key indicators: {', '.join(res.contributing_features.keys()) or 'unusual session pattern'})."
            )

            evidence_summary: Dict[str, Any] = {
                "ml_algorithm": res.algorithm,
                "anomaly_score": res.anomaly_score,
                "predicted_class": res.predicted_class,
                "confidence": res.confidence,
                "contributing_features": res.contributing_features,
                "triggering_event_count": len(res.triggering_event_ids),
            }

            alerts.append(
                DetectionAlert(
                    alert_id=alert_id,
                    rule_id="RULE-ML-001" if res.predicted_class == "normal" else "RULE-ML-002",
                    rule_name=rule_name,
                    severity=severity,
                    description=description,
                    triggering_event_ids=res.triggering_event_ids,
                    affected_user=affected_user,
                    source_ip=src_ip,
                    severity_rationale=severity_rationale,
                    evidence_summary=evidence_summary,
                    mitre_candidates=mitre_candidates,
                )
            )

        return alerts
