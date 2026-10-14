"""Machine Learning Intrusion Detection Package.

Exports:
    MLDetector: Core ensemble anomaly detector & classifier.
    compute_entity_session_features: Feature engineering for log sequences.
    generate_synthetic_feature_dataset: Baseline cybersecurity dataset generator.
"""

from ml.detector import MLDetector
from ml.features import compute_entity_session_features, FEATURE_COLUMNS
from ml.dataset import generate_synthetic_feature_dataset, get_or_create_dataset

__all__ = [
    "MLDetector",
    "compute_entity_session_features",
    "FEATURE_COLUMNS",
    "generate_synthetic_feature_dataset",
    "get_or_create_dataset",
]
