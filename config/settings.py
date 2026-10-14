"""Application configuration and environment settings.

Provides strongly typed configuration for Ollama, rule thresholds,
database paths, and ingestion limits, loaded from environment variables or .env.
"""

from pathlib import Path
import os
import logging
from dotenv import load_dotenv

# Base directory of the repository
BASE_DIR = Path(__file__).resolve().parent.parent

# Load environment variables from .env file if present
load_dotenv(BASE_DIR / ".env")


class Settings:
    """Central configuration class."""

    # Project Paths
    BASE_DIR: Path = BASE_DIR
    DATA_DIR: Path = BASE_DIR / "data"
    SAMPLES_DIR: Path = BASE_DIR / "data" / "samples"
    KNOWLEDGE_DIR: Path = BASE_DIR / "data" / "knowledge"
    VECTOR_CACHE_DIR: Path = BASE_DIR / "data" / "cache"
    ML_MODEL_DIR: Path = BASE_DIR / "data" / "cache" / "ml_models"

    # ML Settings
    ML_ANOMALY_CONTAMINATION: float = float(os.getenv("ML_ANOMALY_CONTAMINATION", "0.1"))
    ML_ANOMALY_SCORE_THRESHOLD: float = float(os.getenv("ML_ANOMALY_SCORE_THRESHOLD", "0.60"))

    # Embedding Settings
    EMBEDDING_MODEL_NAME: str = os.getenv("EMBEDDING_MODEL_NAME", "all-MiniLM-L6-v2")

    # Environment
    ENVIRONMENT: str = os.getenv("ENVIRONMENT", "development")
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO").upper()

    # Ollama LLM Settings
    OLLAMA_BASE_URL: str = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434").rstrip("/")
    OLLAMA_MODEL: str = os.getenv("OLLAMA_MODEL", "qwen3:4b")
    OLLAMA_TIMEOUT_SECONDS: int = int(os.getenv("OLLAMA_TIMEOUT_SECONDS", "120"))
    USE_MOCK_LLM: bool = os.getenv("USE_MOCK_LLM", "false").lower() in ("true", "1", "yes")

    # Ingestion Constraints
    MAX_FILE_SIZE_MB: int = int(os.getenv("MAX_FILE_SIZE_MB", "10"))
    MAX_RECORDS_PER_FILE: int = int(os.getenv("MAX_RECORDS_PER_FILE", "10000"))

    # Rule-Based Detection Thresholds
    BRUTE_FORCE_THRESHOLD: int = int(os.getenv("BRUTE_FORCE_THRESHOLD", "5"))
    BRUTE_FORCE_WINDOW_MINUTES: int = int(os.getenv("BRUTE_FORCE_WINDOW_MINUTES", "10"))
    FAILED_THEN_SUCCESS_WINDOW_MINUTES: int = int(os.getenv("FAILED_THEN_SUCCESS_WINDOW_MINUTES", "15"))
    USER_ENUMERATION_THRESHOLD: int = int(os.getenv("USER_ENUMERATION_THRESHOLD", "3"))

    # Database
    DATABASE_URL: str = os.getenv("DATABASE_URL", f"sqlite:///{BASE_DIR / 'data' / 'soc_analyst.db'}")

    # Threat Intelligence Keys (Optional)
    ABUSEIPDB_API_KEY: str = os.getenv("ABUSEIPDB_API_KEY", "")
    VIRUSTOTAL_API_KEY: str = os.getenv("VIRUSTOTAL_API_KEY", "")

    @classmethod
    def setup_logging(cls) -> None:
        """Configure structured application logging."""
        numeric_level = getattr(logging, cls.LOG_LEVEL, logging.INFO)
        logging.basicConfig(
            level=numeric_level,
            format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )


settings = Settings()
settings.setup_logging()
