"""Storage and SQLite Persistence Package (Phase 6).

Exports:
    DatabaseManager: Main database client for case storage and retrieval.
    CaseRecord: SQLAlchemy ORM model for an investigated SOC case.
    get_db: Factory helper to obtain singleton DatabaseManager.
"""

from storage.models import Base, CaseRecord
from storage.database import DatabaseManager, get_db

__all__ = [
    "Base",
    "CaseRecord",
    "DatabaseManager",
    "get_db",
]
