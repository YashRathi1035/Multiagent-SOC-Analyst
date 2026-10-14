"""FastAPI REST API Package for Multi-Agent SOC Analyst.

Exports:
    app: Core FastAPI application instance.
"""

from api.routes import app

__all__ = ["app"]
