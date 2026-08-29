"""Internal REST adapter for External Sources application services."""

from backend.app.pipeline.ingestion.external.integration.api import AdapterServices, create_app

__all__ = ["AdapterServices", "create_app"]
