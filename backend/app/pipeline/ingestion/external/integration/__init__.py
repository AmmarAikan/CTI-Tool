"""Internal REST adapter for External Sources application services.

The package also contains dependency-neutral contracts consumed by Central.
Keep the External API graph lazy so importing those contracts does not require
connector-only dependencies.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from backend.app.pipeline.ingestion.external.integration.api import AdapterServices, create_app

__all__ = ["AdapterServices", "create_app"]


def __getattr__(name: str) -> Any:
    if name not in __all__:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    from backend.app.pipeline.ingestion.external.integration import api

    value = getattr(api, name)
    globals()[name] = value
    return value


def __dir__() -> list[str]:
    return sorted({*globals(), *__all__})
