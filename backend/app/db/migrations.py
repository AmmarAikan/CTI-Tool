from __future__ import annotations

from sqlalchemy import inspect
from sqlalchemy.engine import Engine

from backend.app.db.database import Base


def apply_additive_migrations(engine: Engine) -> None:
    """Apply the repository's bounded additive schema migrations idempotently."""
    from backend.app.db import models  # noqa: F401

    tables = set(inspect(engine).get_table_names())
    if "pipeline_runs" not in tables:
        # A fresh installation is created from current metadata. Existing
        # installations take the explicit additive path below.
        Base.metadata.create_all(bind=engine)
        return
    Base.metadata.tables["external_ingestion_operations"].create(bind=engine, checkfirst=True)
