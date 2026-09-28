from __future__ import annotations

from sqlalchemy import inspect, text
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
    columns = {value["name"] for value in inspect(engine).get_columns("external_ingestion_operations")}
    additions = {
        "priority": "INTEGER NOT NULL DEFAULT 100",
        "processed_offset": "INTEGER NOT NULL DEFAULT 0",
        "fairness_skips": "INTEGER NOT NULL DEFAULT 0",
    }
    with engine.begin() as connection:
        for name, declaration in additions.items():
            if name not in columns:
                connection.execute(text(
                    f"ALTER TABLE external_ingestion_operations ADD COLUMN {name} {declaration}"
                ))
        connection.execute(text(
            "CREATE INDEX IF NOT EXISTS ix_external_ingestion_operations_priority "
            "ON external_ingestion_operations (priority, created_at)"
        ))
