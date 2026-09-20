from __future__ import annotations

from collections.abc import Generator
from pathlib import Path
import tempfile
import threading

from sqlalchemy import URL, create_engine
from sqlalchemy.engine import Engine, make_url
from sqlalchemy.orm import DeclarativeBase, Session, close_all_sessions, sessionmaker

from backend.app.core.config import PROJECT_ROOT, get_settings


class Base(DeclarativeBase):
    pass


def _create_engine(database_url: str | URL) -> Engine:
    connect_args = {"check_same_thread": False} if str(database_url).startswith("sqlite") else {}
    return create_engine(
        database_url,
        future=True,
        pool_pre_ping=True,
        connect_args=connect_args,
    )


def _build_engine() -> Engine:
    settings = get_settings()
    if settings.database_url:
        database_url = settings.database_url
    elif settings.database_host:
        database_url = URL.create(
            "postgresql+psycopg",
            username=settings.database_user,
            password=settings.database_password,
            host=settings.database_host,
            port=settings.database_port,
            database=settings.database_name,
        )
    else:
        database_url = f"sqlite:///{(PROJECT_ROOT / 'data' / 'cti_platform.db').as_posix()}"
    return _create_engine(database_url)


engine: Engine | None = _build_engine()
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False, class_=Session)
_test_database_url: str | None = None
_engine_lock = threading.RLock()


def _validated_test_database_url(database_url: str) -> str:
    parsed = make_url(database_url)
    if not parsed.drivername.startswith("sqlite") or not parsed.database or parsed.database == ":memory:":
        raise ValueError("test database must be a temporary SQLite file")
    target = Path(parsed.database).expanduser().resolve(strict=False)
    temporary_root = Path(tempfile.gettempdir()).resolve()
    try:
        target.relative_to(temporary_root)
    except ValueError as exc:
        raise ValueError("test database must be under the temporary directory") from exc
    if not any(part.startswith(("cti_", "test")) for part in target.parts[len(temporary_root.parts):]):
        raise ValueError("test database path must be explicitly test-scoped")
    return str(make_url(database_url).set(database=str(target)))


def configure_test_database(database_url: str) -> None:
    """Rebind global database state to an explicit temporary test database."""
    normalized = _validated_test_database_url(database_url)
    global engine, _test_database_url
    with _engine_lock:
        close_all_sessions()
        if engine is not None:
            engine.dispose()
        engine = _create_engine(normalized)
        SessionLocal.configure(bind=engine)
        _test_database_url = normalized


def dispose_test_database(database_url: str) -> None:
    """Dispose a matching test engine without deleting its database file."""
    normalized = _validated_test_database_url(database_url)
    global engine, _test_database_url
    with _engine_lock:
        if _test_database_url != normalized:
            raise RuntimeError("refusing to dispose an unconfigured test database")
        close_all_sessions()
        if engine is not None:
            engine.dispose()
        engine = None
        SessionLocal.configure(bind=None)
        _test_database_url = None


def initialize_database() -> None:
    from backend.app.db import models  # noqa: F401

    if engine is None:
        raise RuntimeError("database engine is not configured")
    Base.metadata.create_all(bind=engine)


def get_db() -> Generator[Session, None, None]:
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()
