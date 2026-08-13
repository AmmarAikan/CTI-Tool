from __future__ import annotations

from collections.abc import Generator

from sqlalchemy import URL, create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from backend.app.core.config import PROJECT_ROOT, get_settings


class Base(DeclarativeBase):
    pass


def _build_engine():
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
    connect_args = {"check_same_thread": False} if str(database_url).startswith("sqlite") else {}
    return create_engine(
        database_url,
        future=True,
        pool_pre_ping=True,
        connect_args=connect_args,
    )


engine = _build_engine()
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False, class_=Session)


def initialize_database() -> None:
    from backend.app.db import models  # noqa: F401

    Base.metadata.create_all(bind=engine)


def get_db() -> Generator[Session, None, None]:
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()
