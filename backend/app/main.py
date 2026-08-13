from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from sqlalchemy import func, select

from backend.app.api.v1.router import router
from backend.app.core.config import get_settings
from backend.app.core.security import hash_password
from backend.app.db.database import SessionLocal, initialize_database
from backend.app.db.models import User

LOGGER = logging.getLogger(__name__)


def bootstrap_admin_from_environment() -> None:
    settings = get_settings()
    if not settings.bootstrap_admin_username or not settings.bootstrap_admin_password:
        return
    with SessionLocal() as session:
        if session.scalar(select(func.count()).select_from(User)):
            return
        user = User(
            username=settings.bootstrap_admin_username,
            password_hash=hash_password(settings.bootstrap_admin_password),
            role="admin",
        )
        session.add(user)
        session.commit()
        LOGGER.info("Created bootstrap administrator from environment")


@asynccontextmanager
async def lifespan(_: FastAPI):
    settings = get_settings()
    if settings.is_production and settings.jwt_secret == "development-only-change-me":
        raise RuntimeError("JWT_SECRET must be changed in production")
    settings.upload_dir.mkdir(parents=True, exist_ok=True)
    initialize_database()
    bootstrap_admin_from_environment()
    yield


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title=settings.app_name,
        version="1.0.0",
        description="Graduation-project CTI backend for external and internal telemetry.",
        lifespan=lifespan,
    )
    app.include_router(router, prefix=settings.api_prefix)
    return app


app = create_app()
