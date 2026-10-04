"""Async SQLAlchemy engine and sessions (A03, A51)."""

from collections.abc import AsyncIterator
from functools import lru_cache

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import NullPool

from app.config import get_settings


def async_url(url: str) -> str:
    """Map a plain DATABASE_URL (as Railway provides it) to its async driver."""
    for prefix, driver in (
        ("postgres://", "postgresql+asyncpg://"),
        ("postgresql://", "postgresql+asyncpg://"),
        ("sqlite:///", "sqlite+aiosqlite:///"),
    ):
        if url.startswith(prefix):
            return driver + url[len(prefix) :]
    return url


def make_engine(url: str | None = None) -> AsyncEngine:
    settings = get_settings()
    if settings.env == "test":
        # Each TestClient runs its own event loop; pooled asyncpg connections can't cross loops
        return create_async_engine(async_url(url or settings.database_url), poolclass=NullPool)
    return create_async_engine(async_url(url or settings.database_url), pool_pre_ping=True)


@lru_cache
def get_sessionmaker() -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(make_engine(), expire_on_commit=False)


async def get_db() -> AsyncIterator[AsyncSession]:
    async with get_sessionmaker()() as session:
        yield session
