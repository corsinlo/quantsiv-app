"""The ARQ connection the web service enqueues jobs through (A50).

The pool is created on first use and closed at shutdown, so the web app starts (and its tests
run) without Redis. Tests override `get_queue` with an in-memory fake.
"""

import asyncio
from typing import Any, Protocol

from arq import create_pool
from arq.connections import RedisSettings
from fastapi import FastAPI, Request

from app.config import get_settings

_lock = asyncio.Lock()


class JobQueue(Protocol):
    async def enqueue_job(self, function: str, *args: Any, **kwargs: Any) -> Any: ...


async def get_queue(request: Request) -> JobQueue:
    app = request.app
    if getattr(app.state, "arq", None) is None:
        async with _lock:
            if getattr(app.state, "arq", None) is None:
                settings = RedisSettings.from_dsn(get_settings().redis_url)
                app.state.arq = await create_pool(settings)
    return app.state.arq


async def close_queue(app: FastAPI) -> None:
    pool = getattr(app.state, "arq", None)
    if pool is not None:
        await pool.aclose()
        app.state.arq = None
