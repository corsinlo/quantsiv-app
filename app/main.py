"""
Quantsiv MVP - Main FastAPI Application
"""

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from app.api import router
from app.config import get_settings
from app.queue import close_queue
from app.routers import webhooks
from app.security import security_headers


@asynccontextmanager
async def lifespan(app: FastAPI):
    yield
    await close_queue(app)


def create_app() -> FastAPI:
    is_prod = get_settings().env == "production"
    app = FastAPI(
        title="Quantsiv",
        lifespan=lifespan,
        docs_url=None if is_prod else "/docs",
        redoc_url=None,
        openapi_url=None if is_prod else "/openapi.json",
    )
    app.middleware("http")(security_headers)
    app.mount("/static", StaticFiles(directory="app/static"), name="static")
    app.include_router(router)  # "/" and "/health" live in the router only
    app.include_router(webhooks.router)
    return app


app = create_app()
