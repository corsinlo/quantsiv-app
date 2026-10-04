"""
Quantsiv MVP - Main FastAPI Application
"""

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from app.api import router
from app.config import get_settings


def create_app() -> FastAPI:
    is_prod = get_settings().env == "production"
    app = FastAPI(
        title="Quantsiv",
        docs_url=None if is_prod else "/docs",
        redoc_url=None,
        openapi_url=None if is_prod else "/openapi.json",
    )
    app.mount("/static", StaticFiles(directory="app/static"), name="static")
    app.include_router(router)  # "/" and "/health" live in the router only
    return app


app = create_app()
