"""
Quantsiv MVP - Main FastAPI Application
"""

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware

from app import auth
from app.api import router
from app.config import configure_logging, get_settings
from app.queue import close_queue
from app.routers import webhooks
from app.security import security_headers


@asynccontextmanager
async def lifespan(app: FastAPI):
    yield
    await close_queue(app)


def create_app() -> FastAPI:
    settings = get_settings()
    configure_logging()
    is_prod = settings.env == "production"
    app = FastAPI(
        title="Quantsiv",
        lifespan=lifespan,
        docs_url=None if is_prod else "/docs",
        redoc_url=None,
        openapi_url=None if is_prod else "/openapi.json",
    )
    app.middleware("http")(security_headers)
    app.add_middleware(
        SessionMiddleware,
        secret_key=settings.session_secret.get_secret_value(),
        session_cookie="quantsiv_session",
        max_age=auth.SESSION_MAX_AGE,
        same_site="lax",
        https_only=is_prod,
    )
    app.add_exception_handler(auth.LoginRequired, auth.login_redirect)
    app.mount("/static", StaticFiles(directory="app/static"), name="static")
    app.include_router(router)  # "/" and "/health" live in the router only
    app.include_router(webhooks.router)
    app.include_router(auth.router)
    return app


app = create_app()
