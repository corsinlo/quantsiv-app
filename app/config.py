"""Application settings. Secrets come only from here (A10)."""

import logging
from functools import lru_cache

from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    # env_ignore_empty: a blank line copied from .env.example falls back to the default, and a
    # blank required secret fails validation instead of becoming ""
    model_config = SettingsConfigDict(env_file=".env", extra="ignore", env_ignore_empty=True)

    env: str = "development"
    github_app_id: str
    github_app_private_key: SecretStr
    github_webhook_secret: SecretStr
    # OAuth credentials of the same GitHub App, for user sign-in (A14)
    github_client_id: str
    github_client_secret: SecretStr
    session_secret: SecretStr
    stripe_secret_key: SecretStr | None = None
    stripe_webhook_secret: SecretStr | None = None
    database_url: str = "sqlite:///./quantsiv.db"
    redis_url: str = "redis://localhost:6379/0"
    # INFO carries no personal data (account or repo names); those are DEBUG only (A25)
    log_level: str = "INFO"


@lru_cache
def get_settings() -> Settings:
    return Settings()  # missing required secrets fail at startup, never at request time


def configure_logging() -> None:
    """Send app.* logs to stderr at LOG_LEVEL. Idempotent; uvicorn and arq keep their own."""
    logger = logging.getLogger("app")
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
        logger.addHandler(handler)
    logger.setLevel(get_settings().log_level.upper())
