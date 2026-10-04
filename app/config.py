"""Application settings. Secrets come only from here (A10)."""

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
    session_secret: SecretStr
    stripe_secret_key: SecretStr | None = None
    stripe_webhook_secret: SecretStr | None = None
    database_url: str = "sqlite:///./quantsiv.db"
    redis_url: str = "redis://localhost:6379/0"


@lru_cache
def get_settings() -> Settings:
    return Settings()  # missing required secrets fail at startup, never at request time
