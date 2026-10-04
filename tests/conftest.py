import os
import tempfile
from pathlib import Path

import pytest

# Required settings must exist before anything imports app.config (A10)
for key, value in {
    "GITHUB_APP_ID": "1",
    "GITHUB_APP_PRIVATE_KEY": "test",
    "GITHUB_WEBHOOK_SECRET": "test-secret",
    "GITHUB_CLIENT_ID": "test-client",
    "GITHUB_CLIENT_SECRET": "test-client-secret",
    "SESSION_SECRET": "test",
    "ENV": "test",
}.items():
    os.environ.setdefault(key, value)

# A throwaway SQLite database, created through the real migrations
_DB_DIR = tempfile.mkdtemp(prefix="quantsiv-tests-")
# (CI also runs the suite against Postgres by setting TEST_DATABASE_URL)
os.environ["DATABASE_URL"] = os.environ.get("TEST_DATABASE_URL") or (
    f"sqlite:///{Path(_DB_DIR) / 'test.db'}"
)


@pytest.fixture(scope="session", autouse=True)
def migrated_database():
    from alembic import command
    from alembic.config import Config

    config = Config("alembic.ini")
    config.attributes["configure_logger"] = False
    command.upgrade(config, "head")
    yield


@pytest.fixture
async def worker_ctx():
    """An ARQ-style ctx for calling job functions directly, on the test database."""
    from app import worker

    ctx: dict = {}
    await worker.startup(ctx)
    yield ctx
    await worker.shutdown(ctx)
