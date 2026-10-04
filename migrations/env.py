import asyncio
from logging.config import fileConfig

from alembic import context
from sqlalchemy.engine import Connection

from app.db import async_url, make_engine
from app.models import Base

config = context.config
if config.config_file_name is not None and config.attributes.get("configure_logger", True):
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def _url() -> str | None:
    # An explicit sqlalchemy.url (tests) wins; otherwise Settings.database_url
    return config.get_main_option("sqlalchemy.url")


def run_migrations_offline() -> None:
    from app.config import get_settings

    context.configure(
        url=async_url(_url() or get_settings().database_url),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        render_as_batch=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def do_run_migrations(connection: Connection) -> None:
    # render_as_batch: ALTERs that SQLite can't do in place are emitted as table copies
    context.configure(connection=connection, target_metadata=target_metadata, render_as_batch=True)
    with context.begin_transaction():
        context.run_migrations()


async def run_migrations_online() -> None:
    engine = make_engine(_url())
    async with engine.connect() as connection:
        await connection.run_sync(do_run_migrations)
    await engine.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    asyncio.run(run_migrations_online())
