"""
ARQ worker for Quantsiv: GitHub events, repository scans and account deletion (A50).

Start it with `python -m arq app.worker.WorkerSettings`.
"""

import asyncio
import logging
import shutil
import tempfile
from typing import ClassVar

from arq.connections import RedisSettings
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker

from app.config import configure_logging, get_settings
from app.db import make_engine
from app.models import Installation, Scan, ScanStatus, upsert_user, utcnow
from app.services.errors import ScanError

logger = logging.getLogger(__name__)
configure_logging()

SCAN_TIMEOUT = 540  # seconds; below WorkerSettings.job_timeout so the scan is marked failed


class ScanPipeline:
    """The steps of one scan. Each step that isn't built yet fails with a clear ScanError, so a
    scan never reports invented findings (A29): repository access and the hardened clone arrive
    with WP5, the scan engine with decision D2, CBOM and scoring with WP6."""

    async def run(self, scan: Scan, workdir: str) -> None:
        await self.get_access_token(scan)
        await self.clone(scan, workdir)
        await self.scan_source(workdir)

    async def get_access_token(self, scan: Scan) -> str:
        raise ScanError("Repository access is not available yet.")

    async def clone(self, scan: Scan, workdir: str) -> None:
        raise ScanError("Repository cloning is not available yet.")

    async def scan_source(self, workdir: str) -> list[dict]:
        raise ScanError("The scan engine is not available yet.")


async def startup(ctx: dict) -> None:
    ctx["engine"] = make_engine()
    ctx["sessionmaker"] = async_sessionmaker(ctx["engine"], expire_on_commit=False)


async def shutdown(ctx: dict) -> None:
    await ctx["engine"].dispose()


async def scan_repository(
    ctx: dict,
    installation_id: int,
    repo_full_name: str,
    triggered_by: str = "manual",
    pipeline: ScanPipeline | None = None,
) -> int | None:
    """Run one scan of `repo_full_name` for the GitHub installation `installation_id`.

    Returns the scan id, or None when the installation is unknown.
    """
    pipeline = pipeline or ScanPipeline()
    async with ctx["sessionmaker"]() as db:
        installation = await db.scalar(
            select(Installation).where(Installation.github_installation_id == installation_id)
        )
        if installation is None:
            logger.warning("scan requested for unknown installation %s", installation_id)
            return None
        scan = Scan(
            installation_id=installation.id,
            repo_full_name=repo_full_name,
            triggered_by=triggered_by,
            status=ScanStatus.RUNNING,
        )
        db.add(scan)
        await db.commit()
        logger.info("scan %s started (installation %s)", scan.id, installation_id)

        workdir = await asyncio.to_thread(tempfile.mkdtemp, prefix=f"quantsiv_scan_{scan.id}_")
        try:
            async with asyncio.timeout(SCAN_TIMEOUT):
                await pipeline.run(scan, workdir)
            scan.status = ScanStatus.DONE
        except ScanError as exc:
            scan.status, scan.error_message = ScanStatus.FAILED, str(exc)
        except TimeoutError:
            scan.status, scan.error_message = ScanStatus.FAILED, "The scan timed out."
        except Exception:
            # Details (which can include repo names or git output) go to the logs only (A15)
            logger.exception("scan %s failed", scan.id)
            scan.status, scan.error_message = ScanStatus.FAILED, "Internal error"
        finally:
            await asyncio.to_thread(shutil.rmtree, workdir, ignore_errors=True)
            scan.completed_at = utcnow()
            await db.commit()
        logger.info("scan %s is now %s", scan.id, scan.status)
        return scan.id


async def handle_github_event(ctx: dict, event: str, payload: dict) -> str:
    """Process a verified GitHub webhook (A12, A13). Returns what was done, for the job result.

    Account names are logged at DEBUG only (A25).
    """
    action = payload.get("action")
    if event == "installation":
        installation = payload.get("installation") or {}
        account = installation.get("account") or {}  # not payload["account"] (A12)
        logger.info("installation %s: %s", action, installation.get("id"))
        logger.debug("installation account %s (%s)", account.get("login"), account.get("type"))
        if action == "created":
            await _save_installation(ctx, installation, account, payload.get("sender") or {})
        # "deleted" and the data purge belong to the erasure runbook (WP8, A35)
        return f"installation-{action}"
    if event == "push":
        repo = payload.get("repository") or {}
        if payload.get("deleted"):
            return "ignored-deleted-branch"
        if not repo.get("default_branch") or payload.get("ref") != (
            f"refs/heads/{repo['default_branch']}"
        ):
            return "ignored-non-default-ref"  # tags, other and nested branches (A13)
        await ctx["redis"].enqueue_job(
            "scan_repository",
            payload["installation"]["id"],
            repo["full_name"],
            triggered_by="push",
        )
        return "scan-queued"
    return f"ignored-{event}"


async def _save_installation(ctx: dict, installation: dict, account: dict, sender: dict) -> None:
    async with ctx["sessionmaker"]() as db:
        row = await db.scalar(
            select(Installation).where(Installation.github_installation_id == installation["id"])
        )
        if row is None:
            row = Installation(github_installation_id=installation["id"])
            db.add(row)
        row.account_name = account["login"]
        row.account_type = account["type"]
        if sender.get("id") and sender.get("login"):
            # The GitHub user who installed the app owns it in Quantsiv
            row.user = await upsert_user(db, sender["id"], sender["login"])
        await db.commit()


async def delete_account(ctx: dict, user_id: int) -> None:
    logger.info("delete_account: not implemented until WP8")


class WorkerSettings:
    functions: ClassVar[list] = [scan_repository, handle_github_event, delete_account]
    on_startup = startup
    on_shutdown = shutdown
    redis_settings = RedisSettings.from_dsn(get_settings().redis_url)
    job_timeout = 600
    max_jobs = 2
    keep_result = 3600
