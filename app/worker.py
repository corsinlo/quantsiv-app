"""
ARQ worker for Quantsiv: GitHub events, repository scans and account deletion (A50).

Start it with `python -m arq app.worker.WorkerSettings`.
"""

import asyncio
import json
import logging
import os
import shutil
import sys
import tempfile
from dataclasses import dataclass
from typing import ClassVar

from arq.connections import RedisSettings
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.config import configure_logging, get_settings
from app.db import make_engine
from app.models import (
    CbomSnapshot,
    Installation,
    Scan,
    ScanStatus,
    upsert_user,
    utcnow,
)
from app.services.cbom import build_cbom
from app.services.clone import clone_repository
from app.services.errors import ScanError
from app.services.github import GitHubApp
from app.services.lifetimes import Lifetimes, read_lifetimes
from app.services.results import finding_rows, score
from app.services.sandbox import run_limited
from app.services.scoring import severity_score

logger = logging.getLogger(__name__)
configure_logging()

SCAN_TIMEOUT = 540  # seconds; below WorkerSettings.job_timeout so the scan is marked failed
APP_ROOT = os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))
)  # holds app/ and quantsiv_scanner/


MAX_REPO_KB = 500 * 1024  # GitHub reports size in KB; larger repos are refused before cloning


@dataclass
class ScanResult:
    findings: list[dict]  # engine output, one dict per cryptographic finding
    lifetimes: Lifetimes  # from the repository's quantsiv.yml, if any


class ScanPipeline:
    """The steps of one scan (A15, A16, A52). Hosted scanning covers public repositories only
    (D1): a private repository is refused before anything is cloned. The token is down-scoped
    to the one repository and revoked before the engine runs. The engine itself is decision D2:
    until it exists the scan fails with a clear message, never with invented findings (A29)."""

    def __init__(self, github: GitHubApp | None = None, max_repo_kb: int = MAX_REPO_KB):
        self.github = github or GitHubApp()
        self.max_repo_kb = max_repo_kb

    async def run(self, scan: Scan, workdir: str, installation_id: int) -> ScanResult:
        dest = os.path.join(workdir, "repo")
        async with self.github.installation_token(installation_id, scan.repo_full_name) as token:
            repo = await self.github.repository(token, scan.repo_full_name)
            if repo.get("private"):
                raise ScanError("Hosted scanning covers public repositories only.")
            if int(repo.get("size") or 0) > self.max_repo_kb:
                raise ScanError(
                    f"The repository is larger than the {self.max_repo_kb // 1024} MB scan limit."
                )
            await clone_repository(scan.repo_full_name, token, dest)
        lifetimes = await asyncio.to_thread(read_lifetimes, dest)
        return ScanResult(await self.scan_source(dest), lifetimes)

    async def scan_source(self, path: str) -> list[dict]:
        """The D2 engine: `quantsiv_scanner` as a separate, limited process on the cloned tree
        (no network isolation here; that is why only public repositories are scanned, D1)."""
        stdout = await run_limited(
            [sys.executable, "-m", "quantsiv_scanner", "scan", path, "--json"],
            cwd=path,
            env={"PYTHONPATH": APP_ROOT, "PYTHONDONTWRITEBYTECODE": "1"},
        )
        try:
            return json.loads(stdout)["findings"]
        except (ValueError, KeyError, TypeError):
            logger.warning("engine returned unreadable output")
            raise ScanError("The scanner produced no readable result.") from None


async def record_results(
    db: AsyncSession, scan: Scan, installation: Installation, result: ScanResult
) -> None:
    """Score the engine's findings on the dual track (WP6), store them, and store the CBOM."""
    scored = score(result.findings, scan.repo_full_name, result.lifetimes, utcnow().date())
    scan.findings = finding_rows(scored, installation)
    cbom_input = [
        {**raw, "primitive": v.primitive, "track": v.track, "lifetime_years": v.lifetime_years}
        for v, raw in scored
    ]
    scan.cbom = CbomSnapshot(
        cbom_json=json.loads(build_cbom(cbom_input, scan.repo_full_name)),
        risk_score=severity_score([v.severity for v, _ in scored]),
        producer="Quantsiv hosted scan",
    )


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
            findings=[],  # loaded-empty, so attaching results needs no lazy load
            cbom=None,
        )
        db.add(scan)
        await db.commit()
        logger.info("scan %s started (installation %s)", scan.id, installation_id)

        workdir = await asyncio.to_thread(tempfile.mkdtemp, prefix=f"quantsiv_scan_{scan.id}_")
        try:
            async with asyncio.timeout(SCAN_TIMEOUT):
                result = await pipeline.run(scan, workdir, installation_id)
            await record_results(db, scan, installation, result)
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
