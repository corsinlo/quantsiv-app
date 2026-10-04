"""
ARQ worker for Quantsiv: GitHub events, repository scans and account deletion (A50).

Start it with `python -m arq app.worker.WorkerSettings`.
"""

import asyncio
import hashlib
import json
import logging
import os
import shutil
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
    Finding,
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
from app.services.lifetimes import Lifetimes, parse_lifetimes
from app.services.scoring import assess, is_quantum_vulnerable, rank_key, severity_score

logger = logging.getLogger(__name__)
configure_logging()

SCAN_TIMEOUT = 540  # seconds; below WorkerSettings.job_timeout so the scan is marked failed


MAX_REPO_KB = 500 * 1024  # GitHub reports size in KB; larger repos are refused before cloning
MAX_CONFIG_BYTES = 64 * 1024  # quantsiv.yml read from the (untrusted) cloned tree


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
        # D2: run the chosen engine through app.services.sandbox.run_limited
        raise ScanError("The scan engine is not available yet.")


def read_lifetimes(repo_root: str) -> Lifetimes:
    """quantsiv.yml from the repo root: a regular file, size-limited, never followed symlinks."""
    path = os.path.join(repo_root, "quantsiv.yml")
    if not os.path.isfile(path) or os.path.islink(path):
        return Lifetimes()
    if os.path.getsize(path) > MAX_CONFIG_BYTES:
        raise ScanError("quantsiv.yml is larger than 64 KB")
    with open(path, encoding="utf-8", errors="replace") as handle:
        return parse_lifetimes(handle.read())


async def record_results(
    db: AsyncSession, scan: Scan, installation: Installation, result: ScanResult
) -> None:
    """Score the engine's findings on the dual track (WP6), store them, and store the CBOM."""
    today = utcnow().date()
    scored = []
    for raw in result.findings:
        verdict = assess(raw, scan.repo_full_name, result.lifetimes, today)
        scored.append((verdict, raw))
    scored.sort(key=lambda pair: rank_key(pair[0]))
    rows = []
    for verdict, raw in scored:
        snippet = raw.get("raw_match")
        rows.append(
            Finding(
                file_path=raw.get("file_path"),
                line_number=raw.get("line_number"),
                algorithm=str(raw.get("algorithm") or "unknown")[:50],
                algorithm_family=raw.get("algorithm_family"),
                primitive=verdict.primitive,
                track=verdict.track,
                lifetime_years=verdict.lifetime_years,
                reason=verdict.reason,
                key_size=raw.get("key_size"),
                quantum_safe=not is_quantum_vulnerable(raw),
                severity=verdict.severity,
                confidence=raw.get("confidence"),
                context_label=raw.get("context_label"),
                # Raw code is opt-in per tenant; otherwise keep only its hash (A39)
                raw_match=snippet if snippet and installation.store_code_snippets else None,
                snippet_hash=hashlib.sha256(snippet.encode()).hexdigest() if snippet else None,
            )
        )
    scan.findings = rows
    cbom_input = [
        {**raw, "primitive": v.primitive, "track": v.track, "lifetime_years": v.lifetime_years}
        for v, raw in scored
    ]
    scan.cbom = CbomSnapshot(
        cbom_json=json.loads(build_cbom(cbom_input, scan.repo_full_name)),
        risk_score=severity_score([v.severity for v, _ in scored]),
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
