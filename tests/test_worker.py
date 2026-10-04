"""Worker jobs, called directly with a ctx on the test database (WP4 acceptance)."""

from sqlalchemy import select

from app import worker
from app.models import Installation, Scan, ScanStatus, User
from app.services.errors import ScanError


def test_worker_settings_register_the_jobs():
    names = {f.__name__ for f in worker.WorkerSettings.functions}
    assert names == {"scan_repository", "handle_github_event", "delete_account"}
    assert worker.WorkerSettings.on_startup is worker.startup
    assert worker.SCAN_TIMEOUT < worker.WorkerSettings.job_timeout


async def _installation(ctx, github_id: int) -> None:
    async with ctx["sessionmaker"]() as db:
        db.add(
            Installation(github_installation_id=github_id, account_name="o", account_type="User")
        )
        await db.commit()


async def _scan(ctx, scan_id: int) -> Scan:
    async with ctx["sessionmaker"]() as db:
        return await db.get(Scan, scan_id)


async def test_scan_for_unknown_installation_creates_nothing(worker_ctx):
    assert await worker.scan_repository(worker_ctx, 123456, "o/r") is None


async def test_scan_fails_honestly_until_the_pipeline_exists(worker_ctx):
    await _installation(worker_ctx, 8001)
    scan_id = await worker.scan_repository(worker_ctx, 8001, "o/r", triggered_by="push")
    scan = await _scan(worker_ctx, scan_id)
    assert scan.status == ScanStatus.FAILED
    assert scan.error_message == "Repository access is not available yet."
    assert scan.triggered_by == "push"
    assert scan.completed_at is not None


class Boom(worker.ScanPipeline):
    async def run(self, scan, workdir):
        raise RuntimeError("git said: https://x-access-token:ghs_SECRET@github.com/o/r")


async def test_unexpected_errors_are_stored_as_internal_error(worker_ctx):
    await _installation(worker_ctx, 8002)
    scan_id = await worker.scan_repository(worker_ctx, 8002, "o/r", pipeline=Boom())
    scan = await _scan(worker_ctx, scan_id)
    assert scan.status == ScanStatus.FAILED
    assert scan.error_message == "Internal error"  # never the exception text (A15)


class Works(worker.ScanPipeline):
    def __init__(self):
        self.workdirs = []

    async def run(self, scan, workdir):
        import os

        assert os.path.isdir(workdir)
        self.workdirs.append(workdir)


async def test_successful_pipeline_marks_done_and_cleans_up(worker_ctx):
    import os

    await _installation(worker_ctx, 8003)
    pipeline = Works()
    scan_id = await worker.scan_repository(worker_ctx, 8003, "o/r", pipeline=pipeline)
    assert (await _scan(worker_ctx, scan_id)).status == ScanStatus.DONE
    assert not os.path.exists(pipeline.workdirs[0])


class Slow(worker.ScanPipeline):
    async def run(self, scan, workdir):
        import asyncio

        await asyncio.sleep(5)


async def test_timeout_marks_the_scan_failed(worker_ctx, monkeypatch):
    monkeypatch.setattr(worker, "SCAN_TIMEOUT", 0.05)
    await _installation(worker_ctx, 8004)
    scan_id = await worker.scan_repository(worker_ctx, 8004, "o/r", pipeline=Slow())
    scan = await _scan(worker_ctx, scan_id)
    assert (scan.status, scan.error_message) == (ScanStatus.FAILED, "The scan timed out.")


async def test_installation_owner_is_the_sender(worker_ctx):
    payload = {
        "action": "created",
        "installation": {"id": 8005, "account": {"login": "acme", "type": "Organization"}},
        "sender": {"id": 9005, "login": "acme-admin"},
    }
    await worker.handle_github_event(worker_ctx, "installation", payload)
    async with worker_ctx["sessionmaker"]() as db:
        row = await db.scalar(
            select(Installation).where(Installation.github_installation_id == 8005)
        )
        owner = await db.get(User, row.user_id)
        assert owner.github_user_id == 9005


async def test_scan_error_is_user_safe():
    assert issubclass(ScanError, Exception)


async def test_delete_account_is_a_stub():
    assert await worker.delete_account({}, 1) is None
