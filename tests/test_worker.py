"""Worker jobs, called directly with a ctx on the test database (WP4 acceptance)."""

import shutil
from pathlib import Path

from sqlalchemy import select

from app import worker
from app.models import Installation, Scan, ScanStatus, User
from app.services.errors import ScanError
from app.services.lifetimes import Lifetimes
from tests.github_mock import FakeGitHub


def test_worker_settings_register_the_jobs():
    names = {f.__name__ for f in worker.WorkerSettings.functions}
    assert names == {"scan_repository", "scan_tls", "handle_github_event", "delete_account"}
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


async def _cloned(repo_full_name, token, dest, timeout=120):
    import os

    os.makedirs(dest)


FIXTURE = Path(__file__).parent / "scanner" / "fixtures" / "sample"


async def _cloned_fixture(repo_full_name, token, dest, timeout=120):
    shutil.copytree(FIXTURE, dest, symlinks=True)


async def test_public_repo_is_cloned_scanned_and_scored_end_to_end(worker_ctx, monkeypatch):
    """Clone (faked), the real engine in the sandbox, scoring with the repo's quantsiv.yml,
    findings and CBOM stored. The fixture declares a 25-year lifetime for acme/sample."""
    from sqlalchemy.orm import selectinload

    monkeypatch.setattr(worker, "clone_repository", _cloned_fixture)
    fake = FakeGitHub()
    await _installation(worker_ctx, 8001)
    scan_id = await worker.scan_repository(
        worker_ctx,
        8001,
        "acme/sample",
        triggered_by="push",
        pipeline=worker.ScanPipeline(fake.app()),
    )
    async with worker_ctx["sessionmaker"]() as db:
        scan = await db.scalar(
            select(Scan)
            .where(Scan.id == scan_id)
            .options(selectinload(Scan.findings), selectinload(Scan.cbom))
        )
    assert scan.status == ScanStatus.DONE, scan.error_message
    assert scan.triggered_by == "push"
    assert fake.calls()[-1] == ("DELETE", "/installation/token")  # revoked before the engine
    algorithms = {f.algorithm for f in scan.findings}
    assert {"RSA", "ECDH", "X25519", "ML-KEM", "AES-256-GCM"} <= algorithms
    ecdh = next(f for f in scan.findings if f.algorithm == "ECDH" and f.file_path == "src/app.py")
    assert (ecdh.track, ecdh.severity, ecdh.lifetime_years) == ("HNDL", "critical", 25)
    assert all(f.raw_match is None for f in scan.findings)  # snippets are opt-in (A39)
    assert scan.cbom.risk_score > 0
    assert scan.cbom.producer == "Quantsiv hosted scan"
    assert len(scan.cbom.cbom_json["components"]) == len(scan.findings)


async def test_engine_failure_is_a_fixed_message(worker_ctx, monkeypatch):
    async def broken(*args, **kwargs):
        return b"not json"

    monkeypatch.setattr(worker, "clone_repository", _cloned_fixture)
    monkeypatch.setattr(worker, "run_limited", broken)
    await _installation(worker_ctx, 8011)
    scan_id = await worker.scan_repository(
        worker_ctx, 8011, "acme/sample", pipeline=worker.ScanPipeline(FakeGitHub().app())
    )
    scan = await _scan(worker_ctx, scan_id)
    assert (scan.status, scan.error_message) == (
        ScanStatus.FAILED,
        "The scanner produced no readable result.",
    )


async def test_private_repos_are_refused_before_cloning(worker_ctx, monkeypatch):
    async def must_not_clone(*args, **kwargs):
        raise AssertionError("private repos must not be cloned (D1)")

    monkeypatch.setattr(worker, "clone_repository", must_not_clone)
    fake = FakeGitHub(private=True)
    await _installation(worker_ctx, 8006)
    scan_id = await worker.scan_repository(
        worker_ctx, 8006, "o/private", pipeline=worker.ScanPipeline(fake.app())
    )
    scan = await _scan(worker_ctx, scan_id)
    assert scan.error_message == "Hosted scanning covers public repositories only."
    assert ("DELETE", "/installation/token") in fake.calls()


async def test_oversized_repos_are_refused_before_cloning(worker_ctx, monkeypatch):
    monkeypatch.setattr(worker, "clone_repository", None)
    fake = FakeGitHub(size_kb=600 * 1024)
    await _installation(worker_ctx, 8007)
    scan_id = await worker.scan_repository(
        worker_ctx, 8007, "o/huge", pipeline=worker.ScanPipeline(fake.app())
    )
    assert "500 MB scan limit" in (await _scan(worker_ctx, scan_id)).error_message


class Boom(worker.ScanPipeline):
    async def run(self, scan, workdir, installation_id):
        raise RuntimeError("git said: https://x-access-token:ghs_SECRET@github.com/o/r")


async def test_unexpected_errors_are_stored_as_internal_error(worker_ctx):
    await _installation(worker_ctx, 8002)
    scan_id = await worker.scan_repository(worker_ctx, 8002, "o/r", pipeline=Boom(object()))
    scan = await _scan(worker_ctx, scan_id)
    assert scan.status == ScanStatus.FAILED
    assert scan.error_message == "Internal error"  # never the exception text (A15)


class Works(worker.ScanPipeline):
    def __init__(self):
        self.workdirs = []

    async def run(self, scan, workdir, installation_id):
        import os

        assert os.path.isdir(workdir)
        self.workdirs.append(workdir)
        return worker.ScanResult(findings=[], lifetimes=Lifetimes())


async def test_successful_pipeline_marks_done_and_cleans_up(worker_ctx):
    import os

    await _installation(worker_ctx, 8003)
    pipeline = Works()
    pipeline.github = None
    scan_id = await worker.scan_repository(worker_ctx, 8003, "o/r", pipeline=pipeline)
    assert (await _scan(worker_ctx, scan_id)).status == ScanStatus.DONE
    assert not os.path.exists(pipeline.workdirs[0])


class Slow(worker.ScanPipeline):
    async def run(self, scan, workdir, installation_id):
        import asyncio

        await asyncio.sleep(5)


async def test_timeout_marks_the_scan_failed(worker_ctx, monkeypatch):
    monkeypatch.setattr(worker, "SCAN_TIMEOUT", 0.05)
    await _installation(worker_ctx, 8004)
    scan_id = await worker.scan_repository(worker_ctx, 8004, "o/r", pipeline=Slow(object()))
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


async def test_delete_account_of_unknown_user(worker_ctx):
    assert await worker.delete_account(worker_ctx, 1) == {"user": False, "installations": 0}


ENGINE_OUTPUT = [
    {
        "algorithm": "RSA",
        "context_label": "JWT signing",
        "key_size": 2048,
        "file_path": "a.py",
        "raw_match": "jwt.encode(payload, key, 'RS256')",
    },
    {"algorithm": "ECDH", "file_path": "net.py", "line_number": 3},
    {"algorithm": "AES", "key_size": 128, "file_path": "store.py"},
]


class Engine(worker.ScanPipeline):
    def __init__(self, lifetimes):
        self.lifetimes = lifetimes

    async def run(self, scan, workdir, installation_id):
        return worker.ScanResult(findings=ENGINE_OUTPUT, lifetimes=self.lifetimes)


async def test_results_are_scored_ranked_and_stored_with_a_cbom(worker_ctx):
    from sqlalchemy.orm import selectinload

    lifetimes = Lifetimes(data_classes={"records": 25}, repositories={"o/r": "records"})
    await _installation(worker_ctx, 8010)
    scan_id = await worker.scan_repository(worker_ctx, 8010, "o/r", pipeline=Engine(lifetimes))
    async with worker_ctx["sessionmaker"]() as db:
        scan = await db.scalar(
            select(Scan)
            .where(Scan.id == scan_id)
            .options(selectinload(Scan.findings), selectinload(Scan.cbom))
        )
    assert scan.status == ScanStatus.DONE
    tracks = [(f.algorithm, f.track, f.severity) for f in scan.findings]
    assert tracks[0] == ("ECDH", "HNDL", "critical")  # 25-year data outranks the token signature
    assert ("RSA", "signature deadline", "medium") in tracks
    assert ("AES", "severity", "info") in tracks  # AES-128 is not quantum-vulnerable (A30)
    rsa = next(f for f in scan.findings if f.algorithm == "RSA")
    assert rsa.raw_match is None and len(rsa.snippet_hash) == 64  # snippets are opt-in (A39)
    assert scan.cbom.risk_score == 25 + 5  # one critical, one medium: a severity score
    components = scan.cbom.cbom_json["components"]
    assert any(
        p == {"name": "quantsiv:confidentiality-lifetime-years", "value": "25"}
        for c in components
        for p in c.get("properties", [])
    )


async def test_quantsiv_yml_is_read_safely(tmp_path):
    (tmp_path / "quantsiv.yml").write_text(
        "data_classes:\n  pii: {confidentiality_lifetime_years: 30}\nrepositories:\n  o/r: pii\n"
    )
    assert worker.read_lifetimes(str(tmp_path)).confidentiality_years("o/r") == 30
    assert worker.read_lifetimes(str(tmp_path / "missing")).data_classes == {}


async def test_symlinked_quantsiv_yml_is_ignored(tmp_path):
    (tmp_path / "secret").write_text("data_classes: {}")
    (tmp_path / "quantsiv.yml").symlink_to(tmp_path / "secret")
    assert worker.read_lifetimes(str(tmp_path)) == Lifetimes()
