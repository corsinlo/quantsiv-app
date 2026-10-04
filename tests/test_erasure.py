"""Uninstall purges an installation's data; delete_account erases a user (A35, WP8)."""

from sqlalchemy import func, select

from app import worker
from app.models import (
    ApiToken,
    AuditEvent,
    CbomSnapshot,
    Finding,
    Installation,
    Scan,
    ScanStatus,
    User,
)


async def seed(ctx, user_id: int, installation_id: int) -> None:
    async with ctx["sessionmaker"]() as db:
        user = User(github_user_id=user_id, github_login=f"u{user_id}")
        installation = Installation(
            github_installation_id=installation_id,
            account_name=f"org{installation_id}",
            account_type="Organization",
            user=user,
        )
        db.add(
            Scan(
                installation=installation,
                repo_full_name=f"org{installation_id}/app",
                triggered_by="push",
                status=ScanStatus.DONE,
                findings=[Finding(algorithm="RSA", severity="high")],
                cbom=CbomSnapshot(cbom_json={}, risk_score=1),
            )
        )
        db.add(
            ApiToken(installation=installation, name="ci", token_hash=b"x" * 32, prefix="qsv_xxxx")
        )
        await db.flush()
        db.add(AuditEvent(installation_id=installation.id, kind="gate", data={}))
        await db.commit()


async def counts(ctx, installation_id: int) -> dict:
    async with ctx["sessionmaker"]() as db:
        inst = await db.scalar(
            select(Installation).where(Installation.github_installation_id == installation_id)
        )
        if inst is None:
            return {"installation": 0}
        return {
            "installation": 1,
            "scans": await db.scalar(
                select(func.count()).select_from(Scan).where(Scan.installation_id == inst.id)
            ),
            "tokens": await db.scalar(
                select(func.count())
                .select_from(ApiToken)
                .where(ApiToken.installation_id == inst.id)
            ),
            "audit": await db.scalar(
                select(func.count())
                .select_from(AuditEvent)
                .where(AuditEvent.installation_id == inst.id)
            ),
        }


async def test_uninstall_purges_everything_derived_from_the_installation(worker_ctx):
    await seed(worker_ctx, 9101, 9102)
    assert (await counts(worker_ctx, 9102))["scans"] == 1
    payload = {"action": "deleted", "installation": {"id": 9102, "account": {"login": "org9102"}}}
    assert (
        await worker.handle_github_event(worker_ctx, "installation", payload)
        == "installation-deleted"
    )
    assert await counts(worker_ctx, 9102) == {"installation": 0}
    async with worker_ctx["sessionmaker"]() as db:
        assert (
            await db.scalar(select(func.count()).select_from(Finding)) is not None
        )  # table intact
        assert (
            await db.scalar(select(User).where(User.github_user_id == 9101)) is not None
        )  # user kept


async def test_delete_account_erases_the_user_and_their_installations(worker_ctx):
    await seed(worker_ctx, 9201, 9202)
    result = await worker.delete_account(worker_ctx, 9201)
    assert result == {"user": True, "installations": 1}
    assert await counts(worker_ctx, 9202) == {"installation": 0}
    async with worker_ctx["sessionmaker"]() as db:
        assert await db.scalar(select(User).where(User.github_user_id == 9201)) is None
    assert await worker.delete_account(worker_ctx, 9201) == {"user": False, "installations": 0}


async def test_authorization_revoked_queues_delete_account(worker_ctx):
    calls = []

    class Redis:
        async def enqueue_job(self, *args, **kwargs):
            calls.append(args)

    ctx = {**worker_ctx, "redis": Redis()}
    payload = {"action": "revoked", "sender": {"id": 9301, "login": "x"}}
    result = await worker.handle_github_event(ctx, "github_app_authorization", payload)
    assert result == "authorization-revoked"
    assert calls == [("delete_account", 9301)]


async def test_purge_of_unknown_installation_is_a_no_op(worker_ctx):
    assert await worker.purge_installation(worker_ctx, 424242) == 0
    assert await worker.purge_installation(worker_ctx, None) == 0
