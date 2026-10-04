"""The database-backed ScanStore: tenancy enforced in SQL (A14, WP4)."""

from app.db import get_sessionmaker
from app.models import CbomSnapshot, Finding, Installation, Scan, ScanStatus, User
from app.scans import DbScanStore


async def _seed():
    async with get_sessionmaker()() as db:
        alice = User(github_user_id=5001, github_login="alice")
        bob = User(github_user_id=5002, github_login="bob")
        alice_inst = Installation(
            github_installation_id=6001,
            account_name="alice-org",
            account_type="Organization",
            user=alice,
        )
        bob_inst = Installation(
            github_installation_id=6002, account_name="bob", account_type="User", user=bob
        )
        alice_scan = Scan(
            installation=alice_inst,
            repo_full_name="alice-org/app",
            triggered_by="push",
            status=ScanStatus.DONE,
            findings=[Finding(algorithm="RSA", primitive="signature", severity="medium")],
            cbom=CbomSnapshot(cbom_json={}, risk_score=12),
        )
        bob_scan = Scan(installation=bob_inst, repo_full_name="bob/secret", triggered_by="push")
        db.add_all([alice_scan, bob_scan])
        await db.commit()
        return alice_scan.id, bob_scan.id


async def test_users_see_only_their_installations_scans():
    alice_scan, bob_scan = await _seed()
    async with get_sessionmaker()() as db:
        store = DbScanStore(db)
        scan = await store.get(alice_scan, 5001)
        assert scan["repo_full_name"] == "alice-org/app"
        assert scan["risk_score"] == 12
        assert scan["findings"][0]["primitive"] == "signature"
        assert await store.get(bob_scan, 5001) is None  # another tenant: same as missing
        assert [s["repo_full_name"] for s in await store.list_recent(5001)] == ["alice-org/app"]
        assert await store.list_recent(5999) == []


async def test_sign_in_creates_the_user_and_the_dashboard_shows_their_scans():
    from fastapi.testclient import TestClient
    from sqlalchemy import select

    from app.main import app
    from tests.helpers import sign_in

    user = {"id": 5101, "login": "carol"}
    with TestClient(app) as client:
        sign_in(client, user=user)
        async with get_sessionmaker()() as db:
            row = await db.scalar(select(User).where(User.github_user_id == 5101))
            assert row.github_login == "carol"
            db.add(
                Scan(
                    installation=Installation(
                        github_installation_id=6101,
                        account_name="carol",
                        account_type="User",
                        user=row,
                    ),
                    repo_full_name="carol/tool",
                    triggered_by="push",
                    status=ScanStatus.FAILED,
                    error_message="The scan engine is not available yet.",
                )
            )
            await db.commit()
        html = client.get("/dashboard").text
        assert "carol/tool" in html
        assert 'id="scans-empty"' not in html
