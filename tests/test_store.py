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


async def test_repo_access_needs_github_and_ownership():
    from app.scans import GitHubRepoAccess
    from tests.github_mock import FakeGitHub

    async with get_sessionmaker()() as db:
        dave = User(github_user_id=5201, github_login="dave")
        db.add(
            Installation(
                github_installation_id=6201, account_name="dave", account_type="User", user=dave
            )
        )
        await db.commit()
        covered = GitHubRepoAccess(db, FakeGitHub(installation=6201).app())
        assert await covered.installation_for(5201, "dave/tool") == 6201
        assert await covered.installation_for(5999, "dave/tool") is None  # not the owner
        uncovered = GitHubRepoAccess(db, FakeGitHub(installation=None).app())
        assert await uncovered.installation_for(5201, "dave/tool") is None


async def test_cbom_download_is_scoped():
    from fastapi.testclient import TestClient

    from app.main import app
    from tests.helpers import sign_in

    async with get_sessionmaker()() as db:
        erin = User(github_user_id=5301, github_login="erin")
        db.add(
            Scan(
                installation=Installation(
                    github_installation_id=6301, account_name="erin", account_type="User", user=erin
                ),
                repo_full_name="erin/app",
                triggered_by="manual",
                status=ScanStatus.DONE,
                cbom=CbomSnapshot(cbom_json={"bomFormat": "CycloneDX", "specVersion": "1.6"}),
            )
        )
        await db.commit()
        scan_id = (await db.scalar(select_scan("erin/app"))).id
    with TestClient(app) as client:
        sign_in(client, user={"id": 5301, "login": "erin"})
        response = client.get(f"/api/scans/{scan_id}/cbom")
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("application/vnd.cyclonedx+json")
        assert "attachment" in response.headers["content-disposition"]
        assert response.json()["specVersion"] == "1.6"
        page = client.get(f"/dashboard/scans/{scan_id}").text
        assert f'href="/api/scans/{scan_id}/cbom"' in page
    with TestClient(app) as other:
        sign_in(other, user={"id": 5302, "login": "frank"})
        assert other.get(f"/api/scans/{scan_id}/cbom").status_code == 404


def select_scan(repo):
    from sqlalchemy import select

    return select(Scan).where(Scan.repo_full_name == repo)
