"""Domain verification page and the hosted TLS scan job (A17)."""

from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app import worker
from app.db import get_sessionmaker
from app.main import app
from app.models import Domain, Installation, Scan, ScanStatus, TlsScan, User
from app.queue import get_queue
from app.services.tls import TlsProbe
from tests.fakes import FakeQueue
from tests.helpers import csrf, sign_in


async def _installation(db, github_id, account, user_id, login) -> int:
    row = await db.scalar(
        select(Installation).where(Installation.github_installation_id == github_id)
    )
    if row is None:
        row = Installation(
            github_installation_id=github_id,
            account_name=account,
            account_type="Organization",
            user=User(github_user_id=user_id, github_login=login),
        )
        db.add(row)
        await db.commit()
    return row.id


@pytest.fixture
async def owner():
    async with get_sessionmaker()() as db:
        return {
            "installation": await _installation(db, 8802, "dora-org", 8801, "dora"),
            "github_installation": 8802,
            "other": await _installation(db, 8804, "evan", 8803, "evan"),
        }


@pytest.fixture
def queue():
    q = FakeQueue()
    app.dependency_overrides[get_queue] = lambda: q
    yield q
    app.dependency_overrides.pop(get_queue, None)


@pytest.fixture
def client(owner, queue):
    with TestClient(app) as c:
        sign_in(c, user={"id": 8801, "login": "dora"})
        yield c


def add(client, installation, domain, lifetime=""):
    return client.post(
        "/dashboard/domains",
        data={
            "installation_id": installation,
            "domain": domain,
            "lifetime_years": lifetime,
            "csrf_token": csrf(client),
        },
        follow_redirects=True,
    )


async def row(domain) -> Domain:
    async with get_sessionmaker()() as db:
        return await db.scalar(select(Domain).where(Domain.domain == domain))


async def test_add_shows_the_txt_record_and_nothing_is_scanned(client, owner, queue):
    page = add(client, owner["installation"], "Api.Example.com", "25")
    assert page.status_code == 200
    assert "_quantsiv.api.example.com" in page.text
    token = (await row("api.example.com")).verification_token
    assert f"quantsiv-verify={token}" in page.text
    assert "Not verified" in page.text
    response = client.post(
        f"/dashboard/domains/{(await row('api.example.com')).id}/scan",
        data={"csrf_token": csrf(client)},
        follow_redirects=True,
    )
    assert "is not verified" in response.text
    assert queue.jobs == {}


@pytest.mark.parametrize("value", ["localhost", "10.0.0.1", "svc.railway.internal", "http://"])
def test_internal_and_malformed_names_are_refused(client, owner, value):
    assert "Enter a public host name" in add(client, owner["installation"], value).text


def test_lifetime_must_be_a_sensible_number(client, owner):
    assert (
        "whole number of years" in add(client, owner["installation"], "a.example.com", "500").text
    )


def test_cannot_add_to_someone_elses_installation(client, owner):
    response = client.post(
        "/dashboard/domains",
        data={
            "installation_id": owner["other"],
            "domain": "x.example.com",
            "csrf_token": csrf(client),
        },
    )
    assert response.status_code == 404


async def test_verify_fails_until_the_record_exists_then_scan_is_queued(
    client, owner, queue, monkeypatch
):
    add(client, owner["installation"], "ok.example.com")
    domain = await row("ok.example.com")
    monkeypatch.setattr("app.routers.domains.check_verification", lambda d, t: False)
    failed = client.post(
        f"/dashboard/domains/{domain.id}/verify",
        data={"csrf_token": csrf(client)},
        follow_redirects=True,
    )
    assert "was not found yet" in failed.text
    assert (await row("ok.example.com")).verified_at is None
    monkeypatch.setattr("app.routers.domains.check_verification", lambda d, t: True)
    done = client.post(
        f"/dashboard/domains/{domain.id}/verify",
        data={"csrf_token": csrf(client)},
        follow_redirects=True,
    )
    assert "is verified" in done.text
    queued = client.post(
        f"/dashboard/domains/{domain.id}/scan",
        data={"csrf_token": csrf(client)},
        follow_redirects=True,
    )
    assert "queued" in queued.text
    ((function, args, _),) = queue.jobs.values()
    assert (function, args) == ("scan_tls", (owner["github_installation"], "ok.example.com"))


async def test_domains_of_other_users_are_invisible(client, owner):
    async with get_sessionmaker()() as db:
        db.add(
            Domain(
                installation_id=owner["other"], domain="secret.example.com", verification_token="t"
            )
        )
        await db.commit()
        other = await db.scalar(select(Domain).where(Domain.domain == "secret.example.com"))
    assert "secret.example.com" not in client.get("/dashboard/domains").text
    for action in ("verify", "scan", "remove"):
        r = client.post(
            f"/dashboard/domains/{other.id}/{action}", data={"csrf_token": csrf(client)}
        )
        assert r.status_code == 404


def test_page_needs_sign_in_and_csrf(owner):
    anon = TestClient(app)
    assert anon.get("/dashboard/domains", follow_redirects=False).status_code in (302, 303, 307)
    with TestClient(app) as c:
        sign_in(c, user={"id": 8801, "login": "dora"})
        assert (
            c.post(
                "/dashboard/domains", data={"installation_id": 1, "domain": "a.example.com"}
            ).status_code
            == 403
        )


# --- the worker job -------------------------------------------------------------------------


def good_probe(domain):
    return TlsProbe(
        domain=domain,
        ip_address="203.0.113.7",
        tls_version="TLSv1.3",
        cipher_suite="TLS_AES_256_GCM_SHA384",
        key_exchange_group="x25519",
        pqc_key_exchange=False,
        cert_subject="CN=ok.example.com",
        cert_expiry=datetime(2030, 1, 1, tzinfo=UTC),
        cert_algorithm="RSA",
        cert_key_bits=2048,
    )


async def _seed(ctx, github_id, domain, verified, years=None):
    async with ctx["sessionmaker"]() as db:
        inst = Installation(github_installation_id=github_id, account_name="o", account_type="User")
        db.add(inst)
        await db.flush()
        db.add(
            Domain(
                installation_id=inst.id,
                domain=domain,
                verification_token="tok",
                verified_at=datetime.now(UTC) if verified else None,
                confidentiality_lifetime_years=years,
            )
        )
        await db.commit()


async def _scan(ctx, scan_id):
    async with ctx["sessionmaker"]() as db:
        scan = await db.get(Scan, scan_id)
        tls = list(await db.scalars(select(TlsScan).where(TlsScan.scan_id == scan_id)))
        from app.models import Finding

        findings = list(await db.scalars(select(Finding).where(Finding.scan_id == scan_id)))
        return scan, tls, findings


async def test_scan_tls_stores_probe_findings_and_cbom(worker_ctx):
    await _seed(worker_ctx, 8811, "ok.example.com", True, years=20)
    scan_id = await worker.scan_tls(
        worker_ctx,
        8811,
        "ok.example.com",
        probe=good_probe,
        lookup=lambda n: ["quantsiv-verify=tok"],
    )
    scan, tls, findings = await _scan(worker_ctx, scan_id)
    assert scan.status == ScanStatus.DONE and scan.scan_type == "tls"
    assert scan.repo_full_name == "ok.example.com"
    assert (tls[0].cert_algorithm, tls[0].cert_key_bits, tls[0].tls_version) == (
        "RSA",
        2048,
        "TLSv1.3",
    )
    kx = next(
        f
        for f in findings
        if f.context_label.startswith("TLS endpoint") and f.primitive == "key-agree"
    )
    assert (kx.track, kx.lifetime_years, kx.severity) == ("HNDL", 20, "critical")
    assert any(f.primitive == "signature" and f.track == "signature deadline" for f in findings)
    async with worker_ctx["sessionmaker"]() as db:
        from app.models import CbomSnapshot

        cbom = await db.scalar(select(CbomSnapshot).where(CbomSnapshot.scan_id == scan_id))
    assert cbom.producer == "Quantsiv hosted TLS scan"
    assert len(cbom.cbom_json["components"]) == len(findings)


async def test_unverified_domain_is_never_contacted(worker_ctx):
    await _seed(worker_ctx, 8812, "no.example.com", False)

    def boom(domain):
        raise AssertionError("contacted an unverified domain")

    assert await worker.scan_tls(worker_ctx, 8812, "no.example.com", probe=boom) is None
    assert await worker.scan_tls(worker_ctx, 8812, "other.example.com", probe=boom) is None
    assert await worker.scan_tls(worker_ctx, 999999, "no.example.com", probe=boom) is None


async def test_lost_record_unverifies_the_domain_and_skips_the_probe(worker_ctx):
    await _seed(worker_ctx, 8813, "gone.example.com", True)

    def boom(domain):
        raise AssertionError("contacted a domain whose record is gone")

    scan_id = await worker.scan_tls(
        worker_ctx, 8813, "gone.example.com", probe=boom, lookup=lambda n: []
    )
    scan, _, findings = await _scan(worker_ctx, scan_id)
    assert scan.status == ScanStatus.FAILED
    assert scan.error_message == "The DNS verification record is no longer published."
    assert findings == []
    async with worker_ctx["sessionmaker"]() as db:
        assert (
            await db.scalar(select(Domain).where(Domain.domain == "gone.example.com"))
        ).verified_at is None


async def test_probe_error_is_stored_as_a_failed_scan(worker_ctx):
    await _seed(worker_ctx, 8814, "down.example.com", True)
    failing = lambda d: TlsProbe(domain=d, ip_address="203.0.113.7", error="Connection failed")
    scan_id = await worker.scan_tls(
        worker_ctx,
        8814,
        "down.example.com",
        probe=failing,
        lookup=lambda n: ["quantsiv-verify=tok"],
    )
    scan, _, _ = await _scan(worker_ctx, scan_id)
    assert (scan.status, scan.error_message) == (ScanStatus.FAILED, "Connection failed")


async def test_purge_removes_domains(worker_ctx):
    await _seed(worker_ctx, 8815, "p.example.com", True)
    await worker.purge_installation(worker_ctx, 8815)
    async with worker_ctx["sessionmaker"]() as db:
        assert await db.scalar(select(Domain).where(Domain.domain == "p.example.com")) is None
