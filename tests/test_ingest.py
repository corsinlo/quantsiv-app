"""CBOM ingest and export with organisation tokens (WP7)."""

import json
import re

import pytest
from cyclonedx.schema import SchemaVersion
from cyclonedx.validation.json import JsonStrictValidator
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.db import get_sessionmaker
from app.main import app
from app.models import ApiToken, Installation, User
from app.routers import v1
from app.services.cbom import build_cbom
from app.services.tokens import hash_token
from tests.helpers import csrf, sign_in


def asset(name, primitive, path, level=0, lifetime=None):
    component = {
        "type": "cryptographic-asset",
        "bom-ref": f"{name}@{path}",
        "name": name,
        "cryptoProperties": {
            "assetType": "algorithm",
            "algorithmProperties": {"primitive": primitive, "nistQuantumSecurityLevel": level},
        },
        "evidence": {"occurrences": [{"location": path, "line": 3}]},
    }
    if lifetime is not None:
        component["properties"] = [
            {"name": "quantsiv:confidentiality-lifetime-years", "value": str(lifetime)}
        ]
    return component


def third_party_cbom(*components) -> bytes:
    """Shaped like CBOMkit output: a CycloneDX 1.6 CBOM produced by another tool."""
    return json.dumps(
        {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
            "version": 1,
            "metadata": {
                "timestamp": "2026-10-04T08:00:00Z",
                "tools": {
                    "components": [{"type": "application", "name": "cbomkit", "version": "2.1"}]
                },
            },
            "components": list(components),
        }
    ).encode()


async def _installation(db, github_id, account, user_id, login):
    row = await db.scalar(
        select(Installation).where(Installation.github_installation_id == github_id)
    )
    if row is None:
        user = await db.scalar(select(User).where(User.github_user_id == user_id))
        row = Installation(
            github_installation_id=github_id,
            account_name=account,
            account_type="Organization",
            user=user or User(github_user_id=user_id, github_login=login),
        )
        db.add(row)
        await db.commit()
    return row.id


@pytest.fixture
async def owner():
    async with get_sessionmaker()() as db:
        return {
            "installation": await _installation(db, 7702, "gina-org", 7701, "gina"),
            "other_installation": await _installation(db, 7703, "hank", 7704, "hank"),
        }


@pytest.fixture
def client(owner):
    with TestClient(app) as c:
        sign_in(c, user={"id": 7701, "login": "gina"})
        yield c


def create_token(client, installation_id, name="ci") -> str:
    response = client.post(
        "/dashboard/tokens",
        data={"installation_id": installation_id, "name": name, "csrf_token": csrf(client)},
    )
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    return re.search(r'id="new-token"[^>]*value="(qsv_[^"]+)"', response.text).group(1)


def upload(client, token, body, repo="gina-org/payments"):
    return client.post(
        "/api/v1/cbom",
        params={"repository": repo},
        content=body,
        headers={"Authorization": f"Bearer {token}"},
    )


async def test_token_is_shown_once_and_stored_hashed(client, owner):
    token = create_token(client, owner["installation"])
    page = client.get("/dashboard/tokens").text
    assert token not in page
    assert token[:8] in page
    async with get_sessionmaker()() as db:
        row = await db.scalar(select(ApiToken).where(ApiToken.prefix == token[:8]))
        assert row.token_hash == hash_token(token)


def test_no_tokens_for_someone_elses_installation(client, owner):
    response = client.post(
        "/dashboard/tokens",
        data={
            "installation_id": owner["other_installation"],
            "name": "x",
            "csrf_token": csrf(client),
        },
    )
    assert response.status_code == 404


def test_token_creation_needs_csrf(client, owner):
    response = client.post(
        "/dashboard/tokens", data={"installation_id": owner["installation"], "name": "x"}
    )
    assert response.status_code == 403


@pytest.mark.parametrize(
    "header", [None, "Bearer nope", "Basic qsv_x", "Bearer qsv_not-a-real-token"]
)
def test_upload_needs_a_valid_token(header):
    headers = {"Authorization": header} if header else {}
    response = TestClient(app).post(
        "/api/v1/cbom", params={"repository": "o/r"}, content=b"{}", headers=headers
    )
    assert response.status_code == 401


def test_revoked_tokens_stop_working(client, owner):
    token = create_token(client, owner["installation"])
    assert upload(client, token, third_party_cbom()).status_code == 201
    page = client.get("/dashboard/tokens").text
    token_id = re.search(r'action="/dashboard/tokens/(\d+)/revoke"', page).group(1)
    client.post(f"/dashboard/tokens/{token_id}/revoke", data={"csrf_token": csrf(client)})
    assert upload(client, token, third_party_cbom()).status_code == 401


@pytest.mark.parametrize(
    "body",
    [
        b"not json",
        json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1}).encode(),
        json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.6", "components": "x"}).encode(),
    ],
)
def test_only_valid_cyclonedx_1_6_is_accepted(client, owner, body):
    token = create_token(client, owner["installation"])
    assert upload(client, token, body).status_code == 422


@pytest.mark.parametrize("repo", ["no-slash", "a/../b", "x" * 150 + "/y"])
def test_repository_must_look_like_owner_name(client, owner, repo):
    token = create_token(client, owner["installation"])
    assert upload(client, token, third_party_cbom(), repo=repo).status_code == 422


def test_oversized_upload_is_413(client, owner, monkeypatch):
    token = create_token(client, owner["installation"])
    monkeypatch.setattr(v1, "MAX_CBOM", 100)
    assert upload(client, token, third_party_cbom(asset("RSA", "pke", "a.py"))).status_code == 413


def test_third_party_cbom_is_ingested_with_provenance_and_scored(client, owner):
    token = create_token(client, owner["installation"])
    body = third_party_cbom(
        asset("ECDH", "key-agree", "net/kex.py", lifetime=25),
        asset("ML-KEM-768", "kem", "net/pq.py", level=3),
    )
    response = upload(client, token, body, repo="gina-org/ledger")
    assert response.status_code == 201
    result = response.json()
    assert result["producer"] == "cbomkit 2.1"
    assert result["assets"] == 2
    assert result["baseline_scan_id"] is None
    assert result["new_quantum_vulnerable"] == ["ECDH"]  # ML-KEM is quantum-safe
    assert result["gate"] == "fail"
    page = client.get(f"/dashboard/scans/{result['scan_id']}").text
    assert "HNDL · 25-year data" in page  # the lifetime property drives the HNDL track
    assert "gina-org/ledger" in client.get("/dashboard").text


def test_gate_runs_on_the_delta(client, owner):
    token = create_token(client, owner["installation"])
    base = asset("RSA", "signature", "auth/jwt.py")
    first = upload(client, token, third_party_cbom(base), repo="gina-org/svc").json()
    same = upload(client, token, third_party_cbom(base), repo="gina-org/svc").json()
    assert (same["gate"], same["added"], same["baseline_scan_id"]) == ("pass", [], first["scan_id"])
    added = upload(
        client,
        token,
        third_party_cbom(base, asset("X25519", "key-agree", "tls.py")),
        repo="gina-org/svc",
    ).json()
    assert (added["gate"], added["new_quantum_vulnerable"]) == ("fail", ["X25519"])
    fixed = upload(
        client,
        token,
        third_party_cbom(asset("ML-KEM-768", "kem", "tls.py", level=3)),
        repo="gina-org/svc",
    ).json()
    assert fixed["gate"] == "pass"
    assert fixed["removed"] == ["RSA", "X25519"]


def test_quantsiv_cboms_round_trip(client, owner):
    token = create_token(client, owner["installation"])
    body = build_cbom(
        [
            {
                "algorithm": "ECDH",
                "primitive": "key-agree",
                "file_path": "k.py",
                "track": "HNDL",
                "lifetime_years": 30,
            }
        ],
        "gina-org/roundtrip",
    ).encode()
    result = upload(client, token, body, repo="gina-org/roundtrip").json()
    assert result["assets"] == 1


def test_estate_export_is_valid_cyclonedx_and_scoped(client, owner):
    token = create_token(client, owner["installation"])
    upload(client, token, third_party_cbom(asset("RSA", "pke", "a.py")), repo="gina-org/a")
    upload(client, token, third_party_cbom(asset("RSA", "pke", "a.py")), repo="gina-org/b")
    response = client.get("/api/v1/cbom", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/vnd.cyclonedx+json")
    assert JsonStrictValidator(SchemaVersion.V1_6).validate_str(response.text) is None
    doc = response.json()
    repos = {
        p["value"]
        for c in doc["components"]
        for p in c["properties"]
        if p["name"] == "quantsiv:repository"
    }
    assert {"gina-org/a", "gina-org/b"} <= repos
    with TestClient(app) as hank:
        sign_in(hank, user={"id": 7704, "login": "hank"})
        hank_token = create_token(hank, owner["other_installation"])
        other = hank.get("/api/v1/cbom", headers={"Authorization": f"Bearer {hank_token}"}).json()
        assert other["components"] == []
