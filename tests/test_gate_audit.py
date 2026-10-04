"""The upload gate uses the shared policy function and records an audit event (WP10)."""

import json

from app.services.cbom import build_cbom
from quantsiv_scanner.policy import parse_policy
from tests.test_ingest import (  # noqa: F401
    asset,
    client,
    create_token,
    owner,
    third_party_cbom,
    upload,
)

POLICY = parse_policy(
    "policy:\n  allowed_algorithms: [Ed25519]\n"
    "  exceptions:\n    - {asset: DSA, approver: Jane Doe, expires: 2099-01-01, reason: legacy}\n"
)


def quantsiv_cbom(findings, repo):
    return build_cbom(
        findings, repo, properties={"policy": json.dumps(POLICY.as_dict(), sort_keys=True)}
    ).encode()


def test_upload_gate_applies_the_embedded_policy_and_records_audit(client, owner):  # noqa: F811
    token = create_token(client, owner["installation"])
    first = upload(client, token, third_party_cbom(), repo="gina-org/gated").json()
    assert first["gate"] == "pass"
    body = quantsiv_cbom(
        [
            {"algorithm": "Ed25519", "primitive": "signature", "file_path": "a.py"},
            {"algorithm": "DSA", "primitive": "signature", "file_path": "b.py"},
            {"algorithm": "ECDH", "primitive": "key-agree", "file_path": "c.py"},
        ],
        "gina-org/gated",
    )
    result = upload(client, token, body, repo="gina-org/gated").json()
    assert result["gate"] == "fail"
    assert result["new_quantum_vulnerable"] == ["ECDH"]  # Ed25519 allowed, DSA excepted
    verdict = result["verdict"]
    assert [e["algorithm"] for e in verdict["excepted"]] == ["DSA"]
    assert verdict["excepted"][0]["exception"]["approver"] == "Jane Doe"
    blocked = verdict["blocking"][0]
    # No lifetime is declared for this repo, so it is a severity, not HNDL, and cites IR 8547
    assert blocked["track"] == "severity" and "NIST IR 8547" in blocked["authority"]

    audit = client.get("/api/v1/audit", headers={"Authorization": f"Bearer {token}"}).json()
    gates = [
        e
        for e in audit["events"]
        if e["kind"] == "gate" and e["data"]["repository"] == "gina-org/gated"
    ]
    assert gates[0]["scan_id"] == result["scan_id"] and gates[0]["data"]["gate"] == "fail"
    assert gates[1]["data"]["gate"] == "pass"


def test_audit_export_needs_a_token():
    from fastapi.testclient import TestClient

    from app.main import app

    assert TestClient(app).get("/api/v1/audit").status_code == 401
