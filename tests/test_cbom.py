"""CBOM builder (A26): CycloneDX 1.6 strict validation, lifetime property round-trip (D6)."""

import json

from cyclonedx.schema import SchemaVersion
from cyclonedx.validation.json import JsonStrictValidator

from app.services.cbom import LIFETIME_PROPERTY, build_cbom

FINDINGS = [
    {
        "file_path": "auth/jwt.py",
        "line_number": 47,
        "algorithm": "RSA",
        "primitive": "signature",
        "key_size": 2048,
        "quantum_safe": False,
        "track": "signature deadline",
    },
    {
        "file_path": "net/kex.py",
        "algorithm": "ECDH",
        "primitive": "key-agree",
        "track": "HNDL",
        "lifetime_years": 25,
    },
]


def validate(text: str) -> None:
    assert JsonStrictValidator(SchemaVersion.V1_6).validate_str(text) is None


def test_cbom_is_valid_cyclonedx_1_6():
    out = build_cbom(FINDINGS, "o/r")
    validate(out)
    assert '"type": "cryptographic-asset"' in out
    doc = json.loads(out)
    assert doc["specVersion"] == "1.6"
    assert doc["metadata"]["component"]["name"] == "o/r"
    assert len(doc["components"]) == 2


def test_empty_scan_is_still_a_valid_cbom():
    validate(build_cbom([], "o/r"))


def test_lifetime_property_survives_a_strict_round_trip():
    doc = json.loads(build_cbom(FINDINGS, "o/r"))
    reparsed = json.loads(json.dumps(doc))
    validate(json.dumps(reparsed))
    ecdh = next(c for c in reparsed["components"] if c["name"] == "ECDH")
    assert {"name": LIFETIME_PROPERTY, "value": "25"} in ecdh["properties"]
    rsa = next(c for c in reparsed["components"] if c["name"] == "RSA-2048")
    assert all(p["name"] != LIFETIME_PROPERTY for p in rsa.get("properties", []))


def test_primitives_are_mapped():
    doc = json.loads(build_cbom(FINDINGS, "o/r"))
    primitives = {
        c["name"]: c["cryptoProperties"]["algorithmProperties"]["primitive"]
        for c in doc["components"]
    }
    assert primitives == {"RSA-2048": "signature", "ECDH": "key-agree"}
