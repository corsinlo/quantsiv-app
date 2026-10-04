"""Dual-track scoring (A28, A30, A53, D6)."""

from datetime import date

import pytest

from app.services.errors import ScanError
from app.services.lifetimes import DEFAULT_SIGNATURE_DEADLINE, Lifetimes, parse_lifetimes
from app.services.scoring import (
    TRACK_HNDL,
    TRACK_SEVERITY,
    TRACK_SIGNATURE,
    assess,
    primitive_for,
    rank_key,
    severity_score,
)

TODAY = date(2026, 10, 4)
DECLARED = Lifetimes(data_classes={"records": 25}, repositories={"o/r": "records"})


def test_long_lived_key_agreement_outranks_a_short_lived_token_signature():
    kex = assess({"algorithm": "ECDH"}, "o/r", DECLARED, TODAY)
    token = assess({"algorithm": "RSA", "context_label": "JWT signing"}, "o/r", DECLARED, TODAY)
    assert (kex.track, kex.severity, kex.lifetime_years) == (TRACK_HNDL, "critical", 25)
    assert (token.track, token.severity) == (TRACK_SIGNATURE, "medium")
    assert min([token, kex], key=rank_key) is kex


@pytest.mark.parametrize("context", ["Code signing", "Firmware signing", "CA root key"])
def test_code_signing_is_never_hndl(context):
    verdict = assess({"algorithm": "ECDSA", "context_label": context}, "o/r", DECLARED, TODAY)
    assert verdict.track == TRACK_SIGNATURE
    assert verdict.severity == "high"
    assert "HNDL" not in verdict.reason


def test_without_a_declared_lifetime_it_is_a_severity_not_hndl():
    verdict = assess({"algorithm": "X25519"}, "other/repo", DECLARED, TODAY)
    assert verdict.track == TRACK_SEVERITY
    assert verdict.lifetime_years is None


@pytest.mark.parametrize("algorithm", ["AES", "AES-128", "ChaCha20", "SHA-256", "ML-KEM-768"])
def test_symmetric_hash_and_pqc_are_not_quantum_vulnerable(algorithm):
    verdict = assess({"algorithm": algorithm, "key_size": 128}, "o/r", DECLARED, TODAY)
    assert verdict.severity == "info"


@pytest.mark.parametrize(
    "finding,primitive",
    [
        ({"algorithm": "RSA", "context_label": "Token signing"}, "signature"),
        ({"algorithm": "RSA", "context_label": "OAEP key transport"}, "pke"),
        ({"algorithm": "RSA"}, "unknown"),
        ({"algorithm": "ECDSA"}, "signature"),
        ({"algorithm": "Ed25519"}, "signature"),
        ({"algorithm": "DH"}, "key-agree"),
        ({"algorithm": "ML-KEM-768"}, "kem"),
        ({"algorithm": "X", "primitive": "pke"}, "pke"),
    ],
)
def test_primitive_mapping(finding, primitive):
    assert primitive_for(finding) == primitive


def test_signature_trust_lifetime_against_the_deadline():
    long = Lifetimes(signature_trust_years=10)
    short = Lifetimes(signature_trust_years=1)
    assert assess({"algorithm": "ECDSA"}, "o/r", long, TODAY).severity == "high"
    assert assess({"algorithm": "ECDSA"}, "o/r", short, TODAY).severity == "medium"
    assert DEFAULT_SIGNATURE_DEADLINE == date(2031, 12, 31)


def test_severity_score_caps():
    assert severity_score([]) == 0
    assert severity_score(["critical"] * 5) == 50
    assert severity_score(["critical"] * 5 + ["high"] * 5 + ["medium"] * 9) == 100
    assert severity_score(["info", "low"]) == 0


def test_parse_lifetimes():
    text = """
data_classes:
  records: {confidentiality_lifetime_years: 25}
repositories:
  o/r: records
signatures:
  deadline: 2031-12-31
  trust_lifetime_years: 10
"""
    lifetimes = parse_lifetimes(text)
    assert lifetimes.confidentiality_years("o/r") == 25
    assert lifetimes.signature_trust_years == 10
    assert parse_lifetimes(None) == Lifetimes()


@pytest.mark.parametrize(
    "text",
    [
        "data_classes: {x: {}}",
        "data_classes: {x: {confidentiality_lifetime_years: -1}}",
        "data_classes: {x: {confidentiality_lifetime_years: '25'}}",
        "repositories: {o/r: undeclared}",
        "signatures: {deadline: soon}",
        "[1, 2]",
        "key: [unclosed",
    ],
)
def test_invalid_quantsiv_yml_is_a_clear_scan_error(text):
    with pytest.raises(ScanError, match="quantsiv.yml"):
        parse_lifetimes(text)
