"""The policy and the gate function (WP10): deterministic, exceptions need approver and expiry."""

from datetime import date

import pytest

from app.services.errors import ScanError
from quantsiv_scanner.policy import (
    Policy,
    evaluate,
    explain,
    parse_policy,
    policy_from_dict,
    verdict_from_dict,
)

TODAY = date(2026, 10, 4)
TEXT = """
data_classes:
  records: {confidentiality_lifetime_years: 25}
  public: {confidentiality_lifetime_years: 0}
repositories:
  o/r: records
  o/site: public
policy:
  allowed_algorithms: [Ed25519]
  data_classes:
    public: {blocked_primitives: [signature]}
  exceptions:
    - asset: RSA-2048
      path: "legacy/*"
      approver: Jane Doe
      expires: 2027-06-30
      reason: vendor SDK
"""


def test_default_policy_blocks_every_new_quantum_vulnerable_asset():
    verdict = evaluate([{"algorithm": "RSA", "primitive": "signature"}], [], "o/r", Policy(), TODAY)
    assert not verdict.passed
    assert verdict.blocking[0].track == "signature deadline"
    assert "EO 14412" in verdict.blocking[0].authority
    assert "ML-DSA" in verdict.blocking[0].alternatives


def test_nothing_added_passes():
    verdict = evaluate([], [{"algorithm": "RSA"}], "o/r", Policy(), TODAY)
    assert verdict.passed and verdict.removed == ("RSA",)
    assert verdict.summary == "no cryptographic assets added"


def test_quantum_safe_additions_pass():
    verdict = evaluate(
        [{"algorithm": "ML-KEM", "key_size": 768}, {"algorithm": "AES"}], [], "o/r", Policy(), TODAY
    )
    assert verdict.passed
    assert all(not e.quantum_vulnerable for e in verdict.added)


def test_allowed_algorithms_exceptions_and_class_primitives():
    policy = parse_policy(TEXT)
    added = [
        {"algorithm": "ECDH", "primitive": "key-agree", "file_path": "net.py"},
        {
            "algorithm": "RSA",
            "key_size": 2048,
            "primitive": "signature",
            "file_path": "legacy/x.py",
        },
        {"algorithm": "RSA", "key_size": 2048, "primitive": "signature", "file_path": "new/x.py"},
        {"algorithm": "Ed25519", "primitive": "signature"},
    ]
    verdict = evaluate(added, [], "o/r", policy, TODAY)
    by = {(e.algorithm, e.file_path): e for e in verdict.added}
    assert by[("ECDH", "net.py")].blocking and by[("ECDH", "net.py")].track == "HNDL"
    assert by[("ECDH", "net.py")].lifetime_years == 25
    legacy = by[("RSA", "legacy/x.py")]
    assert not legacy.blocking and legacy.exception == {
        "approver": "Jane Doe",
        "expires": "2027-06-30",
        "reason": "vendor SDK",
    }
    assert by[("RSA", "new/x.py")].blocking  # the exception is path-scoped
    assert not by[("Ed25519", None)].blocking  # allowed by name
    assert not verdict.passed
    # On the public site only new signatures are blocked
    site = evaluate([{"algorithm": "ECDH", "primitive": "key-agree"}], [], "o/site", policy, TODAY)
    assert site.passed
    assert verdict.as_dict()["blocking"][0]["algorithm"] == "ECDH"


def test_expired_exception_does_not_apply():
    policy = parse_policy(TEXT)
    finding = {
        "algorithm": "RSA",
        "key_size": 2048,
        "primitive": "signature",
        "file_path": "legacy/x.py",
    }
    assert not explain(finding, "o/r", policy, TODAY).blocking
    assert explain(finding, "o/r", policy, date(2027, 7, 1)).blocking


def test_code_signing_is_explained_on_the_signature_track_never_hndl():
    policy = parse_policy(TEXT)
    e = explain({"algorithm": "ECDSA", "context_label": "Code signing"}, "o/r", policy, TODAY)
    assert e.track == "signature deadline"
    assert "HNDL" not in e.reason and "HNDL" not in e.track
    assert "31 Dec 2031" in e.authority
    assert e.severity == "high"


@pytest.mark.parametrize(
    "text",
    [
        "policy: [1]",
        "policy: {blocked_primitives: [magic]}",
        "policy: {exceptions: [{asset: RSA, expires: 2027-01-01}]}",
        "policy: {exceptions: [{asset: RSA, approver: A}]}",
        "policy: {exceptions: [{asset: RSA, approver: A, expires: soon}]}",
        "policy: {data_classes: {undeclared: {}}}",
        "policy: {block_new_quantum_vulnerable: maybe}",
    ],
)
def test_invalid_policy_is_a_clear_error(text):
    with pytest.raises(ScanError, match="quantsiv.yml"):
        parse_policy(text)


def test_policy_and_verdict_round_trip():
    policy = parse_policy(TEXT)
    assert policy_from_dict(policy.as_dict()) == policy
    verdict = evaluate(
        [{"algorithm": "ECDH", "primitive": "key-agree"}],
        [{"algorithm": "DSA"}],
        "o/r",
        policy,
        TODAY,
    )
    again = verdict_from_dict(verdict.as_dict())
    assert again.as_dict() == verdict.as_dict()


def test_verdicts_are_deterministic():
    policy = parse_policy(TEXT)
    added = [
        {"algorithm": a, "primitive": p}
        for a, p in (("RSA", "pke"), ("ECDH", "key-agree"), ("DSA", "signature"))
    ]
    first = evaluate(added, [], "o/r", policy, TODAY).as_dict()
    assert all(
        evaluate(list(reversed(added)), [], "o/r", policy, TODAY).as_dict() == first
        for _ in range(3)
    )
