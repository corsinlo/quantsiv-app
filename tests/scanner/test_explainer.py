"""The gate explainer renders track, lifetime, authority and alternatives for every new asset."""

from datetime import date

from quantsiv_scanner.explainer import check_run, gate_sarif, pr_comment
from quantsiv_scanner.policy import evaluate, parse_policy

TODAY = date(2026, 10, 4)
POLICY = parse_policy(
    "data_classes:\n  records: {confidentiality_lifetime_years: 25}\nrepositories: {o/r: records}\n"
    "policy:\n  exceptions:\n    - {asset: DSA, approver: Jane Doe, expires: 2027-01-01, reason: legacy}\n"
)
ADDED = [
    {"algorithm": "ECDH", "primitive": "key-agree", "file_path": "net/kex.py", "line_number": 3},
    {"algorithm": "ECDSA", "context_label": "Code signing", "file_path": "release/sign.py"},
    {"algorithm": "DSA", "primitive": "signature"},
    {"algorithm": "ML-KEM", "key_size": 768},
]


def test_pr_comment_explains_each_asset():
    verdict = evaluate(ADDED, [{"algorithm": "RSA"}], "o/r", POLICY, TODAY)
    text = pr_comment(verdict)
    assert text.startswith("## ❌ Quantsiv cryptography gate: fail")
    assert "| `ECDH` at `net/kex.py:3` | HNDL | 25 years | critical |" in text
    assert "ML-KEM (FIPS 203)" in text
    assert "| `ECDSA` at `release/sign.py` | signature deadline | not declared | high |" in text
    assert "ML-DSA (FIPS 204)" in text
    assert "allowed under exception (approver Jane Doe, expires 2027-01-01)" in text
    assert (
        "`ML-KEM-768` | severity | not declared | info |" in text
        and "not quantum-vulnerable" in text
    )
    assert "### Authority" in text and "31 Dec 2030" in text and "31 Dec 2031" in text
    assert "Removed: RSA." in text
    assert "No model" not in text.lower() or "no model involved" in text.lower()


def test_code_signing_never_appears_as_hndl():
    verdict = evaluate([ADDED[1]], [], "o/r", POLICY, TODAY)
    for text in (pr_comment(verdict), check_run(verdict)["text"]):
        line = next(ln for ln in text.splitlines() if "ECDSA" in ln)
        assert "HNDL" not in line


def test_check_run_and_sarif():
    verdict = evaluate(ADDED, [], "o/r", POLICY, TODAY)
    run = check_run(verdict)
    assert (run["title"], run["conclusion"]) == ("Quantsiv gate: fail", "failure")
    assert "BLOCKED: ECDH at net/kex.py:3" in run["text"]
    assert "EXCEPTION: DSA" in run["text"]
    doc = gate_sarif(verdict)
    results = {r["message"]["text"].split(" ")[0]: r for r in doc["runs"][0]["results"]}
    assert results["ECDH"]["ruleId"] == "gate-blocked" and results["ECDH"]["level"] == "error"
    assert results["ML-KEM-768"]["level"] == "none"
    passing = evaluate([], [], "o/r", POLICY, TODAY)
    assert check_run(passing)["conclusion"] == "success"
    assert pr_comment(passing).startswith("## ✅")
