"""The change gate cannot be talked out of its verdict (WP12).

Each test reproduces a way a change used to pass its own gate: a failing pull request passing
when CI re-ran, a pull request excusing itself through its own policy, and a second use of an
algorithm hiding in a file that already had one.
"""

import json

from app.routers import v1
from app.services import ingest
from app.services.cbom import build_cbom
from quantsiv_scanner.gate import gate
from quantsiv_scanner.policy import parse_policy, policy_changes
from tests.test_ingest import (  # noqa: F401
    asset,
    client,
    create_token,
    owner,
    third_party_cbom,
    upload,
)

TODAY = __import__("datetime").date(2026, 10, 6)
ECDH = [{"algorithm": "ECDH", "primitive": "key-agree", "file_path": "kex.py"}]


def cbom(findings, repo, policy_yaml=""):
    policy = parse_policy(policy_yaml)
    return build_cbom(
        findings, repo, properties={"policy": json.dumps(policy.as_dict(), sort_keys=True)}
    ).encode()


def start(client, owner, repo, policy_yaml=""):  # noqa: F811
    """A repository with a clean default-branch baseline; returns the token."""
    token = create_token(client, owner["installation"])
    first = upload(client, token, cbom([], repo, policy_yaml), repo=repo).json()
    assert first["baseline"] is True
    return token


# --- a failing pull request fails again --------------------------------------------------------


def test_a_failing_pull_request_fails_again_when_ci_reruns(client, owner):  # noqa: F811
    repo = "gina-org/wp12-rerun"
    token = start(client, owner, repo)
    body = cbom(ECDH, repo)
    first = upload(client, token, body, repo=repo, branch="fix/kex", change=True).json()
    second = upload(client, token, body, repo=repo, branch="fix/kex", change=True).json()
    assert (first["gate"], second["gate"]) == ("fail", "fail")
    assert second["added"] == ["ECDH"] and second["baseline"] is False


def test_pull_requests_and_feature_branches_never_become_the_baseline(client, owner):  # noqa: F811
    repo = "gina-org/wp12-candidates"
    token = start(client, owner, repo)
    pr = upload(client, token, cbom(ECDH, repo), repo=repo, branch="x", change=True).json()
    push = upload(client, token, cbom(ECDH, repo), repo=repo, branch="feature").json()
    assert (pr["baseline"], push["baseline"]) == (False, False)
    # Both were compared with the default-branch build, not with each other
    assert pr["baseline_scan_id"] == push["baseline_scan_id"]
    mainline = upload(client, token, cbom([], repo), repo=repo).json()
    assert mainline["baseline"] is True and mainline["added"] == []
    # The estate export holds default-branch builds only
    estate = client.get("/api/v1/cbom", headers={"Authorization": f"Bearer {token}"}).json()
    names = {c["name"] for c in estate["components"] if c["bom-ref"].startswith(repo)}
    assert "ECDH" not in names


def test_an_upload_that_does_not_say_where_it_ran_is_a_candidate(client, owner):  # noqa: F811
    repo = "gina-org/wp12-unknown"
    token = create_token(client, owner["installation"])
    result = client.post(
        "/api/v1/cbom",
        params={"repository": repo},
        content=cbom(ECDH, repo),
        headers={"Authorization": f"Bearer {token}"},
    ).json()
    assert result["baseline"] is False
    assert any("No baseline exists yet" in n for n in result["verdict"]["notes"])


def test_branch_names_are_validated(client, owner):  # noqa: F811
    token = create_token(client, owner["installation"])
    bad = upload(
        client, token, cbom([], "gina-org/wp12-bad"), repo="gina-org/wp12-bad", branch="a b;c"
    )
    assert bad.status_code == 422


# --- a change cannot rewrite its own rules -----------------------------------------------------


def test_a_pull_request_cannot_excuse_itself(client, owner):  # noqa: F811
    repo = "gina-org/wp12-excuse"
    token = start(client, owner, repo)
    excuse = (
        "policy:\n  exceptions:\n    - {asset: ECDH, approver: Nobody Real, expires: 2099-12-31}\n"
    )
    result = upload(
        client, token, cbom(ECDH, repo, excuse), repo=repo, branch="x", change=True
    ).json()
    assert result["gate"] == "fail"
    verdict = result["verdict"]
    assert verdict["policy_source"] == "baseline"
    assert any(c.startswith("loosens: exception added for ECDH") for c in verdict["policy_changes"])
    assert any("take effect after the change is merged" in n for n in verdict["notes"])


def test_a_pull_request_cannot_switch_the_gate_off(client, owner):  # noqa: F811
    repo = "gina-org/wp12-off"
    token = start(client, owner, repo)
    off = "policy:\n  block_new_quantum_vulnerable: false\n"
    result = upload(client, token, cbom(ECDH, repo, off), repo=repo, branch="x", change=True).json()
    assert result["gate"] == "fail"
    assert (
        "loosens: block_new_quantum_vulnerable changed from true to false"
        in result["verdict"]["policy_changes"]
    )


def test_an_exception_takes_effect_once_merged(client, owner):  # noqa: F811
    repo = "gina-org/wp12-merged"
    token = start(client, owner, repo)
    excuse = (
        "policy:\n  exceptions:\n    - {asset: ECDH, approver: Jane Doe, expires: 2099-12-31}\n"
    )
    # 1. the exception is reviewed and merged on its own
    merged = upload(client, token, cbom([], repo, excuse), repo=repo).json()
    assert merged["gate"] == "pass" and merged["baseline"] is True
    assert merged["verdict"]["policy_source"] == "own"
    # 2. the code that needs it passes under the baseline's policy
    later = upload(
        client, token, cbom(ECDH, repo, excuse), repo=repo, branch="feat", change=True
    ).json()
    assert later["gate"] == "pass"
    assert later["verdict"]["policy_source"] == "baseline"
    assert later["verdict"]["policy_changes"] == []
    assert [e["algorithm"] for e in later["verdict"]["excepted"]] == ["ECDH"]


def test_a_default_branch_build_applies_its_own_merged_policy(client, owner):  # noqa: F811
    repo = "gina-org/wp12-own"
    token = start(client, owner, repo)
    excuse = (
        "policy:\n  exceptions:\n    - {asset: ECDH, approver: Jane Doe, expires: 2099-12-31}\n"
    )
    result = upload(client, token, cbom(ECDH, repo, excuse), repo=repo).json()
    assert result["gate"] == "pass" and result["verdict"]["policy_source"] == "own"


def test_the_first_upload_has_no_baseline_and_says_so(client, owner):  # noqa: F811
    repo = "gina-org/wp12-first"
    token = create_token(client, owner["installation"])
    result = upload(client, token, cbom(ECDH, repo), repo=repo, branch="x", change=True).json()
    assert result["baseline_scan_id"] is None
    assert result["verdict"]["policy_source"] == "bootstrap"
    assert result["gate"] == "fail"


def test_audit_events_record_the_branch_and_the_policy_source(client, owner):  # noqa: F811
    repo = "gina-org/wp12-audit"
    token = start(client, owner, repo)
    upload(client, token, cbom(ECDH, repo), repo=repo, branch="fix", change=True)
    audit = client.get("/api/v1/audit", headers={"Authorization": f"Bearer {token}"}).json()
    event = next(e for e in audit["events"] if e["data"].get("branch") == "fix")
    assert event["data"]["baseline"] is False
    assert event["data"]["policy_source"] == "baseline"


# --- a second use in the same file counts ------------------------------------------------------


def test_a_second_use_in_a_file_that_already_has_one_is_added():
    before = [
        {"algorithm": "RSA-2048", "primitive": "pke", "file_path": "crypto.py", "line_number": 3}
    ]
    after = [*before, {**before[0], "line_number": 90}]
    added, removed = ingest.diff(before, after)
    assert [f["line_number"] for f in added] == [90] and removed == []
    added, removed = ingest.diff(after, before)
    assert added == [] and [f["line_number"] for f in removed] == [90]
    assert ingest.diff(before, before) == ([], [])


def test_the_upload_gate_flags_a_second_use(client, owner):  # noqa: F811
    repo = "gina-org/wp12-count"
    token = create_token(client, owner["installation"])
    one = third_party_cbom(asset("RSA-2048", "pke", "crypto.py"))
    upload(client, token, one, repo=repo)
    second = {**asset("RSA-2048", "pke", "crypto.py"), "bom-ref": "second"}
    second["evidence"] = {"occurrences": [{"location": "crypto.py", "line": 90}]}
    two = third_party_cbom(asset("RSA-2048", "pke", "crypto.py"), second)
    result = upload(client, token, two, repo=repo).json()
    assert result["added"] == ["RSA-2048"] and result["gate"] == "fail"


# --- the gate function and the offline gate ----------------------------------------------------


def doc(findings, policy_yaml=""):
    return json.loads(cbom(findings, "o/r", policy_yaml))


def test_gate_function_chooses_the_policy_source():
    excuse = "policy:\n  exceptions:\n    - {asset: ECDH, approver: Jane, expires: 2099-12-31}\n"
    base, change = doc([]), doc(ECDH, excuse)
    assert gate(change, base, "o/r", TODAY).policy_source == "baseline"
    assert gate(change, base, "o/r", TODAY).passed is False
    assert gate(change, base, "o/r", TODAY, own_policy=True).passed is True
    assert gate(change, None, "o/r", TODAY).policy_source == "bootstrap"
    explicit = parse_policy(excuse)
    assert gate(change, base, "o/r", TODAY, explicit).policy_source == "explicit"


def test_policy_changes_say_what_loosens():
    old = parse_policy(
        "data_classes:\n  secrets:\n    confidentiality_lifetime_years: 25\n"
        "repositories:\n  o/r: secrets\n"
        "policy:\n  allowed_algorithms: [Ed25519]\n"
        "  exceptions:\n    - {asset: DSA, approver: Jane, expires: 2027-01-01}\n"
    )
    new = parse_policy(
        "data_classes:\n  secrets:\n    confidentiality_lifetime_years: 5\n"
        "repositories:\n  o/r: secrets\n"
        "signatures:\n  deadline: 2033-12-31\n"
        "policy:\n  blocked_primitives: [key-agree]\n"
        "  exceptions:\n    - {asset: DSA, approver: Jane, expires: 2028-01-01}\n"
        "    - {asset: RSA, approver: Max, expires: 2027-06-30, path: legacy/*}\n"
    )
    changes = policy_changes(old, new)
    assert "loosens: data class secrets lifetime changed from 25 to 5 years" in changes
    assert "loosens: signature deadline changed from 2031-12-31 to 2033-12-31" in changes
    assert "tightens: algorithm ED25519 is no longer always allowed" in changes
    assert "loosens: kem is no longer a blocked primitive" in changes
    assert any(
        c.startswith("loosens: exception added for RSA in legacy/*, approver Max") for c in changes
    )
    assert any(c.startswith("changed: exception for DSA") for c in changes)
    assert policy_changes(old, old) == ()


def test_offline_gate_uses_the_baselines_policy_by_default(tmp_path):
    from quantsiv_scanner import cli

    excuse = "policy:\n  exceptions:\n    - {asset: ECDH, approver: Jane, expires: 2099-12-31}\n"
    (tmp_path / "base.json").write_text(json.dumps(doc([])))
    (tmp_path / "new.json").write_text(json.dumps(doc(ECDH, excuse)))
    args = ["gate", "--cbom", str(tmp_path / "new.json"), "--baseline", str(tmp_path / "base.json")]
    assert cli.main([*args, "--out", str(tmp_path / "a")]) == 1
    assert cli.main([*args, "--policy-from", "change", "--out", str(tmp_path / "b")]) == 0
    comment = (tmp_path / "a" / "pr_comment.md").read_text()
    assert "### Policy changes in this change" in comment
    assert "loosens: exception added for ECDH" in comment
    assert "take effect after the change is merged" in comment
    check = json.loads((tmp_path / "a" / "check_run.json").read_text())
    assert "Policy changes in this change" in check["text"]


def test_branch_names_with_slashes_are_accepted():
    assert v1.BRANCH.fullmatch("feature/PQC-12_fix@v2")
    assert not v1.BRANCH.fullmatch("a b")
    assert not v1.BRANCH.fullmatch("x" * 201)
