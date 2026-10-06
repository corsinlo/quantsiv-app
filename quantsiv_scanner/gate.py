"""The gate on a CBOM delta: shared by `quantsiv gate` (offline), the control plane's upload
endpoint, and the MCP server's `check_change`. All three end in `policy.evaluate`."""

import json
from dataclasses import replace
from datetime import date

from app.services import ingest
from quantsiv_scanner.policy import (
    Policy,
    Verdict,
    evaluate,
    policy_changes,
    policy_from_dict,
)

POLICY_PROPERTY = "quantsiv:policy"


def policy_from_cbom(doc: dict) -> Policy:
    """The policy the scanner embedded in metadata.properties, else the default policy."""
    for prop in (doc.get("metadata") or {}).get("properties") or []:
        if prop.get("name") == POLICY_PROPERTY:
            try:
                return policy_from_dict(json.loads(prop.get("value") or "{}"))
            except (ValueError, TypeError, KeyError):
                return Policy()
    return Policy()


def delta(current: dict, baseline: dict | None) -> tuple[list[dict], list[dict]]:
    now = ingest.findings_from_cbom(current)
    before = ingest.findings_from_cbom(baseline) if baseline else []
    return ingest.diff(before, now)


def gate(
    current: dict,
    baseline: dict | None,
    repository: str,
    today: date,
    policy: Policy | None = None,
    *,
    own_policy: bool = False,
) -> Verdict:
    """The verdict on a change, with the policy chosen so a change cannot rewrite its own rules.

    - `policy` given: that policy decides ("explicit").
    - no baseline yet: the change's own policy decides, and the verdict says so ("bootstrap").
    - `own_policy`: a default-branch build applies its own policy ("own"); its code has been
      reviewed and merged, so its policy is the truth.
    - otherwise the baseline's policy decides ("baseline"). Exceptions or loosened rules in the
      change take effect only after it is merged and built on the default branch.
    Whatever decides, the verdict lists how the change alters the policy.
    """
    added, removed = delta(current, baseline)
    own = policy_from_cbom(current)
    notes: list[str] = []
    if policy is not None:
        used, source = policy, "explicit"
    elif baseline is None:
        used, source = own, "bootstrap"
        notes.append(
            "No baseline exists yet (no default-branch build was uploaded or given), so every "
            "asset counts as new and this build's own policy applies. Upload a build from the "
            "default branch to record one."
        )
    elif own_policy:
        used, source = own, "own"
    else:
        used, source = policy_from_cbom(baseline), "baseline"
    changes = policy_changes(policy_from_cbom(baseline), own) if baseline is not None else ()
    if changes and source == "baseline":
        notes.append(
            "This change edits the policy. The gate applied the default branch's policy; the "
            "edits take effect after the change is merged and built on the default branch."
        )
    verdict = evaluate(added, removed, repository, used, today)
    return replace(verdict, policy_source=source, policy_changes=changes, notes=tuple(notes))
