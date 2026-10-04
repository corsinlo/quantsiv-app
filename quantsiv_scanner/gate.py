"""The gate on a CBOM delta: shared by `quantsiv gate` (offline), the control plane's upload
endpoint, and the MCP server's `check_change`. All three end in `policy.evaluate`."""

import json
from datetime import date

from app.services import ingest
from quantsiv_scanner.policy import Policy, Verdict, evaluate, policy_from_dict

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
) -> Verdict:
    added, removed = delta(current, baseline)
    return evaluate(added, removed, repository, policy or policy_from_cbom(current), today)
