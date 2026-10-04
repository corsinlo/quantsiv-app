"""Cryptographic change policy (WP10, D7): deterministic, offline, the one function behind both
the CI gate and the MCP server's `check_change`.

The `policy:` section of `quantsiv.yml`:

    policy:
      block_new_quantum_vulnerable: true      # default; the WP7 gate rule
      blocked_primitives: [key-agree, kem, pke, signature]   # which primitives the rule covers
      data_classes:
        customer-records:
          blocked_primitives: [key-agree, kem, pke]         # per data class (repositories: map)
      allowed_algorithms: [Ed25519]           # never blocked, e.g. during a planned transition
      exceptions:
        - asset: RSA-2048                     # algorithm, or algorithm-keysize
          path: legacy/signer.py              # optional glob on the file path
          approver: Jane Doe
          expires: 2027-06-30
          reason: vendor SDK; replacement scheduled

An exception needs a named approver and an expiry; an expired one does not apply. Declared
lifetimes and the signature deadline come from the same file (`services.lifetimes`).
Nothing here calls a model: the verdict is a pure function of the delta and the policy.
"""

import fnmatch
import os
from dataclasses import asdict, dataclass, field
from datetime import date

import yaml

from app.services.errors import ScanError
from app.services.lifetimes import MAX_CONFIG_BYTES, Lifetimes, parse_lifetimes
from app.services.scoring import (
    HNDL_EXPOSED,
    PQC_GUIDANCE,
    TRACK_HNDL,
    TRACK_SIGNATURE,
    Assessment,
    assess,
    is_quantum_vulnerable,
)

POLICY_VERSION = "1"
ALL_PRIMITIVES = ("key-agree", "kem", "pke", "signature", "unknown")

# Authority cited per track (the narrative in CLAUDE.md; never invent dates)
AUTHORITY = {
    TRACK_HNDL: (
        "EO 14412 (22 Jun 2026): post-quantum key establishment on high-value assets and "
        "high-impact systems by 31 Dec 2030. NIST IR 8547 (ipd): 112-bit RSA/ECC/DH deprecated "
        "after 2030, all quantum-vulnerable public-key algorithms disallowed after 2035."
    ),
    TRACK_SIGNATURE: (
        "EO 14412 (22 Jun 2026): post-quantum digital signatures on high-value assets and "
        "high-impact systems by 31 Dec 2031. NIST IR 8547 (ipd): disallowed after 2035."
    ),
    "severity": (
        "NIST IR 8547 (ipd): quantum-vulnerable public-key algorithms are deprecated after 2030 "
        "and disallowed after 2035."
    ),
}


@dataclass(frozen=True)
class Exception_:
    asset: str  # "RSA" or "RSA-2048"
    approver: str
    expires: date
    path: str | None = None
    reason: str | None = None

    def matches(self, finding: dict, today: date) -> bool:
        if today > self.expires:
            return False
        name = str(finding.get("algorithm") or "").upper()
        full = f"{name}-{finding['key_size']}" if finding.get("key_size") else name
        if self.asset.upper() not in (name, full):
            return False
        return not self.path or fnmatch.fnmatch(str(finding.get("file_path") or ""), self.path)


@dataclass(frozen=True)
class Policy:
    lifetimes: Lifetimes = field(default_factory=Lifetimes)
    block_new_quantum_vulnerable: bool = True
    blocked_primitives: frozenset[str] = frozenset(ALL_PRIMITIVES)
    class_primitives: dict[str, frozenset[str]] = field(default_factory=dict)
    allowed_algorithms: frozenset[str] = frozenset()
    exceptions: tuple[Exception_, ...] = ()

    def blocked_for(self, repo_full_name: str) -> frozenset[str]:
        data_class = self.lifetimes.repositories.get(repo_full_name)
        return self.class_primitives.get(data_class, self.blocked_primitives)

    def as_dict(self) -> dict:
        return {
            "version": POLICY_VERSION,
            "block_new_quantum_vulnerable": self.block_new_quantum_vulnerable,
            "blocked_primitives": sorted(self.blocked_primitives),
            "data_classes": {
                name: {
                    "confidentiality_lifetime_years": years,
                    **(
                        {"blocked_primitives": sorted(self.class_primitives[name])}
                        if name in self.class_primitives
                        else {}
                    ),
                }
                for name, years in self.lifetimes.data_classes.items()
            },
            "repositories": dict(self.lifetimes.repositories),
            "signature_deadline": self.lifetimes.signature_deadline.isoformat(),
            "signature_trust_years": self.lifetimes.signature_trust_years,
            "allowed_algorithms": sorted(self.allowed_algorithms),
            "exceptions": [
                {**asdict(e), "expires": e.expires.isoformat()} for e in self.exceptions
            ],
        }


def _primitives(value, where: str) -> frozenset[str]:
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise ScanError(f"quantsiv.yml: {where} must be a list of primitives")
    unknown = sorted(set(value) - set(ALL_PRIMITIVES))
    if unknown:
        raise ScanError(f"quantsiv.yml: {where}: unknown primitives {unknown}")
    return frozenset(value)


def parse_policy(text: str | None) -> Policy:
    """Lifetimes plus the policy section. Errors are ScanErrors safe to show."""
    lifetimes = parse_lifetimes(text)
    if not text or not text.strip():
        return Policy(lifetimes=lifetimes)
    doc = yaml.safe_load(text) or {}
    section = doc.get("policy") or {}
    if not isinstance(section, dict):
        raise ScanError("quantsiv.yml: policy must be a mapping")
    block = section.get("block_new_quantum_vulnerable", True)
    if not isinstance(block, bool):
        raise ScanError("quantsiv.yml: policy.block_new_quantum_vulnerable must be true or false")
    blocked = _primitives(
        section.get("blocked_primitives", list(ALL_PRIMITIVES)), "policy.blocked_primitives"
    )
    class_primitives = {}
    for name, spec in (section.get("data_classes") or {}).items():
        if name not in lifetimes.data_classes:
            raise ScanError(
                f"quantsiv.yml: policy.data_classes.{name} is not a declared data class"
            )
        if not isinstance(spec, dict):
            raise ScanError(f"quantsiv.yml: policy.data_classes.{name} must be a mapping")
        class_primitives[str(name)] = _primitives(
            spec.get("blocked_primitives", list(blocked)), f"policy.data_classes.{name}"
        )
    allowed = section.get("allowed_algorithms") or []
    if not isinstance(allowed, list) or not all(isinstance(v, str) for v in allowed):
        raise ScanError("quantsiv.yml: policy.allowed_algorithms must be a list of names")
    exceptions = []
    for i, item in enumerate(section.get("exceptions") or []):
        if not isinstance(item, dict):
            raise ScanError(f"quantsiv.yml: policy.exceptions[{i}] must be a mapping")
        asset, approver, expires = item.get("asset"), item.get("approver"), item.get("expires")
        if not isinstance(asset, str) or not asset.strip():
            raise ScanError(f"quantsiv.yml: policy.exceptions[{i}] needs an asset")
        if not isinstance(approver, str) or not approver.strip():
            raise ScanError(f"quantsiv.yml: policy.exceptions[{i}] needs a named approver")
        if not isinstance(expires, date):
            raise ScanError(f"quantsiv.yml: policy.exceptions[{i}] needs expires (YYYY-MM-DD)")
        exceptions.append(
            Exception_(
                asset=asset.strip(),
                approver=approver.strip(),
                expires=expires,
                path=str(item["path"]) if item.get("path") else None,
                reason=str(item["reason"]) if item.get("reason") else None,
            )
        )
    return Policy(
        lifetimes=lifetimes,
        block_new_quantum_vulnerable=block,
        blocked_primitives=blocked,
        class_primitives=class_primitives,
        allowed_algorithms=frozenset(a.upper() for a in allowed),
        exceptions=tuple(exceptions),
    )


def read_policy(repo_root: str) -> Policy:
    """quantsiv.yml from the repo root (a regular file, size-limited, symlinks ignored)."""
    path = os.path.join(repo_root, "quantsiv.yml")
    if not os.path.isfile(path) or os.path.islink(path):
        return Policy()
    if os.path.getsize(path) > MAX_CONFIG_BYTES:
        raise ScanError("quantsiv.yml is larger than 64 KB")
    with open(path, encoding="utf-8", errors="replace") as handle:
        return parse_policy(handle.read())


def policy_from_dict(data: dict | None) -> Policy:
    """Rebuild a Policy from `Policy.as_dict()` output (the CBOM carries it to the control plane)."""
    if not data:
        return Policy()
    doc = {
        "data_classes": {
            name: {"confidentiality_lifetime_years": spec["confidentiality_lifetime_years"]}
            for name, spec in (data.get("data_classes") or {}).items()
        },
        "repositories": data.get("repositories") or {},
        "signatures": {
            "deadline": date.fromisoformat(data["signature_deadline"])
            if data.get("signature_deadline")
            else None,
            "trust_lifetime_years": data.get("signature_trust_years"),
        },
        "policy": {
            "block_new_quantum_vulnerable": data.get("block_new_quantum_vulnerable", True),
            "blocked_primitives": data.get("blocked_primitives", list(ALL_PRIMITIVES)),
            "data_classes": {
                name: {"blocked_primitives": spec["blocked_primitives"]}
                for name, spec in (data.get("data_classes") or {}).items()
                if "blocked_primitives" in spec
            },
            "allowed_algorithms": data.get("allowed_algorithms") or [],
            "exceptions": [
                {**e, "expires": date.fromisoformat(e["expires"])}
                for e in data.get("exceptions") or []
            ],
        },
    }
    if doc["signatures"]["deadline"] is None:
        del doc["signatures"]["deadline"]
    return parse_policy(yaml.safe_dump(doc))


@dataclass(frozen=True)
class Explanation:
    """One asset, explained for a human: the gate explainer renders these."""

    algorithm: str
    key_size: int | None
    primitive: str
    file_path: str | None
    line_number: int | None
    track: str
    severity: str
    lifetime_years: int | None
    reason: str
    authority: str
    alternatives: str
    quantum_vulnerable: bool
    blocking: bool
    exception: dict | None = None
    source: str | None = None

    def as_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class Verdict:
    passed: bool
    repository: str
    policy_version: str
    added: tuple[Explanation, ...]
    removed: tuple[str, ...]
    summary: str

    @property
    def blocking(self) -> list[Explanation]:
        return [e for e in self.added if e.blocking]

    @property
    def excepted(self) -> list[Explanation]:
        return [e for e in self.added if e.exception]

    def as_dict(self) -> dict:
        return {
            "gate": "pass" if self.passed else "fail",
            "repository": self.repository,
            "policy_version": self.policy_version,
            "summary": self.summary,
            "added": [e.as_dict() for e in self.added],
            "removed": list(self.removed),
            "blocking": [e.as_dict() for e in self.blocking],
            "excepted": [e.as_dict() for e in self.excepted],
        }


def explain(finding: dict, repo_full_name: str, policy: Policy, today: date) -> Explanation:
    """Classify one asset (added or existing) under the policy. Not a gate decision by itself."""
    verdict: Assessment = assess(finding, repo_full_name, policy.lifetimes, today)
    vulnerable = is_quantum_vulnerable(finding)
    name = str(finding.get("algorithm") or "unknown")
    blocked = (
        vulnerable
        and policy.block_new_quantum_vulnerable
        and verdict.primitive in policy.blocked_for(repo_full_name)
        and name.upper() not in policy.allowed_algorithms
    )
    exception = next((e for e in policy.exceptions if e.matches(finding, today)), None)
    alternatives = PQC_GUIDANCE.get(verdict.primitive) or (
        "Classify the use first (sign or encrypt); then ML-DSA/SLH-DSA for signatures, ML-KEM "
        "for key establishment, hybrid during the transition."
    )
    if not vulnerable:
        alternatives = "None needed: not quantum-vulnerable."
    return Explanation(
        algorithm=name,
        key_size=finding.get("key_size"),
        primitive=verdict.primitive,
        file_path=finding.get("file_path"),
        line_number=finding.get("line_number"),
        track=verdict.track,
        severity=verdict.severity,
        lifetime_years=verdict.lifetime_years,
        reason=verdict.reason,
        authority=AUTHORITY.get(verdict.track, AUTHORITY["severity"]) if vulnerable else "",
        alternatives=alternatives,
        quantum_vulnerable=vulnerable,
        blocking=blocked and exception is None,
        exception=(
            {
                "approver": exception.approver,
                "expires": exception.expires.isoformat(),
                "reason": exception.reason,
            }
            if exception and blocked
            else None
        ),
        source=finding.get("source"),
    )


def evaluate(
    added: list[dict], removed: list[dict], repo_full_name: str, policy: Policy, today: date
) -> Verdict:
    """The gate: fails only on newly added assets the policy blocks (the delta, never the
    absolute count). Identical inputs give identical verdicts; the CI gate and `check_change`
    both call this."""
    explained = tuple(
        sorted(
            (explain(f, repo_full_name, policy, today) for f in added),
            key=lambda e: (not e.blocking, e.track != TRACK_HNDL, e.algorithm, e.file_path or ""),
        )
    )
    blocking = [e for e in explained if e.blocking]
    excepted = [e for e in explained if e.exception]
    removed_names = tuple(sorted({str(f.get("algorithm") or "unknown") for f in removed}))
    if blocking:
        summary = (
            f"{len(blocking)} newly added quantum-vulnerable asset(s) blocked by policy: "
            + ", ".join(sorted({e.algorithm for e in blocking}))
        )
    elif excepted:
        summary = f"{len(excepted)} newly added asset(s) allowed under approved exceptions"
    elif explained:
        summary = f"{len(explained)} asset(s) added, none blocked"
    else:
        summary = "no cryptographic assets added"
    return Verdict(
        passed=not blocking,
        repository=repo_full_name,
        policy_version=POLICY_VERSION,
        added=explained,
        removed=removed_names,
        summary=summary,
    )


def verdict_from_dict(data: dict) -> Verdict:
    """Rebuild a Verdict from `Verdict.as_dict()` (the control plane returns one on upload)."""
    fields = Explanation.__dataclass_fields__
    added = tuple(
        Explanation(**{k: v for k, v in item.items() if k in fields})
        for item in data.get("added") or []
    )
    return Verdict(
        passed=data.get("gate") == "pass",
        repository=str(data.get("repository") or "unknown"),
        policy_version=str(data.get("policy_version") or POLICY_VERSION),
        added=added,
        removed=tuple(data.get("removed") or []),
        summary=str(data.get("summary") or ""),
    )


__all__ = [
    "AUTHORITY",
    "HNDL_EXPOSED",
    "Explanation",
    "Policy",
    "Verdict",
    "evaluate",
    "explain",
    "parse_policy",
    "policy_from_dict",
    "read_policy",
    "verdict_from_dict",
]
