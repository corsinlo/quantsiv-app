"""Classification and dual-track scoring (A28, A30, A53, D6).

- **HNDL track** for confidentiality primitives (key-agree, kem, pke): ranked by the declared
  confidentiality lifetime of the data. Harvest-now-decrypt-later only threatens these.
- **Signature-deadline track** for signatures: ranked by whether the signature must stay trusted
  past the signature deadline (EO 14412: 31 Dec 2031 by default, configurable), or by the kind of
  artifact signed (code, firmware and CA keys high; short-lived tokens medium). Never HNDL.
- **Severity** (no track) when no lifetime is declared: the label must not say HNDL.

The thresholds below are Quantsiv's own ranking rule, not a regulatory requirement.
"""

import re
from dataclasses import dataclass
from datetime import date

from app.services.lifetimes import Lifetimes

PQC_GUIDANCE = {
    "signature": "Migrate to ML-DSA (FIPS 204) or SLH-DSA (FIPS 205). Prioritise long-lived "
    "signing keys: code/firmware signing, CA and token-issuer keys.",
    "key-agree": "Migrate key establishment to ML-KEM (FIPS 203), deployed as a hybrid with "
    "X25519 (e.g. X25519MLKEM768 in TLS) during the transition.",
    "kem": "Use ML-KEM (FIPS 203).",
    "pke": "Replace RSA encryption/key transport with ML-KEM (FIPS 203) plus an AEAD.",
}

# Harvest-now-decrypt-later threatens confidentiality only: show the HNDL text for these
HNDL_EXPOSED = frozenset({"key-agree", "kem", "pke"})

TRACK_HNDL = "HNDL"
TRACK_SIGNATURE = "signature deadline"
TRACK_SEVERITY = "severity"

SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

# Public-key algorithms Shor's algorithm breaks. Symmetric ciphers and hashes are not in here:
# NIST IR 8547 (ipd) treats >=128-bit symmetric primitives, including AES-128, as meeting
# Category 1, so AES-128 is not quantum-vulnerable (A30).
_SIGNATURE = re.compile(r"^(ECDSA|EDDSA|ED25519|ED448|DSA|RSA-?PSS|RSASSA.*)$")
_KEY_AGREE = re.compile(r"^(ECDH|ECDHE|X25519|X448|DH|DHE|FFDH|ECMQV)$")
_SIGNING_CONTEXT = re.compile(r"sign|jwt|token|cert|code|firmware|\bca\b", re.IGNORECASE)
_ENCRYPTION_CONTEXT = re.compile(
    r"encrypt|decrypt|wrap|transport|oaep|kex|key exchange", re.IGNORECASE
)
_LONG_LIVED_SIGNING = re.compile(
    r"code|firmware|\bca\b|root|certificate authority|release", re.IGNORECASE
)
_QUANTUM_SAFE = re.compile(
    r"^(ML-KEM|ML-DSA|SLH-DSA|KYBER|DILITHIUM|SPHINCS|LMS|XMSS)", re.IGNORECASE
)
# Public-key algorithms a cryptographically relevant quantum computer breaks (Shor), whatever
# they are used for: if the use is not classified they still rank, as a severity
_SHOR_BROKEN = re.compile(
    r"^(RSA|EC|ECC|ECDSA|ECDH|ECDHE|ECMQV|ECIES|DSA|DH|DHE|FFDH|X25519|X448|ED25519|ED448|EDDSA"
    r"|ELGAMAL|SM2)\b"
)


def primitive_for(finding: dict) -> str:
    """The CycloneDX crypto primitive of a finding, from engine data or the algorithm name."""
    if finding.get("primitive"):
        return finding["primitive"]
    algorithm = (finding.get("algorithm") or "").upper().replace("_", "-")
    context = " ".join(str(finding.get(k) or "") for k in ("context_label", "algorithm_family"))
    if algorithm.startswith(("ML-KEM", "KYBER")):
        return "kem"
    if _QUANTUM_SAFE.match(algorithm) or _SIGNATURE.match(algorithm):
        return "signature"
    if _KEY_AGREE.match(algorithm):
        return "key-agree"
    if algorithm.startswith("RSA"):
        if _ENCRYPTION_CONTEXT.search(context):
            return "pke"
        if _SIGNING_CONTEXT.search(context) or "signature" in context:
            return "signature"
    return "unknown"


def is_quantum_vulnerable(finding: dict) -> bool:
    algorithm = (finding.get("algorithm") or "").upper().replace("_", "-")
    if finding.get("quantum_safe") or _QUANTUM_SAFE.match(algorithm):
        return False
    if _SHOR_BROKEN.match(algorithm):
        return True
    return primitive_for(finding) in HNDL_EXPOSED | {"signature"}


def _hndl_severity(years: int) -> str:
    if years >= 10:
        return "critical"
    if years >= 5:
        return "high"
    if years >= 1:
        return "medium"
    return "low"


@dataclass(frozen=True)
class Assessment:
    primitive: str
    track: str
    severity: str
    lifetime_years: int | None  # the confidentiality or trust lifetime it was ranked by
    reason: str


def assess(finding: dict, repo_full_name: str, lifetimes: Lifetimes, today: date) -> Assessment:
    primitive = primitive_for(finding)
    if not is_quantum_vulnerable(finding):
        return Assessment(primitive, TRACK_SEVERITY, "info", None, "Not quantum-vulnerable.")
    if primitive in HNDL_EXPOSED:
        # A lifetime declared on the asset itself (an uploaded CBOM's quantsiv property) wins
        years = finding.get("lifetime_years")
        if years is None:
            years = lifetimes.confidentiality_years(repo_full_name)
        if years is None:
            return Assessment(
                primitive,
                TRACK_SEVERITY,
                "high",
                None,
                "Quantum-vulnerable key establishment or encryption; no data lifetime declared.",
            )
        return Assessment(
            primitive,
            TRACK_HNDL,
            _hndl_severity(years),
            years,
            f"Protects data that must stay confidential for {years} years.",
        )
    if primitive != "signature":
        return Assessment(
            primitive,
            TRACK_SEVERITY,
            "high",
            None,
            "Quantum-vulnerable public-key algorithm; whether it signs or encrypts is not "
            "classified, so it is ranked by severity only.",
        )
    # Signatures: future forgery, never retroactive decryption
    deadline = lifetimes.signature_deadline
    trust = lifetimes.signature_trust_years
    context = str(finding.get("context_label") or "")
    if trust is not None:
        must_hold_until = date(today.year + trust, today.month, min(today.day, 28))
        severity = "high" if must_hold_until > deadline else "medium"
        reason = f"Signatures must stay trusted for {trust} years; deadline {deadline:%d %b %Y}."
    elif _LONG_LIVED_SIGNING.search(context):
        severity, reason = "high", f"Long-lived signing key; deadline {deadline:%d %b %Y}."
    else:
        severity, reason = "medium", f"Signature; deadline {deadline:%d %b %Y}."
    return Assessment(primitive, TRACK_SIGNATURE, severity, trust, reason)


def rank_key(assessment: Assessment) -> tuple:
    """Sort key, highest priority first: severity, then HNDL before signatures, then lifetime."""
    return (
        -SEVERITY_RANK[assessment.severity],
        0 if assessment.track == TRACK_HNDL else 1,
        -(assessment.lifetime_years or 0),
    )


def severity_score(severities: list[str]) -> int:
    """0-100 from severity counts (spec §3): critical 25 each (cap 50), high 10 (cap 30),
    medium 5 (cap 20). A severity score, not an HNDL score."""
    counts = {s: severities.count(s) for s in ("critical", "high", "medium")}
    return min(
        100,
        min(counts["critical"] * 25, 50)
        + min(counts["high"] * 10, 30)
        + min(counts["medium"] * 5, 20),
    )


def score(
    findings: list[dict], repo_full_name: str, lifetimes: Lifetimes, today: date
) -> list[tuple[Assessment, dict]]:
    """Assess every finding and rank them, highest priority first."""
    scored = [(assess(raw, repo_full_name, lifetimes, today), raw) for raw in findings]
    scored.sort(key=lambda pair: rank_key(pair[0]))
    return scored
