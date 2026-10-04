"""Declared data lifetimes: the `quantsiv.yml` input the HNDL track needs (A28, D6).

Example (in the scanned repository's root, or uploaded later):

    data_classes:
      customer-records:
        confidentiality_lifetime_years: 25
      session-tokens:
        confidentiality_lifetime_years: 0
    repositories:
      octo-org/payments: customer-records
    signatures:
      deadline: 2031-12-31          # default: EO 14412 signature date, configurable
      trust_lifetime_years: 10      # how long this repo's signatures must stay trusted

Nothing here is guessed: without a declared lifetime the HNDL track is not used and the score is
a plain severity score.
"""

from dataclasses import dataclass, field
from datetime import date

import yaml

from app.services.errors import ScanError

# EO 14412 (22 Jun 2026): post-quantum signatures on high-value assets and high-impact systems
DEFAULT_SIGNATURE_DEADLINE = date(2031, 12, 31)


@dataclass(frozen=True)
class Lifetimes:
    data_classes: dict[str, int] = field(default_factory=dict)  # class -> lifetime in years
    repositories: dict[str, str] = field(default_factory=dict)  # owner/name -> data class
    signature_deadline: date = DEFAULT_SIGNATURE_DEADLINE
    signature_trust_years: int | None = None

    def confidentiality_years(self, repo_full_name: str) -> int | None:
        data_class = self.repositories.get(repo_full_name)
        return self.data_classes.get(data_class) if data_class else None


def _years(value, where: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= 100:
        raise ScanError(f"quantsiv.yml: {where} must be a whole number of years from 0 to 100")
    return value


def parse_lifetimes(text: str | None) -> Lifetimes:
    """Parse quantsiv.yml. Errors are ScanErrors with a message safe to show."""
    if not text or not text.strip():
        return Lifetimes()
    try:
        doc = yaml.safe_load(text) or {}
    except yaml.YAMLError:
        raise ScanError("quantsiv.yml is not valid YAML") from None
    if not isinstance(doc, dict):
        raise ScanError("quantsiv.yml must be a mapping")
    classes = {}
    for name, spec in (doc.get("data_classes") or {}).items():
        if not isinstance(spec, dict) or "confidentiality_lifetime_years" not in spec:
            raise ScanError(
                f"quantsiv.yml: data class {name!r} needs confidentiality_lifetime_years"
            )
        years = spec["confidentiality_lifetime_years"]
        classes[str(name)] = _years(years, f"data class {name!r}")
    repos = {}
    for repo, data_class in (doc.get("repositories") or {}).items():
        if data_class not in classes:
            raise ScanError(f"quantsiv.yml: repository {repo!r} uses an undeclared data class")
        repos[str(repo)] = str(data_class)
    signatures = doc.get("signatures") or {}
    deadline = signatures.get("deadline", DEFAULT_SIGNATURE_DEADLINE)
    if not isinstance(deadline, date):
        raise ScanError("quantsiv.yml: signatures.deadline must be a date (YYYY-MM-DD)")
    trust = signatures.get("trust_lifetime_years")
    return Lifetimes(
        data_classes=classes,
        repositories=repos,
        signature_deadline=deadline,
        signature_trust_years=None if trust is None else _years(trust, "trust_lifetime_years"),
    )
