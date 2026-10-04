"""Turn scored findings into stored rows (WP6). Shared by hosted scans (the worker) and
uploaded CBOMs (WP7 ingest), so both are ranked by exactly the same rules (`scoring.score`).
This module needs the database models; the scanner imports `scoring` only."""

import hashlib

from app.models import Finding, Installation
from app.services.scoring import Assessment, is_quantum_vulnerable, score

__all__ = ["finding_rows", "score"]


def finding_rows(
    scored: list[tuple[Assessment, dict]], installation: Installation
) -> list[Finding]:
    rows = []
    for verdict, raw in scored:
        snippet = raw.get("raw_match")
        rows.append(
            Finding(
                file_path=raw.get("file_path"),
                line_number=raw.get("line_number"),
                algorithm=str(raw.get("algorithm") or "unknown")[:50],
                algorithm_family=raw.get("algorithm_family"),
                primitive=verdict.primitive,
                track=verdict.track,
                lifetime_years=verdict.lifetime_years,
                reason=verdict.reason,
                key_size=raw.get("key_size"),
                quantum_safe=not is_quantum_vulnerable(raw),
                severity=verdict.severity,
                confidence=raw.get("confidence"),
                context_label=raw.get("context_label"),
                # Raw code is opt-in per tenant; otherwise keep only its hash (A39)
                raw_match=snippet if snippet and installation.store_code_snippets else None,
                snippet_hash=hashlib.sha256(snippet.encode()).hexdigest() if snippet else None,
            )
        )
    return rows
