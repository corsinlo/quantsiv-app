"""SARIF 2.1.0 and report writers for the scanner's results."""

import json
from datetime import UTC, datetime

from quantsiv_scanner import __version__

SARIF_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "none",
}


def sarif(results: list[dict], repo_root_uri: str = "") -> dict:
    """GitHub Code Scanning accepts this shape (one run, rules by id, results with regions)."""
    rules: dict[str, dict] = {}
    sarif_results = []
    for finding in results:
        rule_id = finding.get("rule_id") or f"cbom-{finding['algorithm']}"
        rules.setdefault(
            rule_id,
            {
                "id": rule_id,
                "name": rule_id.replace("-", " ").title().replace(" ", ""),
                "shortDescription": {"text": f"Cryptographic asset: {finding['algorithm']}"},
                "helpUri": "https://github.com/corsinlo/quantsiv-app/blob/main/docs/scanner.md",
            },
        )
        message = f"{finding['algorithm']}"
        if finding.get("key_size"):
            message += f"-{finding['key_size']}"
        message += (
            f" ({finding.get('context_label') or 'cryptographic asset'}): {finding['reason']}"
        )
        result = {
            "ruleId": rule_id,
            "level": SARIF_LEVEL.get(finding["severity"], "warning"),
            "message": {"text": message},
            "properties": {
                "track": finding["track"],
                "severity": finding["severity"],
                "primitive": finding.get("primitive"),
                "lifetime_years": finding.get("lifetime_years"),
                "quantum_safe": not finding["quantum_vulnerable"],
            },
        }
        if finding.get("file_path"):
            result["locations"] = [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": finding["file_path"], "uriBaseId": "SRCROOT"},
                        "region": {"startLine": max(1, int(finding.get("line_number") or 1))},
                    }
                }
            ]
        sarif_results.append(result)
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "quantsiv-scanner",
                        "version": __version__,
                        "informationUri": "https://github.com/corsinlo/quantsiv-app",
                        "rules": list(rules.values()),
                    }
                },
                "originalUriBaseIds": {"SRCROOT": {"uri": repo_root_uri or "file:///"}},
                "results": sarif_results,
            }
        ],
    }


def report(results: list[dict], meta: dict) -> dict:
    by_severity: dict[str, int] = {}
    by_track: dict[str, int] = {}
    for finding in results:
        by_severity[finding["severity"]] = by_severity.get(finding["severity"], 0) + 1
        by_track[finding["track"]] = by_track.get(finding["track"], 0) + 1
    return {
        "scanner": {"name": "quantsiv-scanner", "version": __version__},
        "generated_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        **meta,
        "assets": len(results),
        "quantum_vulnerable": sum(1 for f in results if f["quantum_vulnerable"]),
        "by_severity": dict(sorted(by_severity.items())),
        "by_track": dict(sorted(by_track.items())),
        "hndl_ranked": meta.get("lifetime_declared", False),
        "findings": results,
    }


def report_markdown(rep: dict) -> str:
    lines = [
        "# Quantsiv scan report",
        "",
        f"Repository: `{rep.get('repository') or 'unknown'}`  ",
        f"Scanner: quantsiv-scanner {rep['scanner']['version']}  ",
        (
            f"Files scanned: {rep.get('files_scanned', 0)}; time to first CBOM: "
            f"{rep.get('seconds_to_first_cbom', 0):.1f} s"
        ),
        "",
        f"**{rep['assets']} cryptographic assets, {rep['quantum_vulnerable']} quantum-vulnerable.**",
        "",
    ]
    if not rep["hndl_ranked"]:
        lines += [
            (
                "No data lifetime is declared (`quantsiv.yml`), so confidentiality findings "
                "are ranked by severity, not by HNDL exposure."
            ),
            "",
        ]
    lines += [
        "| Severity | Track | Algorithm | Location | Reason |",
        "| --- | --- | --- | --- | --- |",
    ]
    for f in rep["findings"]:
        where = f"{f['file_path']}:{f['line_number']}" if f.get("file_path") else "-"
        algo = f"{f['algorithm']}-{f['key_size']}" if f.get("key_size") else f["algorithm"]
        lines.append(f"| {f['severity']} | {f['track']} | {algo} | `{where}` | {f['reason']} |")
    lines += [
        "",
        (
            "Sources: harvest-now-decrypt-later applies to key establishment and encryption "
            "only; signatures are ranked against EO 14412's 31 Dec 2031 deadline "
            "(configurable). AES-128 and other >=128-bit symmetric primitives are not "
            "quantum-vulnerable (NIST IR 8547 ipd)."
        ),
        "",
    ]
    return "\n".join(lines)


def dumps(doc: dict) -> str:
    return json.dumps(doc, indent=2, sort_keys=False) + "\n"
