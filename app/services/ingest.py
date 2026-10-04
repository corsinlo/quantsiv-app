"""CBOM ingest and export (WP7, D6): accept any schema-valid CycloneDX 1.6 CBOM, not only
Quantsiv's; keep the producing tool as provenance; diff against the previous upload; export the
estate as plain CycloneDX 1.6.

Only CBOM metadata is accepted. A CBOM holds algorithms and where they occur (file and line),
never source code.
"""

import json
import uuid
from datetime import UTC, datetime

from cyclonedx.schema import SchemaVersion
from cyclonedx.validation.json import JsonStrictValidator

from app.services.cbom import LIFETIME_PROPERTY

REPOSITORY_PROPERTY = "quantsiv:repository"


class InvalidCbom(ValueError):
    """The upload is not a CycloneDX 1.6 CBOM; the message is safe to return."""


def validate(raw: bytes) -> dict:
    try:
        doc = json.loads(raw)
    except ValueError:
        raise InvalidCbom("Body is not JSON") from None
    if not isinstance(doc, dict) or doc.get("specVersion") != "1.6":
        raise InvalidCbom("Only CycloneDX 1.6 is accepted")
    error = JsonStrictValidator(SchemaVersion.V1_6).validate_str(raw.decode("utf-8", "replace"))
    if error is not None:
        raise InvalidCbom("Not a valid CycloneDX 1.6 document")
    return doc


def producer(doc: dict) -> str | None:
    """The producing tool(s) from metadata.tools (1.5+ object form or the legacy array)."""
    tools = (doc.get("metadata") or {}).get("tools")
    entries = []
    if isinstance(tools, dict):
        entries = list(tools.get("components") or []) + list(tools.get("services") or [])
    elif isinstance(tools, list):
        entries = tools
    names = []
    for tool in entries:
        if isinstance(tool, dict) and tool.get("name"):
            vendor = tool.get("vendor") or (tool.get("manufacturer") or {}).get("name")
            label = " ".join(str(x) for x in (vendor, tool["name"], tool.get("version")) if x)
            names.append(label)
    return ", ".join(names)[:200] or None


def _walk(components: list) -> list[dict]:
    for component in components or []:
        if isinstance(component, dict):
            yield component
            yield from _walk(component.get("components"))


def findings_from_cbom(doc: dict) -> list[dict]:
    """One finding per cryptographic algorithm asset, in the shape the scorer takes."""
    findings = []
    for component in _walk(doc.get("components")):
        crypto = component.get("cryptoProperties") or {}
        if component.get("type") != "cryptographic-asset" or crypto.get("assetType") != "algorithm":
            continue
        algo = crypto.get("algorithmProperties") or {}
        occurrence = ((component.get("evidence") or {}).get("occurrences") or [{}])[0]
        parameter = str(algo.get("parameterSetIdentifier") or "")
        properties = {p.get("name"): p.get("value") for p in component.get("properties") or []}
        lifetime = properties.get(LIFETIME_PROPERTY)
        level = algo.get("nistQuantumSecurityLevel")
        primitive = algo.get("primitive")
        findings.append(
            {
                "algorithm": component.get("name") or "unknown",
                "primitive": primitive if primitive not in (None, "other", "unknown") else None,
                "key_size": int(parameter) if parameter.isdigit() else None,
                "quantum_safe": isinstance(level, int) and level > 0,
                "file_path": occurrence.get("location"),
                "line_number": occurrence.get("line"),
                "lifetime_years": int(lifetime) if str(lifetime or "").isdigit() else None,
            }
        )
    return findings


def asset_key(finding: dict) -> tuple:
    return (finding["algorithm"], finding.get("primitive"), finding.get("file_path"))


def diff(previous: list[dict], current: list[dict]) -> tuple[list[dict], list[dict]]:
    """(added, removed) cryptographic assets between two uploads of the same repository."""
    before = {asset_key(f) for f in previous}
    after = {asset_key(f) for f in current}
    return (
        [f for f in current if asset_key(f) not in before],
        [f for f in previous if asset_key(f) not in after],
    )


def _prefix_refs(component: dict, repo: str) -> dict:
    copy = dict(component)
    if copy.get("bom-ref"):
        copy["bom-ref"] = f"{repo}:{copy['bom-ref']}"
    if copy.get("components"):
        copy["components"] = [_prefix_refs(c, repo) for c in copy["components"]]
    copy["properties"] = [
        *(copy.get("properties") or []),
        {"name": REPOSITORY_PROPERTY, "value": repo},
    ]
    return copy


def estate_cbom(account: str, latest: list[tuple[str, dict]]) -> dict:
    """One CycloneDX 1.6 document with the latest CBOM components of every repository."""
    components = []
    for repo, doc in latest:
        components.extend(_prefix_refs(c, repo) for c in doc.get("components") or [])
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "component": {"type": "application", "name": account, "bom-ref": "estate"},
        },
        "components": components,
    }
