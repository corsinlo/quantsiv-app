"""`quantsiv mcp`: a read-only MCP server over stdio for the customer's AI coding assistant
(WP10, D7). It answers from the local checkout's `quantsiv.yml` and `quantsiv-out/cbom.json`.

Guarantees, each covered by a test:
- read-only: no tool writes files, runs git or a shell, or opens a network connection. The one
  exception, off by default: `get_cbom_summary(scope="estate")` with `--allow-estate` and an org
  token in QUANTSIV_TOKEN reads the estate CBOM through GET /api/v1/cbom;
- deterministic: `check_change` calls the same `policy.evaluate` as the CI gate;
- static: tool names, descriptions and schemas are fixed strings; a snapshot test fails if they
  change without a TOOLS_VERSION bump. Tool outputs are plain data; no repository text ever
  goes into a tool description;
- audited: every tool call is appended to a local JSONL audit log (`--no-audit` turns it off).
"""

import hashlib
import json
import os
from datetime import UTC, datetime
from typing import Any

from mcp.server.mcpserver import MCPServer
from mcp.types import ToolAnnotations

from app.services.errors import ScanError
from app.services.ingest import findings_from_cbom
from quantsiv_scanner import __version__
from quantsiv_scanner.policy import Policy, evaluate, explain, read_policy

TOOLS_VERSION = "1"
INSTRUCTIONS = (
    "Quantsiv policy server (read-only). Use get_policy before writing cryptographic code, "
    "check_change to test a planned change against the organisation's policy, "
    "get_cbom_summary for the current inventory, and explain_finding for one algorithm. "
    "Verdicts are deterministic and the merge gate applies the same policy; "
    "a human approves every exception."
)
DESCRIPTIONS = {
    "get_policy": (
        "The organisation's cryptographic policy from quantsiv.yml: declared data classes and "
        "confidentiality lifetimes, the signature deadline, which primitives are blocked when "
        "newly added, allowed algorithms, and approved exceptions. Read-only."
    ),
    "check_change": (
        "Evaluate a planned change against the policy, exactly as the merge gate will. "
        "`added` and `removed` are lists of cryptographic assets, each with `algorithm` and "
        "optionally `primitive` (signature, key-agree, kem, pke), `key_size`, `file_path`, "
        "`line_number`, `context_label`. Returns the verdict with each new asset's track "
        "(HNDL or signature deadline), declared lifetime, reason, cited authority and "
        "alternatives. Read-only; does not change anything."
    ),
    "get_cbom_summary": (
        "Summary of the repository's current CBOM (quantsiv-out/cbom.json): assets by "
        "algorithm, primitive and track, and the quantum-vulnerable ones. scope='estate' asks the "
        "control plane for the organisation's estate CBOM, only when the server was started with "
        "--allow-estate and an organisation token. Read-only."
    ),
    "explain_finding": (
        "Explain one cryptographic finding: its CycloneDX primitive, track (HNDL or signature "
        "deadline, never both), severity under the policy, the cited authority and the approved "
        "post-quantum alternatives. Read-only."
    ),
}
READ_ONLY = ToolAnnotations(
    read_only_hint=True, destructive_hint=False, idempotent_hint=True, open_world_hint=False
)


class Audit:
    """Append-only JSONL log of tool calls: when, which tool, a hash of the arguments, the
    sizes, and the verdict where there is one. Never the repository's text."""

    def __init__(self, path: str | None):
        self.path = path

    def record(self, tool: str, arguments: dict[str, Any], result: dict[str, Any]) -> None:
        if not self.path:
            return
        digest = hashlib.sha256(json.dumps(arguments, sort_keys=True, default=str).encode())
        entry = {
            "at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "tool": tool,
            "tools_version": TOOLS_VERSION,
            "arguments_sha256": digest.hexdigest(),
            "arguments_keys": sorted(arguments),
            "gate": result.get("gate"),
            "error": result.get("error"),
        }
        os.makedirs(os.path.dirname(os.path.abspath(self.path)), exist_ok=True)
        with open(self.path, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry) + "\n")


def _summarise(doc: dict, label: str) -> dict:
    findings = findings_from_cbom(doc)
    by_algorithm: dict[str, int] = {}
    by_primitive: dict[str, int] = {}
    for f in findings:
        by_algorithm[f["algorithm"]] = by_algorithm.get(f["algorithm"], 0) + 1
        key = f.get("primitive") or "unknown"
        by_primitive[key] = by_primitive.get(key, 0) + 1
    tracks: dict[str, int] = {}
    for component in doc.get("components") or []:
        for prop in component.get("properties") or []:
            if prop.get("name") == "quantsiv:track":
                tracks[prop["value"]] = tracks.get(prop["value"], 0) + 1
    return {
        "scope": label,
        "assets": len(findings),
        "quantum_vulnerable": sum(1 for f in findings if not f.get("quantum_safe")),
        "by_algorithm": dict(sorted(by_algorithm.items())),
        "by_primitive": dict(sorted(by_primitive.items())),
        "by_track": dict(sorted(tracks.items())),
    }


def build_server(
    repo_root: str,
    cbom_path: str | None = None,
    audit_path: str | None = None,
    api_url: str | None = None,
    allow_estate: bool = False,
    today=None,
) -> MCPServer:
    root = os.path.abspath(repo_root)
    cbom_file = cbom_path or os.path.join(root, "quantsiv-out", "cbom.json")
    audit = Audit(audit_path)
    repository = os.environ.get("GITHUB_REPOSITORY") or os.path.basename(root)
    server = MCPServer(name="quantsiv", version=__version__, instructions=INSTRUCTIONS)

    def policy() -> Policy:
        return read_policy(root)

    def day():
        return today or datetime.now(UTC).date()

    def done(tool: str, arguments: dict, result: dict) -> dict:
        audit.record(tool, arguments, result)
        return result

    @server.tool(
        name="get_policy",
        description=DESCRIPTIONS["get_policy"],
        annotations=READ_ONLY,
        structured_output=True,
    )
    def get_policy() -> dict[str, Any]:
        try:
            return done("get_policy", {}, {"repository": repository, **policy().as_dict()})
        except ScanError as exc:
            return done("get_policy", {}, {"error": str(exc)})

    @server.tool(
        name="check_change",
        description=DESCRIPTIONS["check_change"],
        annotations=READ_ONLY,
        structured_output=True,
    )
    def check_change(
        added: list[dict[str, Any]],
        removed: list[dict[str, Any]] | None = None,
        repository_name: str | None = None,
    ) -> dict[str, Any]:
        arguments = {"added": added, "removed": removed or [], "repository_name": repository_name}
        try:
            verdict = evaluate(added, removed or [], repository_name or repository, policy(), day())
        except ScanError as exc:
            return done("check_change", arguments, {"error": str(exc)})
        return done("check_change", arguments, verdict.as_dict())

    @server.tool(
        name="get_cbom_summary",
        description=DESCRIPTIONS["get_cbom_summary"],
        annotations=READ_ONLY,
        structured_output=True,
    )
    def get_cbom_summary(scope: str = "local") -> dict[str, Any]:
        arguments = {"scope": scope}
        if scope == "estate":
            token = os.environ.get("QUANTSIV_TOKEN")
            if not (allow_estate and api_url and token):
                return done(
                    "get_cbom_summary",
                    arguments,
                    {"error": "estate scope needs --allow-estate, --api-url and QUANTSIV_TOKEN"},
                )
            doc = _fetch_estate(api_url, token)
            return done("get_cbom_summary", arguments, _summarise(doc, "estate"))
        if not os.path.isfile(cbom_file):
            return done(
                "get_cbom_summary",
                arguments,
                {
                    "error": f"no CBOM at {os.path.relpath(cbom_file, root)}; run `quantsiv scan` first"
                },
            )
        with open(cbom_file, encoding="utf-8") as handle:
            doc = json.load(handle)
        return done("get_cbom_summary", arguments, _summarise(doc, "local"))

    @server.tool(
        name="explain_finding",
        description=DESCRIPTIONS["explain_finding"],
        annotations=READ_ONLY,
        structured_output=True,
    )
    def explain_finding(
        algorithm: str,
        primitive: str | None = None,
        key_size: int | None = None,
        context_label: str | None = None,
        file_path: str | None = None,
    ) -> dict[str, Any]:
        finding = {
            "algorithm": algorithm,
            "primitive": primitive,
            "key_size": key_size,
            "context_label": context_label,
            "file_path": file_path,
        }
        try:
            result = explain(finding, repository, policy(), day()).as_dict()
        except ScanError as exc:
            result = {"error": str(exc)}
        return done("explain_finding", finding, result)

    return server


def _fetch_estate(api_url: str, token: str) -> dict:
    """The single allowed network call, read-only, and only when explicitly enabled."""
    from urllib.request import Request, urlopen

    request = Request(
        f"{api_url.rstrip('/')}/api/v1/cbom",
        headers={"Authorization": f"Bearer {token}", "User-Agent": f"quantsiv-mcp/{__version__}"},
    )
    with urlopen(request, timeout=30) as response:
        return json.load(response)


def run_stdio(server: MCPServer) -> None:
    server.run("stdio")
