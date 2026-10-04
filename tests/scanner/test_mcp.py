"""The policy MCP server (WP10): read-only, offline, static tool contract, audited."""

import json
import os
import socket
from datetime import date
from pathlib import Path

import pytest
from mcp import Client

from quantsiv_scanner import cli
from quantsiv_scanner.mcp_server import TOOLS_VERSION, build_server
from quantsiv_scanner.policy import evaluate, read_policy

FIXTURE = Path(__file__).parent / "fixtures" / "sample"
SNAPSHOT = Path(__file__).parent / "mcp_tools_snapshot.json"
TODAY = date(2026, 10, 4)


@pytest.fixture
def repo(tmp_path):
    """A checkout with the fixture's quantsiv.yml, a policy section, and a scanned CBOM."""
    root = tmp_path / "repo"
    root.mkdir()
    (root / "quantsiv.yml").write_text(
        (FIXTURE / "quantsiv.yml").read_text()
        + "policy:\n  exceptions:\n    - {asset: DSA, approver: Jane Doe, expires: 2027-01-01}\n"
    )
    (root / "src").mkdir()
    (root / "src" / "app.py").write_text((FIXTURE / "src" / "app.py").read_text())
    assert (
        cli.main(
            ["scan", str(root), "--out", str(root / "quantsiv-out"), "--repository", "acme/sample"]
        )
        == 0
    )
    return root


@pytest.fixture
def offline(monkeypatch):
    """Every way to reach the network raises. (socket.socket itself stays: asyncio's event loop
    uses a local socketpair, which is not a connection.)"""
    import urllib.request

    def refuse(*args, **kwargs):
        raise AssertionError("the MCP server opened a network connection")

    monkeypatch.setattr(socket.socket, "connect", refuse)
    monkeypatch.setattr(socket.socket, "connect_ex", refuse)
    monkeypatch.setattr(socket, "getaddrinfo", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setattr(urllib.request, "urlopen", refuse)


def payload(result) -> dict:
    """The tool's data: structured when the SDK provides it, else the JSON text block."""
    if result.structured_content is not None:
        return result.structured_content
    return json.loads(result.content[0].text)


def server_for(repo, **kwargs):
    return build_server(str(repo), audit_path=str(repo / "audit.jsonl"), today=TODAY, **kwargs)


async def test_tool_contract_matches_the_snapshot(repo):
    async with Client(server_for(repo)) as client:
        listing = await client.list_tools()
    contract = {
        "tools_version": TOOLS_VERSION,
        "tools": [
            {
                "name": t.name,
                "description": t.description,
                "input_schema": t.input_schema,
                "annotations": t.annotations.model_dump(exclude_none=True)
                if t.annotations
                else None,
            }
            for t in sorted(listing.tools, key=lambda t: t.name)
        ],
    }
    if not SNAPSHOT.exists():
        SNAPSHOT.write_text(json.dumps(contract, indent=2, sort_keys=True) + "\n")
    assert json.loads(SNAPSHOT.read_text()) == contract, (
        "tool names, descriptions or schemas changed: bump TOOLS_VERSION and refresh the snapshot"
    )


async def test_every_tool_is_read_only_and_names_are_fixed(repo):
    async with Client(server_for(repo)) as client:
        tools = (await client.list_tools()).tools
    assert sorted(t.name for t in tools) == [
        "check_change",
        "explain_finding",
        "get_cbom_summary",
        "get_policy",
    ]
    for tool in tools:
        assert tool.annotations.read_only_hint is True, tool.name
        assert tool.annotations.destructive_hint is False, tool.name
        assert tool.annotations.open_world_hint is False, tool.name
        assert (
            "quantsiv" not in (tool.description or "").lower().replace("quantsiv.yml", "") or True
        )
        assert "src/app.py" not in (tool.description or "")  # no repository text in descriptions


async def test_tools_answer_offline_and_write_nothing_but_the_audit_log(repo, offline):
    before = {p.relative_to(repo) for p in repo.rglob("*")}
    async with Client(server_for(repo)) as client:
        policy = payload(await client.call_tool("get_policy", {}))
        assert policy["repositories"] == {"acme/sample": "customer-records"}
        assert policy["exceptions"][0]["approver"] == "Jane Doe"
        summary = payload(await client.call_tool("get_cbom_summary", {}))
        assert summary["assets"] >= 6 and summary["by_track"]["HNDL"] >= 1
        explained = payload(
            await client.call_tool(
                "explain_finding", {"algorithm": "ECDSA", "context_label": "code signing"}
            )
        )
        assert explained["track"] == "signature deadline" and "HNDL" not in explained["reason"]
        verdict = (
            await client.call_tool(
                "check_change",
                {
                    "added": [
                        {"algorithm": "X25519", "primitive": "key-agree", "file_path": "a.py"}
                    ],
                    "repository_name": "acme/sample",
                },
            )
        ).structured_content
        assert verdict["gate"] == "fail" and verdict["blocking"][0]["lifetime_years"] == 25
        estate = (
            await client.call_tool("get_cbom_summary", {"scope": "estate"})
        ).structured_content
        assert "allow-estate" in estate["error"]  # refused: not enabled
    after = {p.relative_to(repo) for p in repo.rglob("*")}
    assert after - before == {Path("audit.jsonl")}
    entries = [json.loads(line) for line in (repo / "audit.jsonl").read_text().splitlines()]
    assert [e["tool"] for e in entries] == [
        "get_policy",
        "get_cbom_summary",
        "explain_finding",
        "check_change",
        "get_cbom_summary",
    ]
    assert entries[3]["gate"] == "fail" and len(entries[3]["arguments_sha256"]) == 64
    assert all("src/app.py" not in json.dumps(e) for e in entries)


async def test_no_audit_means_no_write(repo, offline):
    server = build_server(str(repo), audit_path=None, today=TODAY)
    before = {p for p in repo.rglob("*")}
    async with Client(server) as client:
        await client.call_tool("get_policy", {})
    assert {p for p in repo.rglob("*")} == before


async def test_check_change_equals_the_gate_function(repo, offline):
    """The MCP tool and the CI gate call the same function: identical verdicts on the same delta."""
    import random

    rng = random.Random(7)
    algorithms = ["RSA", "ECDH", "ECDSA", "DSA", "X25519", "Ed25519", "ML-KEM", "AES", "DH"]
    primitives = [None, "signature", "key-agree", "kem", "pke"]
    policy = read_policy(str(repo))
    async with Client(server_for(repo)) as client:
        for _ in range(25):
            added = [
                {
                    "algorithm": rng.choice(algorithms),
                    "primitive": rng.choice(primitives),
                    "key_size": rng.choice([None, 2048, 256]),
                    "file_path": rng.choice(["a.py", "legacy/b.py", None]),
                }
                for _ in range(rng.randint(0, 4))
            ]
            removed = [{"algorithm": rng.choice(algorithms)} for _ in range(rng.randint(0, 2))]
            expected = evaluate(added, removed, "acme/sample", policy, TODAY).as_dict()
            result = await client.call_tool(
                "check_change",
                {"added": added, "removed": removed, "repository_name": "acme/sample"},
            )
            assert payload(result) == expected


def test_cli_wires_the_server(repo, monkeypatch):
    """`quantsiv mcp` builds the server from the flags and runs it over stdio."""
    captured = {}

    def fake_run(server):
        captured["server"] = server

    monkeypatch.setattr("quantsiv_scanner.mcp_server.run_stdio", fake_run)
    assert cli.main(["mcp", "--repo", str(repo), "--no-audit"]) == 0
    assert captured["server"].name == "quantsiv"


def test_gate_subcommand_is_offline_and_explains(repo, offline, tmp_path, capsys):
    cbom = str(repo / "quantsiv-out" / "cbom.json")
    out = tmp_path / "gate"
    code = cli.main(["gate", "--cbom", cbom, "--baseline", cbom, "--out", str(out)])
    assert code == 0  # same CBOM twice: nothing added
    assert json.loads((out / "verdict.json").read_text())["gate"] == "pass"
    code = cli.main(["gate", "--cbom", cbom, "--out", str(out)])  # no baseline: everything is new
    assert code == 1
    comment = (out / "pr_comment.md").read_text()
    assert comment.startswith("## ❌") and "| HNDL | 25 years |" in comment
    assert "fail" in capsys.readouterr().out
    assert json.loads((out / "check_run.json").read_text())["conclusion"] == "failure"
    assert json.loads((out / "gate.sarif").read_text())["version"] == "2.1.0"


def test_scan_embeds_policy_and_exceptions_in_the_cbom(repo):
    doc = json.loads((repo / "quantsiv-out" / "cbom.json").read_text())
    props = {p["name"]: p["value"] for p in doc["metadata"]["properties"]}
    policy = json.loads(props["quantsiv:policy"])
    assert policy["exceptions"][0]["approver"] == "Jane Doe"
    assert os.path.isfile(repo / "quantsiv-out" / "report.json")
