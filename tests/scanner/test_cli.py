"""`quantsiv scan`: offline outputs, CBOMkit merge, time-to-value, upload (WP7 acceptance)."""

import json
import os
import socket
import subprocess
import sys
from pathlib import Path

import httpx
import pytest
from cyclonedx.schema import SchemaVersion
from cyclonedx.validation.json import JsonStrictValidator

from quantsiv_scanner import cli

FIXTURE = str(Path(__file__).parent / "fixtures" / "sample")


@pytest.fixture
def offline(monkeypatch):
    """Any attempt to open a socket fails the test: the scan must not need the network."""

    def refuse(*args, **kwargs):
        raise AssertionError("network access during an offline scan")

    monkeypatch.setattr(socket, "socket", refuse)
    monkeypatch.setattr(socket, "getaddrinfo", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)


@pytest.fixture
def out(tmp_path, offline, monkeypatch, capsys):
    monkeypatch.delenv("QUANTSIV_TOKEN", raising=False)
    monkeypatch.setenv("QUANTSIV_STEP_STARTED", "2000-01-01T00:00:00+00:00")
    code = cli.main(["scan", FIXTURE, "--out", str(tmp_path), "--repository", "acme/sample"])
    assert code == 0, capsys.readouterr()
    return tmp_path


def test_offline_scan_writes_a_valid_cbom(out):
    text = (out / "cbom.json").read_text()
    assert JsonStrictValidator(SchemaVersion.V1_6).validate_str(text) is None
    doc = json.loads(text)
    assert doc["metadata"]["component"]["name"] == "acme/sample"
    assert doc["metadata"]["tools"]["components"][0]["name"] == "quantsiv-scanner"
    props = {p["name"]: p["value"] for p in doc["metadata"]["properties"]}
    assert props["quantsiv:repository"] == "acme/sample"
    assert float(props["quantsiv:seconds-to-first-cbom"]) > 1e8  # measured from the CI step start
    assert props["quantsiv:merged-from"] == "cbomkit 2.3.0"
    names = {c["name"] for c in doc["components"]}
    assert {"RSA-2048", "X25519-256", "ML-KEM-768", "AES-256-GCM"} <= names
    sources = {
        p["value"]
        for c in doc["components"]
        for p in c.get("properties", [])
        if p["name"] == "quantsiv:source"
    }
    assert sources == {"quantsiv-rules", "cbomkit"}


def test_hndl_track_uses_the_declared_lifetime(out):
    rep = json.loads((out / "report.json").read_text())
    assert rep["hndl_ranked"] is True
    ecdh = next(
        f for f in rep["findings"] if f["algorithm"] == "ECDH" and f["file_path"] == "src/app.py"
    )
    assert (ecdh["track"], ecdh["severity"], ecdh["lifetime_years"]) == ("HNDL", "critical", 25)
    jwt = next(
        f for f in rep["findings"] if f["file_path"] == "src/app.py" and f["line_number"] == 11
    )
    assert jwt["track"] == "signature deadline"
    mlkem = next(f for f in rep["findings"] if f["algorithm"] == "ML-KEM")
    assert mlkem["quantum_vulnerable"] is False
    assert rep["findings"][0]["severity"] == "critical"  # ranked, highest first


def test_cbomkit_assets_merge_without_duplicates(out):
    rep = json.loads((out / "report.json").read_text())
    app_py_6 = [
        f for f in rep["findings"] if f["file_path"] == "src/app.py" and f["line_number"] == 6
    ]
    assert len(app_py_6) == 1 and app_py_6[0]["source"] == "quantsiv-rules"  # the rule finding wins
    aes = next(f for f in rep["findings"] if f["algorithm"] == "AES-256-GCM")
    assert aes["source"] == "cbomkit" and aes["quantum_vulnerable"] is False


def test_sarif_is_well_formed(out):
    doc = json.loads((out / "findings.sarif").read_text())
    assert doc["version"] == "2.1.0"
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "quantsiv-scanner"
    rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
    for result in run["results"]:
        assert result["ruleId"] in rule_ids
        assert result["level"] in {"error", "warning", "note", "none"}
        loc = result["locations"][0]["physicalLocation"]
        assert loc["artifactLocation"]["uri"] and loc["region"]["startLine"] >= 1


def test_markdown_report(out):
    text = (out / "report.md").read_text()
    assert "# Quantsiv scan report" in text
    assert "`src/app.py:9`" in text
    assert "NIST IR 8547" in text


def test_json_mode_prints_raw_findings_and_writes_nothing(tmp_path, offline, capsys):
    assert cli.main(["scan", FIXTURE, "--json", "--out", str(tmp_path / "never")]) == 0
    engine = json.loads(capsys.readouterr().out)
    assert engine["files_scanned"] >= 12
    assert engine["cbomkit"] == "cbomkit 2.3.0"
    assert all("severity" not in f for f in engine["findings"])  # unscored: the worker scores
    assert not (tmp_path / "never").exists()


def test_subprocess_entry_point(tmp_path):
    proc = subprocess.run(
        [sys.executable, "-m", "quantsiv_scanner", "scan", FIXTURE, "--out", str(tmp_path)],
        capture_output=True,
        text=True,
        cwd=str(Path(__file__).parents[2]),
        env={**os.environ, "GITHUB_REPOSITORY": "acme/from-ci"},
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    assert "cryptographic assets" in proc.stdout
    assert (
        json.loads((tmp_path / "cbom.json").read_text())["metadata"]["component"]["name"]
        == "acme/from-ci"
    )


def test_missing_directory_is_a_clear_error(tmp_path, capsys):
    assert cli.main(["scan", str(tmp_path / "nope"), "--out", str(tmp_path)]) == 2
    assert "not a directory" in capsys.readouterr().err


def test_invalid_cbomkit_file_is_a_clear_error(tmp_path, capsys):
    bad = tmp_path / "cbom.json"
    bad.write_text("{}")
    code = cli.main(["scan", FIXTURE, "--out", str(tmp_path / "o"), "--cbomkit", str(bad)])
    assert code == 2
    assert "CBOMkit output" in capsys.readouterr().err


class FakeControlPlane:
    def __init__(self, gate="pass"):
        self.gate = gate
        self.requests = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return httpx.Response(
            201, json={"scan_id": 7, "gate": self.gate, "new_quantum_vulnerable": ["X25519"]}
        )


@pytest.fixture
def control_plane(monkeypatch):
    plane = FakeControlPlane()
    real_post = httpx.post

    def post(url, **kwargs):
        with httpx.Client(transport=httpx.MockTransport(plane.handler)) as client:
            return client.post(url, **kwargs)

    monkeypatch.setattr(httpx, "post", post)
    yield plane
    monkeypatch.setattr(httpx, "post", real_post)


def test_upload_sends_the_cbom_with_the_token_from_the_environment(
    tmp_path, monkeypatch, control_plane, capsys
):
    monkeypatch.setenv("QUANTSIV_TOKEN", "qsv_test_token")
    code = cli.main(
        [
            "scan",
            FIXTURE,
            "--out",
            str(tmp_path),
            "--repository",
            "acme/sample",
            "--upload",
            "--api-url",
            "https://cp.example",
        ]
    )
    assert code == 0
    (request,) = control_plane.requests
    assert str(request.url) == "https://cp.example/api/v1/cbom?repository=acme/sample"
    assert request.headers["authorization"] == "Bearer qsv_test_token"
    assert "qsv_test_token" not in str(request.url)
    assert json.loads(request.content)["specVersion"] == "1.6"
    assert "uploaded as scan 7: gate pass" in capsys.readouterr().out


def test_failed_gate_fails_the_build_unless_no_gate(tmp_path, monkeypatch, control_plane):
    monkeypatch.setenv("QUANTSIV_TOKEN", "qsv_test_token")
    control_plane.gate = "fail"
    args = ["scan", FIXTURE, "--out", str(tmp_path), "--repository", "acme/sample", "--upload"]
    assert cli.main(args) == 1
    assert cli.main([*args, "--no-gate"]) == 0


def test_upload_without_a_token_is_refused_before_any_request(
    tmp_path, monkeypatch, control_plane, capsys
):
    monkeypatch.delenv("QUANTSIV_TOKEN", raising=False)
    code = cli.main(
        ["scan", FIXTURE, "--out", str(tmp_path), "--repository", "acme/sample", "--upload"]
    )
    assert code == 2
    assert "QUANTSIV_TOKEN" in capsys.readouterr().err
    assert control_plane.requests == []


def test_there_is_no_token_flag():
    # Tokens travel in the environment only, never in argv (CLAUDE.md, Security)
    with pytest.raises(SystemExit):
        cli.build_parser().parse_args(["scan", ".", "--token", "x"])


def test_tls_flag_adds_probe_findings_to_the_cbom(tmp_path, monkeypatch, capsys):
    import json

    from app.services.tls import TlsProbe
    from quantsiv_scanner import cli

    def fake_probe(host):
        if host == "down.example":
            return TlsProbe(domain=host, ip_address=None, error="Name does not resolve")
        return TlsProbe(
            domain=host,
            ip_address="203.0.113.7",
            tls_version="TLSv1.3",
            cipher_suite="TLS_AES_256_GCM_SHA384",
            key_exchange_group="x25519",
            pqc_key_exchange=False,
            cert_algorithm="EC",
            cert_key_bits=256,
        )

    monkeypatch.setattr("app.services.tls.probe_endpoint", fake_probe)
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "a.py").write_text("rsa.generate_private_key(public_exponent=65537, key_size=2048)\n")
    out = tmp_path / "out"
    code = cli.main(
        [
            "scan",
            str(repo),
            "--out",
            str(out),
            "--repository",
            "o/r",
            "--tls",
            "Api.Example",
            "--tls",
            "down.example",
        ]
    )
    assert code == 0
    assert "TLS probe of down.example: Name does not resolve" in capsys.readouterr().err
    components = json.loads((out / "cbom.json").read_text())["components"]
    assert {c["name"] for c in components} >= {"RSA-2048", "X25519-256", "EC-256"}
    locations = {
        o["location"] for c in components for o in (c.get("evidence") or {}).get("occurrences", [])
    }
    assert "tls://api.example:443" in locations
