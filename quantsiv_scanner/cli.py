"""`quantsiv scan`: scan a checkout offline and write cbom.json, findings.sarif, report.json
and report.md. Upload is opt-in (`--upload`, token in QUANTSIV_TOKEN, never on the command
line). `--json` prints the raw engine output for the hosted worker."""

import argparse
import json
import os
import sys
import time
from datetime import UTC, datetime
from urllib.parse import quote

from app.services import ingest
from app.services.cbom import build_cbom
from app.services.errors import ScanError
from app.services.lifetimes import read_lifetimes
from app.services.scoring import is_quantum_vulnerable, score
from quantsiv_scanner import __version__
from quantsiv_scanner.engine import scan_tree
from quantsiv_scanner.outputs import dumps, report, report_markdown, sarif

DEFAULT_API = "https://app.quantsiv.io"  # TODO: confirm the control-plane host before launch
CBOMKIT_DEFAULT = os.path.join("cbom", "cbom.json")  # CBOMkit-action's default output


def _repository(explicit: str | None) -> str | None:
    """owner/name from the flag, else from the CI environment (GitHub, GitLab, Azure)."""
    return (
        explicit
        or os.environ.get("GITHUB_REPOSITORY")
        or os.environ.get("CI_PROJECT_PATH")
        or os.environ.get("BUILD_REPOSITORY_NAME")
    )


def _started() -> float:
    """When the CI step started (QUANTSIV_STEP_STARTED, ISO 8601), else now: time-to-value."""
    raw = os.environ.get("QUANTSIV_STEP_STARTED")
    if raw:
        try:
            return datetime.fromisoformat(raw).timestamp()
        except ValueError:
            pass
    return time.time()


def _base(algorithm: str) -> str:
    return algorithm.upper().split("-")[0].rstrip("0123456789")


def merge_cbomkit(findings: list[dict], cbomkit_path: str) -> tuple[list[dict], str | None]:
    """Add CBOMkit's assets (its CBOM, produced in the same CI run) to the rules' findings.
    A rule finding on the same file, line and algorithm family wins; CBOMkit assets with no
    location are kept as they are."""
    with open(cbomkit_path, "rb") as handle:
        doc = ingest.validate(handle.read())
    seen = {(f.get("file_path"), f.get("line_number"), _base(f["algorithm"])) for f in findings}
    merged = list(findings)
    for asset in ingest.findings_from_cbom(doc):
        key = (asset.get("file_path"), asset.get("line_number"), _base(asset["algorithm"]))
        if key in seen:
            continue
        seen.add(key)
        merged.append({**asset, "source": "cbomkit", "context_label": "CBOMkit finding"})
    return merged, ingest.producer(doc)


def run_scan(path: str, cbomkit: str | None) -> dict:
    """The engine step: rules, then CBOMkit's CBOM if present. No scoring here."""
    root = os.path.abspath(path)
    if not os.path.isdir(root):
        raise ScanError(f"{path} is not a directory")
    findings, scanned = scan_tree(root)
    raw = [f.as_dict() for f in findings]
    cbomkit_path = cbomkit or os.path.join(root, CBOMKIT_DEFAULT)
    producer = None
    if os.path.isfile(cbomkit_path) and not os.path.islink(cbomkit_path):
        try:
            raw, producer = merge_cbomkit(raw, cbomkit_path)
        except ingest.InvalidCbom as exc:
            raise ScanError(f"CBOMkit output {cbomkit_path}: {exc}") from None
    return {"findings": raw, "files_scanned": scanned, "cbomkit": producer}


def scored_results(raw: list[dict], repository: str, lifetimes) -> list[dict]:
    today = datetime.now(UTC).date()
    results = []
    for verdict, finding in score(raw, repository, lifetimes, today):
        results.append(
            {
                **finding,
                "primitive": verdict.primitive,
                "track": verdict.track,
                "severity": verdict.severity,
                "lifetime_years": verdict.lifetime_years,
                "reason": verdict.reason,
                "quantum_vulnerable": is_quantum_vulnerable(finding),
            }
        )
    return results


def upload(cbom_text: str, repository: str, api_url: str) -> dict:
    import httpx  # imported here: the offline path never loads an HTTP client

    token = os.environ.get("QUANTSIV_TOKEN")
    if not token:
        raise ScanError("--upload needs the organisation token in QUANTSIV_TOKEN")
    url = f"{api_url.rstrip('/')}/api/v1/cbom?repository={quote(repository, safe='/')}"
    response = httpx.post(
        url,
        content=cbom_text.encode(),
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/vnd.cyclonedx+json",
            "User-Agent": f"quantsiv-scanner/{__version__}",
        },
        timeout=60,
    )
    if response.status_code != 201:
        detail = (
            response.json().get("detail")
            if "json" in response.headers.get("content-type", "")
            else ""
        )
        raise ScanError(f"upload failed (HTTP {response.status_code}) {detail or ''}".strip())
    return response.json()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="quantsiv", description=__doc__)
    parser.add_argument("--version", action="version", version=f"quantsiv-scanner {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)
    scan = sub.add_parser("scan", help="scan a checkout and write a CBOM, SARIF and a report")
    scan.add_argument("path", nargs="?", default=".", help="repository root (default: .)")
    scan.add_argument("--out", default="quantsiv-out", help="output directory")
    scan.add_argument("--repository", help="owner/name; default from the CI environment")
    scan.add_argument("--cbomkit", help=f"CBOMkit CBOM to merge (default: {CBOMKIT_DEFAULT})")
    scan.add_argument(
        "--json", action="store_true", help="print raw findings as JSON, write nothing"
    )
    scan.add_argument("--upload", action="store_true", help="upload the CBOM (QUANTSIV_TOKEN)")
    scan.add_argument("--api-url", default=os.environ.get("QUANTSIV_API_URL", DEFAULT_API))
    scan.add_argument(
        "--no-gate",
        action="store_true",
        help="with --upload: exit 0 even when the control plane's delta gate fails",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    started = _started()
    try:
        engine = run_scan(args.path, args.cbomkit)
        if args.json:
            print(json.dumps(engine))
            return 0
        repository = _repository(args.repository) or os.path.basename(os.path.abspath(args.path))
        lifetimes = read_lifetimes(os.path.abspath(args.path))
        results = scored_results(engine["findings"], repository, lifetimes)
        os.makedirs(args.out, exist_ok=True)
        seconds = round(time.time() - started, 1)
        cbom_text = build_cbom(
            results,
            repository,
            tool=("quantsiv-scanner", __version__),
            properties={
                "repository": repository,
                "seconds-to-first-cbom": seconds,
                "files-scanned": engine["files_scanned"],
                **({"merged-from": engine["cbomkit"]} if engine["cbomkit"] else {}),
            },
        )
        with open(os.path.join(args.out, "cbom.json"), "w", encoding="utf-8") as handle:
            handle.write(cbom_text)
        meta = {
            "repository": repository,
            "files_scanned": engine["files_scanned"],
            "seconds_to_first_cbom": seconds,
            "lifetime_declared": lifetimes.confidentiality_years(repository) is not None,
            "merged_from": engine["cbomkit"],
        }
        rep = report(results, meta)
        for name, text in (
            ("findings.sarif", dumps(sarif(results))),
            ("report.json", dumps(rep)),
            ("report.md", report_markdown(rep)),
        ):
            with open(os.path.join(args.out, name), "w", encoding="utf-8") as handle:
                handle.write(text)
        print(
            f"quantsiv-scanner {__version__}: {rep['assets']} cryptographic assets "
            f"({rep['quantum_vulnerable']} quantum-vulnerable) in {engine['files_scanned']} "
            f"files; first CBOM after {seconds} s; outputs in {args.out}/"
        )
        if not args.upload:
            return 0
        if not _repository(args.repository):
            raise ScanError("--upload needs --repository owner/name (or a CI environment)")
        result = upload(cbom_text, repository, args.api_url)
        print(
            f"uploaded as scan {result['scan_id']}: gate {result['gate']}"
            + (
                f", new quantum-vulnerable: {', '.join(result['new_quantum_vulnerable'])}"
                if result.get("new_quantum_vulnerable")
                else ""
            )
        )
        return 1 if result["gate"] == "fail" and not args.no_gate else 0
    except ScanError as exc:
        print(f"quantsiv: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
