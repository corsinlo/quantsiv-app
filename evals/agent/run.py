"""Record one gate verdict for an eval run. See README.md. Records verdicts only."""

import argparse
import json
import os
import sys
from datetime import UTC, datetime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from quantsiv_scanner.engine import scan_tree
from quantsiv_scanner.policy import evaluate, read_policy

RESULTS = os.path.join(os.path.dirname(__file__), "results.jsonl")


def assets(path: str) -> list[dict]:
    findings, _ = scan_tree(path)
    return [f.as_dict() for f in findings]


def key(f: dict) -> tuple:
    return (f["algorithm"], f.get("primitive"), f.get("file_path"))


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--task", required=True)
    parser.add_argument("--assistant", required=True)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--with-mcp", action="store_true")
    group.add_argument("--without-mcp", action="store_true")
    parser.add_argument("--before", required=True)
    parser.add_argument("--after", required=True)
    parser.add_argument("--results", default=RESULTS)
    args = parser.parse_args(argv)

    before, after = assets(args.before), assets(args.after)
    seen = {key(f) for f in before}
    added = [f for f in after if key(f) not in seen]
    now = {key(f) for f in after}
    removed = [f for f in before if key(f) not in now]
    policy = read_policy(args.after)
    verdict = evaluate(added, removed, args.task, policy, datetime.now(UTC).date())
    record = {
        "at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "task": args.task,
        "assistant": args.assistant,
        "mcp": bool(args.with_mcp),
        "gate": "pass" if verdict.passed else "fail",
        "blocking": sorted({e.algorithm for e in verdict.blocking}),
        "added": len(verdict.added),
    }
    with open(args.results, "a", encoding="utf-8") as handle:
        handle.write(json.dumps(record) + "\n")
    print(json.dumps(record))
    return 0


if __name__ == "__main__":
    sys.exit(main())
