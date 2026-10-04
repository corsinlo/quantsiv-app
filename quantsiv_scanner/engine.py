"""Walk a checkout and apply the rules. Pure Python, no network, bounded work per file."""

import os
from dataclasses import asdict, dataclass, replace

from quantsiv_scanner.rules import RULES, Rule, pqc_primitive

SKIP_DIRS = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        "node_modules",
        "vendor",
        "dist",
        "build",
        "target",
        "out",
        ".venv",
        "venv",
        "env",
        "__pycache__",
        ".tox",
        ".mypy_cache",
        ".pytest_cache",
        ".idea",
        ".vscode",
        "bower_components",
        ".gradle",
        ".next",
        ".nuxt",
        "coverage",
    }
)
MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_LINE_CHARS = 4000  # minified or generated lines are skipped, not regex-scanned
MAX_FILES = 200_000
SPECIAL_NAMES = {"dockerfile": "dockerfile", "makefile": "makefile", "jenkinsfile": "groovy"}


@dataclass(frozen=True)
class Finding:
    rule_id: str
    algorithm: str
    primitive: str | None
    key_size: int | None
    file_path: str
    line_number: int
    context_label: str
    confidence: float
    quantum_safe: bool
    raw_match: str
    source: str = "quantsiv-rules"

    def as_dict(self) -> dict:
        return asdict(self)


def file_kind(path: str) -> str:
    name = os.path.basename(path).lower()
    if name in SPECIAL_NAMES:
        return SPECIAL_NAMES[name]
    if name.startswith("dockerfile."):
        return "dockerfile"
    return name.rsplit(".", 1)[-1] if "." in name else ""


def _rules_for(kind: str) -> list[Rule]:
    return [rule for rule in RULES if kind in rule.extensions]


_RULES_BY_KIND: dict[str, list[Rule]] = {}


def rules_for(kind: str) -> list[Rule]:
    if kind not in _RULES_BY_KIND:
        _RULES_BY_KIND[kind] = _rules_for(kind)
    return _RULES_BY_KIND[kind]


def scan_text(text: str, rel_path: str, kind: str | None = None) -> list[Finding]:
    """Apply the rules to one file's text. Returns at most one finding per (line, algorithm)."""
    rules = rules_for(kind if kind is not None else file_kind(rel_path))
    if not rules:
        return []
    found: dict[tuple[int, str], Finding] = {}
    for number, line in enumerate(text.splitlines(), start=1):
        if len(line) > MAX_LINE_CHARS or not line.strip():
            continue
        for rule in rules:
            if rule.needle and rule.needle not in line:
                continue
            match = rule.pattern.search(line)
            if not match:
                continue
            algorithm = rule.algorithm(match) if callable(rule.algorithm) else rule.algorithm
            primitive = rule.primitive
            if rule.quantum_safe and primitive is None:
                primitive = pqc_primitive(algorithm)
            finding = Finding(
                rule_id=rule.id,
                algorithm=algorithm,
                primitive=primitive,
                key_size=rule.key_size(match),
                file_path=rel_path,
                line_number=number,
                context_label=rule.context,
                confidence=rule.confidence,
                quantum_safe=rule.quantum_safe,
                raw_match=line.strip()[:200],
            )
            key = (number, algorithm)
            current = found.get(key)
            if current is None:
                found[key] = finding
            else:  # same line, same algorithm: keep the surer rule, but never lose a key size
                best, other = sorted((current, finding), key=lambda f: -f.confidence)
                if best.key_size is None and other.key_size is not None:
                    best = replace(best, key_size=other.key_size)
                found[key] = best
    return list(found.values())


def iter_files(root: str):
    """Yield (absolute path, path relative to root) for scannable regular files, never
    following symlinks (the tree is untrusted)."""
    count = 0
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS and not d.startswith("."))
        for name in sorted(filenames):
            path = os.path.join(dirpath, name)
            if os.path.islink(path) or not os.path.isfile(path):
                continue
            if not rules_for(file_kind(path)):
                continue
            count += 1
            if count > MAX_FILES:
                return
            yield path, os.path.relpath(path, root).replace(os.sep, "/")


def scan_tree(root: str) -> tuple[list[Finding], int]:
    """Scan a checkout. Returns (findings, number of files scanned)."""
    findings: list[Finding] = []
    scanned = 0
    for path, rel in iter_files(root):
        try:
            if os.path.getsize(path) > MAX_FILE_BYTES:
                continue
            with open(path, "rb") as handle:
                data = handle.read()
        except OSError:
            continue
        if b"\0" in data[:8192]:
            continue  # binary
        scanned += 1
        findings.extend(scan_text(data.decode("utf-8", errors="replace"), rel))
    findings.sort(key=lambda f: (f.file_path, f.line_number, f.algorithm))
    return findings, scanned
