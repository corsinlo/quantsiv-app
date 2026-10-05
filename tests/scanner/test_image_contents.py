"""The scanner image copies a fixed list of app modules; the scanner must import nothing else."""

import ast
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def image_modules() -> set[str]:
    text = (ROOT / "Dockerfile").read_text()
    stage = text.split("AS scanner", 1)[1]
    copied: set[str] = set()
    block = stage.replace("\\\n", " ")
    for match in re.finditer(
        r"^COPY ((?:app/\S+\s+)+)\./(app(?:/services)?)/\s*$", block, re.MULTILINE
    ):
        for src in match.group(1).split():
            copied.add(src.removesuffix(".py").replace("/", "."))
            copied.add(
                src.removesuffix(".py").replace("/", ".").replace("__init__", "").rstrip(".")
            )
    return copied


def imported_app_modules(path: Path) -> set[str]:
    found: set[str] = set()
    for node in ast.walk(ast.parse(path.read_text())):
        if isinstance(node, ast.ImportFrom) and node.module and node.module.startswith("app"):
            found.add(node.module)
            found.update(f"{node.module}.{alias.name}" for alias in node.names)
        elif isinstance(node, ast.Import):
            found.update(a.name for a in node.names if a.name.startswith("app"))
    return found


def test_scanner_and_its_app_dependencies_only_import_what_the_image_ships():
    shipped = image_modules()
    assert "app.services.tls" in shipped and "app.services.scoring" in shipped
    sources = list((ROOT / "quantsiv_scanner").glob("*.py"))
    sources += [
        ROOT / "app" / "services" / f"{name}.py"
        for name in ("tls", "scoring", "ingest", "cbom", "lifetimes", "ssrf")
    ]
    for source in sources:
        for module in imported_app_modules(source):
            if module in ("app", "app.services"):
                continue
            # "from app.services import ingest" yields app.services.ingest; names that are not
            # modules (functions) are fine as long as their module is shipped
            parent = module.rsplit(".", 1)[0]
            assert module in shipped or parent in shipped, (
                f"{source.name} imports {module}, not in the image"
            )
