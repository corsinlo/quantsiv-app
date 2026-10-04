"""Gate explainer (WP10): renders a verdict as a check-run, a PR comment and SARIF, from Jinja
templates. Every new asset shows its track, its declared lifetime, the cited authority and the
approved alternatives. No model is involved: the text is a function of the verdict."""

import os

from jinja2 import Environment, FileSystemLoader

from quantsiv_scanner import __version__
from quantsiv_scanner.outputs import sarif
from quantsiv_scanner.policy import Verdict

_TEMPLATES = os.path.join(os.path.dirname(__file__), "templates")
_env = Environment(loader=FileSystemLoader(_TEMPLATES), autoescape=False, trim_blocks=True)


def _cell(value) -> str:
    """Markdown table cell: no pipes or newlines (values come from code: paths, names)."""
    return str(value if value is not None else "-").replace("|", "\\|").replace("\n", " ")


_env.filters["cell"] = _cell


def pr_comment(verdict: Verdict) -> str:
    return _env.get_template("pr_comment.md.j2").render(v=verdict, version=__version__)


def check_run(verdict: Verdict) -> dict:
    """GitHub check-run `output`: title, summary, and the detailed text."""
    status = "Quantsiv gate: pass" if verdict.passed else "Quantsiv gate: fail"
    return {
        "title": status,
        "summary": verdict.summary,
        "text": _env.get_template("check_run.md.j2").render(v=verdict, version=__version__),
        "conclusion": "success" if verdict.passed else "failure",
    }


def gate_sarif(verdict: Verdict) -> dict:
    """SARIF for the delta only: one result per newly added asset, blocking ones as errors."""
    results = []
    for e in verdict.added:
        results.append(
            {
                **e.as_dict(),
                "rule_id": "gate-blocked" if e.blocking else f"gate-{e.track.replace(' ', '-')}",
                "severity": e.severity
                if e.blocking
                else ("medium" if e.quantum_vulnerable else "info"),
                "context_label": "newly added cryptographic asset",
                "reason": e.reason + (" Blocked by policy." if e.blocking else ""),
            }
        )
    return sarif(results)
