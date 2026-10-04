import re
from pathlib import Path

import pytest
from jinja2 import Environment, FileSystemLoader

TEMPLATES = Path("app/templates")
env = Environment(loader=FileSystemLoader(TEMPLATES), autoescape=True)
STATUSES = ["done", "failed", "queued", "running"]


def scan(status: str) -> dict:
    return {"id": 1, "repo_full_name": "o/r", "status": status, "risk_score": 10, "findings": []}


@pytest.mark.parametrize("name", sorted(p.name for p in TEMPLATES.rglob("*.html")))
def test_template_compiles(name):
    env.get_template(name)


@pytest.mark.parametrize(
    "name,ctx",
    [("dashboard.html", {}), ("scan_live.html", {"scan_id": 1})]
    + [("scan_details.html", {"scan": scan(s)}) for s in STATUSES],
)
def test_rendered_page_is_wired(name, ctx):
    html = env.get_template(name).render(request=None, title="t", **ctx)
    assert "`n" not in html
    ids = set(re.findall(r'id="([^"]+)"', html))
    for target in re.findall(r'hx-target="#([^"]+)"', html):
        assert target in ids, f"{name}: hx-target #{target} does not exist"


@pytest.mark.parametrize("status", STATUSES)
def test_scan_details_divs_balance(status):
    html = env.get_template("scan_details.html").render(request=None, title="t", scan=scan(status))
    assert html.count("<div") == html.count("</div>")
    assert html.count("<h2") == html.count("</h2>")
