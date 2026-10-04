import re
from pathlib import Path

import pytest

from app.models import ScanStatus
from app.templating import templates
from tests.fakes import SCANS

TEMPLATES = Path("app/templates")
env = templates.env
EMPTY_STATS = {"repos_scanned": 0, "findings": 0, "avg_risk_score": None}


def render(name: str, **ctx) -> str:
    return env.get_template(name).render(request=None, title="t", **ctx)


@pytest.mark.parametrize("name", sorted(p.name for p in TEMPLATES.rglob("*.html")))
def test_template_compiles(name):
    env.get_template(name)


@pytest.mark.parametrize(
    "name,ctx",
    [
        ("dashboard.html", {"scans": [], "stats": EMPTY_STATS}),
        ("dashboard.html", {"scans": list(SCANS.values()), "stats": EMPTY_STATS}),
        ("scan_live.html", {"scan_id": 1, "repo_name": "o/r"}),
    ]
    + [("scan_details.html", {"scan": s}) for s in SCANS.values()],
)
def test_rendered_page_is_wired(name, ctx):
    html = render(name, **ctx)
    assert "`n" not in html
    ids = re.findall(r'id="([^"]+)"', html)
    assert len(ids) == len(set(ids)), f"{name}: duplicate ids"
    for attr in ("hx-target", "href"):
        for target in re.findall(rf'{attr}="#([^"]+)"', html):
            assert target in ids, f"{name}: {attr} #{target} does not exist"
    for target in re.findall(r'aria-controls="([^"]+)"', html):
        assert target in ids, f"{name}: aria-controls {target} does not exist"


@pytest.mark.parametrize("scan", SCANS.values(), ids=lambda s: f"{s['id']}-{s['status']}")
def test_scan_details_renders_every_status(scan):
    html = render("scan_details.html", scan=scan)
    assert html.count("<div") == html.count("</div>")
    assert html.count("<h2") == html.count("</h2>")
    assert "Math.random" not in html


def test_no_fabricated_values_in_templates():
    for path in TEMPLATES.rglob("*.html"):
        text = path.read_text(encoding="utf-8")
        for fake in ("Math.random", "7 critical", "or 0.8", "Compliance Rate", "example/repo"):
            assert fake not in text, f"{path}: {fake}"


def test_missing_confidence_shows_a_dash_not_a_default():
    html = render("scan_details.html", scan=SCANS[1])
    assert "90%" in html  # the ECDH finding's real confidence
    assert "80%" not in html


def _detail_rows(html: str) -> dict[str, str]:
    rows = re.findall(r'<tr id="(finding-detail-\d+)" hidden>(.*?)</tr>', html, re.DOTALL)
    return dict(rows)


def test_hndl_text_only_for_confidentiality_primitives():
    rows = _detail_rows(render("scan_details.html", scan=SCANS[1]))
    key_agree, signature, unclassified = rows.values()
    assert "Harvest now, decrypt later" in key_agree
    assert "31 December 2030" in key_agree
    assert "Harvest now, decrypt later" not in signature
    assert "future forgery" in signature
    assert "31 December 2031" in signature
    assert "Harvest now, decrypt later" not in unclassified
    assert "not been classified" in unclassified


def test_no_unsourced_timeline():
    html = render("scan_details.html", scan=SCANS[1])
    assert "2030-2035" not in html


def test_clean_scan_is_not_shown_as_empty_or_failed():
    html = render("scan_details.html", scan=SCANS[2])
    assert "detected no quantum-vulnerable cryptography" in html
    assert "No findings yet" not in html


def test_dashboard_empty_state():
    html = render("dashboard.html", scans=[], stats=EMPTY_STATS)
    assert 'id="scans-empty"' in html
    assert "<table" not in html


def test_status_vocabulary():
    assert [s.value for s in ScanStatus] == ["queued", "running", "done", "failed"]


def test_tracks_are_labelled():
    html = render("scan_details.html", scan=SCANS[1])
    assert "HNDL · 25-year data" in html
    assert "Signature deadline" in html
    assert "Protects data that must stay confidential for 25 years." in html
