"""axe-core WCAG 2.1 A/AA check on the rendered pages (WP2 acceptance).

Run with `pytest -m a11y`. Needs a Playwright Chromium: `python -m playwright install chromium`,
or set PLAYWRIGHT_CHROMIUM_EXECUTABLE to an existing binary. The assets are self-hosted (WP3),
so the check needs no network and also fails on any CSP violation.
"""

import os
import socket
import threading
import time

import pytest
import uvicorn

from app.main import app
from app.scans import get_scan_store
from tests.fakes import SCANS, FakeScanStore

pytestmark = pytest.mark.a11y

WCAG_TAGS = ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"]


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="module")
def base_url():
    port = _free_port()
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.monotonic() + 10
    while not server.started:
        if time.monotonic() > deadline:
            raise RuntimeError("test server did not start")
        time.sleep(0.05)
    yield f"http://127.0.0.1:{port}"
    server.should_exit = True
    thread.join(timeout=5)


@pytest.fixture(scope="module")
def page():
    sync_api = pytest.importorskip("playwright.sync_api")
    executable = os.environ.get("PLAYWRIGHT_CHROMIUM_EXECUTABLE") or None
    with sync_api.sync_playwright() as p:
        browser = p.chromium.launch(executable_path=executable)
        yield browser.new_page()
        browser.close()


@pytest.fixture
def store(request):
    if request.param:
        app.dependency_overrides[get_scan_store] = FakeScanStore
    yield
    app.dependency_overrides.pop(get_scan_store, None)


def _violations(page) -> list[str]:
    from axe_playwright_python.sync_playwright import Axe

    result = Axe().run(page, options={"runOnly": {"type": "tag", "values": WCAG_TAGS}})
    return [
        f"{v['id']} ({v['impact']}): {[n['target'] for n in v['nodes']]}"
        for v in result.response["violations"]
    ]


def _open(page, url: str) -> None:
    from playwright.sync_api import TimeoutError as PlaywrightTimeoutError

    try:
        page.goto(url, wait_until="networkidle", timeout=15000)
    except PlaywrightTimeoutError:  # a CDN that hangs: check the page as rendered
        page.wait_for_load_state("load")


PAGES = [(False, "/dashboard"), (True, "/dashboard")] + [
    (True, path)
    for scan_id in SCANS
    for path in (f"/dashboard/scans/{scan_id}", f"/dashboard/scans/{scan_id}/live")
]


@pytest.mark.parametrize(
    "store,path", PAGES, indirect=["store"], ids=[f"{p}{'' if d else '-empty'}" for d, p in PAGES]
)
def test_page_has_no_wcag_violations(store, path, page, base_url):
    csp_errors = []
    page.on(
        "console",
        lambda msg: "Content Security Policy" in msg.text and csp_errors.append(msg.text),
    )
    _open(page, base_url + path)
    assert _violations(page) == []
    assert csp_errors == [], "the CSP blocked something on this page (A20)"


@pytest.mark.parametrize("store", [True], indirect=True)
def test_expanded_finding_details_have_no_wcag_violations(store, page, base_url):
    _open(page, base_url + "/dashboard/scans/1")
    button = page.locator("[data-disclosure]").first
    button.click()
    assert button.get_attribute("aria-expanded") == "true"
    assert page.locator("#finding-detail-1").is_visible()
    assert _violations(page) == []
