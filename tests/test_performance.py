"""Static weight per page (WP9, A47): under 100 KB, excluding fonts (there are none)."""

import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.scans import get_scan_store
from tests.fakes import FakeScanStore
from tests.helpers import sign_in

BUDGET = 100 * 1024
ASSET = re.compile(r'(?:src|href)="(/static/[^"]+)"')


@pytest.fixture
def client():
    app.dependency_overrides[get_scan_store] = FakeScanStore
    with TestClient(app) as c:
        sign_in(c)
        yield c
    app.dependency_overrides.pop(get_scan_store, None)


@pytest.mark.parametrize("path", ["/dashboard", "/dashboard/scans/1", "/dashboard/scans/1/live"])
def test_static_weight_per_page_is_under_budget(client, path):
    html = client.get(path).text
    assets = set(ASSET.findall(html))
    assert "/static/app.css" in assets
    total = sum(Path("app" + asset).stat().st_size for asset in assets)
    assert total < BUDGET, f"{path}: {total} bytes of static assets: {sorted(assets)}"


@pytest.mark.parametrize("path", ["/dashboard", "/dashboard/scans/1", "/dashboard/scans/1/live"])
def test_every_script_is_deferred(client, path):
    for tag in re.findall(r"<script[^>]*>", client.get(path).text):
        assert " defer" in tag, tag


def test_no_oversized_images_are_served():
    for image in Path("app/static").rglob("*.png"):
        assert image.stat().st_size < 32 * 1024, image
