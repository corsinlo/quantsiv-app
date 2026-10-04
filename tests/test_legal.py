"""Legal routes exist (A33) but publish nothing until LEGAL_READY and D4 (WP8)."""

import pytest
from fastapi.testclient import TestClient

from app.config import get_settings
from app.main import app, create_app
from app.routers.legal import PAGES

client = TestClient(app)


@pytest.mark.parametrize("slug", sorted(PAGES))
def test_placeholders_outside_production_say_so(slug):
    response = client.get(f"/legal/{slug}")
    assert response.status_code == 200
    assert "Not published yet" in response.text
    assert "Musterstra" not in response.text  # never the untracked draft's placeholder entity
    assert "GmbH" not in response.text


def test_unknown_slug_is_404():
    assert client.get("/legal/warranty").status_code == 404


def test_production_hides_the_pages_until_ready(monkeypatch):
    monkeypatch.setenv("ENV", "production")
    get_settings.cache_clear()
    try:
        prod = TestClient(create_app())
        assert prod.get("/legal/privacy").status_code == 404
        assert "/legal/privacy" not in prod.get("/health").text
    finally:
        get_settings.cache_clear()


def test_footer_links_appear_only_when_ready(monkeypatch):
    assert "/legal/privacy" not in client.get("/auth/github/login", follow_redirects=False).text
    monkeypatch.setenv("LEGAL_READY", "true")
    get_settings.cache_clear()
    try:
        ready = TestClient(create_app())
        page = ready.get("/legal/cookies")
        assert page.status_code == 200
        assert "Not published yet" not in page.text
        assert 'href="/legal/privacy"' in page.text  # footer links
    finally:
        get_settings.cache_clear()
