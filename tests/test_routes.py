import pytest
from fastapi.testclient import TestClient

from app.config import get_settings
from app.main import app, create_app

client = TestClient(app)


def test_health():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "healthy"}


@pytest.mark.parametrize("path", ["/dashboard", "/dashboard/scans/1", "/dashboard/scans/1/live"])
def test_page_renders(path):
    response = client.get(path)
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    assert 'id="main-content"' in response.text


def test_static_logo_is_served():
    assert client.get("/static/logo-symbol.png").status_code == 200


def test_docs_are_disabled_in_production(monkeypatch):
    monkeypatch.setenv("ENV", "production")
    get_settings.cache_clear()
    try:
        prod = TestClient(create_app())
        assert prod.get("/docs").status_code == 404
        assert prod.get("/openapi.json").status_code == 404
        assert prod.get("/health").status_code == 200
    finally:
        get_settings.cache_clear()


def test_docs_are_served_in_development():
    assert client.get("/openapi.json").status_code == 200
