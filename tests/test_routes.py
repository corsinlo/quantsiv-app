import pytest
from fastapi.testclient import TestClient

from app.config import get_settings
from app.main import app, create_app
from app.scans import get_repo_access, get_scan_store
from tests.fakes import SCANS, FakeRepoAccess, FakeScanStore
from tests.helpers import csrf, sign_in


@pytest.fixture
def client():
    with TestClient(app) as c:
        sign_in(c)
        yield c


@pytest.fixture
def fake_store():
    app.dependency_overrides[get_scan_store] = FakeScanStore
    yield
    app.dependency_overrides.pop(get_scan_store, None)


def test_health():
    response = TestClient(app).get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "healthy"}


def test_dashboard_without_data_shows_the_empty_state(client):
    response = client.get("/dashboard")
    assert response.status_code == 200
    assert 'id="scans-empty"' in response.text
    assert 'id="main-content"' in response.text
    assert "Signed in as test-user" in response.text


@pytest.mark.parametrize("path", ["/dashboard/scans/1", "/dashboard/scans/1/live", "/api/scans/1"])
def test_unknown_scan_is_404_not_a_fake(client, path):
    assert client.get(path).status_code == 404


def test_worker_health_is_not_claimed():
    assert TestClient(app).get("/worker/health").status_code == 501


@pytest.mark.usefixtures("fake_store")
def test_dashboard_lists_scans_and_computes_stats(client):
    response = client.get("/dashboard")
    assert response.status_code == 200
    for scan in SCANS.values():
        assert scan["repo_full_name"] in response.text
    assert 'id="repos-scanned">2<' in response.text  # two done scans
    assert 'id="findings-total">3<' in response.text  # 3 findings + a clean scan


@pytest.mark.usefixtures("fake_store")
@pytest.mark.parametrize("scan_id", list(SCANS))
def test_scan_pages_render_for_every_status(client, scan_id):
    for path in (f"/dashboard/scans/{scan_id}", f"/dashboard/scans/{scan_id}/live"):
        response = client.get(path)
        assert response.status_code == 200, path
        assert SCANS[scan_id]["repo_full_name"] in response.text


@pytest.mark.usefixtures("fake_store")
def test_api_returns_the_stored_scan(client):
    assert client.get("/api/scans/1").json()["repo_full_name"] == SCANS[1]["repo_full_name"]


@pytest.fixture
def repo_access():
    app.dependency_overrides[get_repo_access] = lambda: FakeRepoAccess({"test-org/allowed"})
    yield
    app.dependency_overrides.pop(get_repo_access, None)


@pytest.mark.usefixtures("repo_access")
def test_manual_scan_of_an_installation_repo_is_not_implemented_yet(client):
    response = client.post(
        "/api/scans",
        json={"repo_full_name": "test-org/allowed"},
        headers={"X-CSRF-Token": csrf(client)},
    )
    assert response.status_code == 501


@pytest.mark.usefixtures("repo_access")
def test_manual_scan_of_a_repo_outside_the_installations_is_404(client):
    response = client.post(
        "/api/scans",
        json={"repo_full_name": "someone/else"},
        headers={"X-CSRF-Token": csrf(client)},
    )
    assert response.status_code == 404


@pytest.mark.parametrize("name", ["no-slash", "a/b/c", "o/r;rm -rf", "-" * 40 + "/r"])
def test_manual_scan_rejects_invalid_repo_names(client, name):
    response = client.post(
        "/api/scans", json={"repo_full_name": name}, headers={"X-CSRF-Token": csrf(client)}
    )
    assert response.status_code == 422


def test_without_installation_lookup_manual_scans_are_501(client):
    response = client.post(
        "/api/scans",
        json={"repo_full_name": "test-org/repo"},
        headers={"X-CSRF-Token": csrf(client)},
    )
    assert response.status_code == 501


def test_static_logo_is_served():
    assert TestClient(app).get("/static/logo-symbol.png").status_code == 200


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
    assert TestClient(app).get("/openapi.json").status_code == 200
