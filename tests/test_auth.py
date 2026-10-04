"""Authentication, tenancy and CSRF (A14)."""

from urllib.parse import parse_qs, urlparse

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.scans import get_scan_store
from tests.fakes import OTHER_USER, FakeScanStore
from tests.helpers import csrf, sign_in


@pytest.fixture(autouse=True)
def fake_store():
    app.dependency_overrides[get_scan_store] = FakeScanStore
    yield
    app.dependency_overrides.pop(get_scan_store, None)


@pytest.fixture
def anon():
    with TestClient(app) as c:
        yield c


@pytest.fixture
def client():
    with TestClient(app) as c:
        sign_in(c)
        yield c


@pytest.mark.parametrize("path", ["/dashboard", "/dashboard/scans/1", "/dashboard/scans/1/live"])
def test_anonymous_pages_redirect_to_sign_in(anon, path):
    response = anon.get(path, follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == f"/auth/github/login?next={path.replace('/', '%2F')}"


def test_anonymous_api_is_401(anon):
    assert anon.get("/api/scans/1").status_code == 401
    assert anon.post("/api/scans", json={"repo_full_name": "o/r"}).status_code in (401, 403)


def test_login_redirects_to_github_with_state(anon):
    response = anon.get("/auth/github/login", follow_redirects=False)
    assert response.status_code == 303
    url = urlparse(response.headers["location"])
    assert (url.scheme, url.netloc, url.path) == ("https", "github.com", "/login/oauth/authorize")
    query = parse_qs(url.query)
    assert query["client_id"] == ["test-client"]
    assert query["redirect_uri"] == ["http://testserver/auth/github/callback"]
    assert len(query["state"][0]) >= 32


def test_callback_signs_in_and_returns_to_next(anon):
    response = sign_in(anon, next_path="/dashboard/scans/1")
    assert response.status_code == 303
    assert response.headers["location"] == "/dashboard/scans/1"
    assert anon.get("/dashboard/scans/1").status_code == 200


@pytest.mark.parametrize("bad_next", ["https://evil.example", "//evil.example", "/\\evil.example"])
def test_next_cannot_redirect_off_site(anon, bad_next):
    assert sign_in(anon, next_path=bad_next).headers["location"] == "/dashboard"


def test_callback_with_wrong_state_is_rejected(anon):
    anon.get("/auth/github/login", follow_redirects=False)
    response = anon.get("/auth/github/callback", params={"code": "c", "state": "forged"})
    assert response.status_code == 400
    assert anon.get("/api/scans/1").status_code == 401


def test_callback_without_a_login_is_rejected(anon):
    response = anon.get("/auth/github/callback", params={"code": "c", "state": "s"})
    assert response.status_code == 400


def test_session_cookie_flags(anon):
    cookie = sign_in(anon).headers["set-cookie"].lower()
    assert "httponly" in cookie
    assert "samesite=lax" in cookie
    assert "quantsiv_session=" in cookie


def test_another_tenants_scan_is_404(client):
    assert client.get("/dashboard/scans/99").status_code == 404
    assert client.get("/dashboard/scans/99/live").status_code == 404
    assert client.get("/api/scans/99").status_code == 404
    assert "other-org/secret" not in client.get("/dashboard").text


def test_the_other_tenant_sees_their_own_scan():
    with TestClient(app) as other:
        sign_in(other, user=OTHER_USER)
        assert other.get("/api/scans/99").status_code == 200
        assert other.get("/api/scans/1").status_code == 404


def test_post_without_csrf_token_is_403(client):
    assert client.post("/api/scans", json={"repo_full_name": "o/r"}).status_code == 403
    response = client.post(
        "/api/scans", json={"repo_full_name": "o/r"}, headers={"X-CSRF-Token": "wrong"}
    )
    assert response.status_code == 403


def test_logout_needs_csrf_and_ends_the_session(client):
    assert client.post("/auth/logout").status_code == 403
    response = client.post(
        "/auth/logout", data={"csrf_token": csrf(client)}, follow_redirects=False
    )
    assert response.status_code == 303
    assert client.get("/api/scans/1").status_code == 401


def test_pages_carry_the_csrf_token_for_htmx(client):
    html = client.get("/dashboard").text
    token = csrf(client)
    assert f'hx-headers=\'{{"X-CSRF-Token": "{token}"}}\'' in html
