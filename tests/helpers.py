from urllib.parse import parse_qs, urlparse

from fastapi.testclient import TestClient

from app.main import app
from app.services.github_oauth import get_github_oauth
from tests.fakes import USER, FakeOAuth


def sign_in(client: TestClient, user: dict = USER, next_path: str | None = None):
    """Run the real OAuth routes against a fake GitHub; returns the callback response."""
    app.dependency_overrides[get_github_oauth] = lambda: FakeOAuth(user)
    try:
        params = {"next": next_path} if next_path else None
        login = client.get("/auth/github/login", params=params, follow_redirects=False)
        state = parse_qs(urlparse(login.headers["location"]).query)["state"][0]
        return client.get(
            "/auth/github/callback",
            params={"code": "one-time-code", "state": state},
            follow_redirects=False,
        )
    finally:
        app.dependency_overrides.pop(get_github_oauth, None)


def csrf(client: TestClient) -> str:
    """The CSRF token the signed-in pages embed."""
    html = client.get("/dashboard").text
    return html.split('name="csrf-token" content="', 1)[1].split('"', 1)[0]
