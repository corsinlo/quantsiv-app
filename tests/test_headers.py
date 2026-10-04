"""Security headers (A20)."""

import pytest
from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


@pytest.mark.parametrize("path", ["/health", "/auth/github/login", "/static/app.css"])
def test_security_headers(path):
    headers = client.get(path, follow_redirects=False).headers
    csp = headers["content-security-policy"]
    for directive in (
        "default-src 'self'",
        "script-src 'self'",
        "style-src 'self'",
        "object-src 'none'",
        "frame-ancestors 'none'",
        "base-uri 'none'",
    ):
        assert directive in csp
    assert "unsafe-inline" not in csp
    assert headers["strict-transport-security"].startswith("max-age=31536000")
    assert headers["x-content-type-options"] == "nosniff"
    assert headers["referrer-policy"] == "no-referrer"
    assert "camera=()" in headers["permissions-policy"]


def test_no_third_party_assets_or_inline_handlers():
    from pathlib import Path

    for path in Path("app").rglob("*"):
        if path.suffix in {".html", ".py", ".js"} and path.name != "htmx.min.js":
            text = path.read_text(encoding="utf-8")
            for banned in ("cdn.tailwindcss", "unpkg.com", "onclick=", "<script>", 'style="'):
                assert banned not in text, f"{path}: {banned}"
