"""GitHub App client (A52): down-scoped tokens, always revoked, fixed error messages."""

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from app.services import github as github_module
from app.services.errors import ScanError
from tests.github_mock import TOKEN, FakeGitHub


async def test_token_is_down_scoped_and_revoked():
    fake = FakeGitHub()
    async with fake.app().installation_token(7, "octo/hello") as token:
        assert token == TOKEN
    create, revoke = fake.requests
    assert create.url.path == "/app/installations/7/access_tokens"
    assert create.headers["authorization"] == "Bearer app-jwt"
    import json

    assert json.loads(create.content) == {
        "repositories": ["hello"],
        "permissions": {"contents": "read", "metadata": "read"},
    }
    assert (revoke.method, revoke.url.path) == ("DELETE", "/installation/token")
    assert revoke.headers["authorization"] == f"Bearer {TOKEN}"
    assert all(TOKEN not in str(r.url) for r in fake.requests)  # never in a URL


async def test_token_is_revoked_even_when_the_block_fails():
    fake = FakeGitHub()
    with pytest.raises(RuntimeError):
        async with fake.app().installation_token(7, "octo/hello"):
            raise RuntimeError("clone exploded")
    assert fake.calls()[-1] == ("DELETE", "/installation/token")


async def test_refused_token_is_a_fixed_scan_error():
    with pytest.raises(ScanError, match="Repository access was refused"):
        async with FakeGitHub(token_status=403).app().installation_token(7, "octo/hello"):
            pass


async def test_installation_for_repo():
    assert await FakeGitHub(installation=42).app().installation_for_repo("octo/hello") == 42
    assert await FakeGitHub(installation=None).app().installation_for_repo("octo/hello") is None


def test_app_jwt_is_rs256_with_the_app_id(monkeypatch):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()

    class Settings:
        github_app_id = "12345"

        class github_app_private_key:
            @staticmethod
            def get_secret_value():
                return pem

    monkeypatch.setattr(github_module, "get_settings", lambda: Settings)
    token = github_module.GitHubApp().app_jwt()
    claims = jwt.decode(token, key.public_key(), algorithms=["RS256"])
    assert claims["iss"] == "12345"
    assert claims["exp"] - claims["iat"] <= 600


def test_app_jwt_accepts_a_pem_stored_with_literal_backslash_n(monkeypatch):
    """Hosts that keep a secret on one line store the key as `-----BEGIN...\\n...`."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()

    class Settings:
        github_app_id = "12345"

        class github_app_private_key:
            @staticmethod
            def get_secret_value():
                return pem.strip().replace("\n", "\\n")

    assert "\n" not in Settings.github_app_private_key.get_secret_value()
    monkeypatch.setattr(github_module, "get_settings", lambda: Settings)
    token = github_module.GitHubApp().app_jwt()
    assert jwt.decode(token, key.public_key(), algorithms=["RS256"])["iss"] == "12345"
