"""The OAuth client: the user token is used once and never leaks into errors or logs (A14)."""

import logging

import httpx
import pytest

from app.services.github_oauth import TOKEN_URL, USER_URL, GitHubOAuth, OAuthError

TOKEN = "gho_SECRET_TOKEN_VALUE"


def transport(token_status=200, token_body=None, user_status=200):
    def handler(request: httpx.Request) -> httpx.Response:
        if str(request.url) == TOKEN_URL:
            assert b"client_secret=test-client-secret" in request.content
            return httpx.Response(token_status, json=token_body or {"access_token": TOKEN})
        if str(request.url) == USER_URL:
            assert request.headers["authorization"] == f"Bearer {TOKEN}"
            return httpx.Response(user_status, json={"id": 42, "login": "octo", "email": "x@y"})
        raise AssertionError(request.url)

    return httpx.MockTransport(handler)


async def test_identify_returns_only_id_and_login():
    user = await GitHubOAuth(transport()).identify("code", "http://testserver/cb")
    assert user == {"id": 42, "login": "octo"}


@pytest.mark.parametrize(
    "kwargs",
    [
        {"token_status": 401},
        {"token_body": {"error": "bad_verification_code"}},
        {"user_status": 500},
    ],
)
async def test_failures_raise_a_fixed_message_without_the_token(kwargs, caplog):
    caplog.set_level(logging.DEBUG)
    with pytest.raises(OAuthError) as exc:
        await GitHubOAuth(transport(**kwargs)).identify("code", "http://testserver/cb")
    assert str(exc.value) == "GitHub sign-in failed"
    assert TOKEN not in caplog.text
