"""GitHub OAuth for user sign-in (A14).

The user's access token is used once, to read who they are, and then dropped: it is never
stored, logged or put in a URL. Errors carry a fixed message, never GitHub's response text.
"""

import logging
from typing import Protocol

import httpx

from app.config import get_settings

logger = logging.getLogger(__name__)

AUTHORIZE_URL = "https://github.com/login/oauth/authorize"
TOKEN_URL = "https://github.com/login/oauth/access_token"
USER_URL = "https://api.github.com/user"


class OAuthError(Exception):
    """Sign-in failed; the message is safe to show."""


class GitHubIdentity(Protocol):
    async def identify(self, code: str, redirect_uri: str) -> dict: ...


class GitHubOAuth:
    def __init__(self, transport: httpx.AsyncBaseTransport | None = None):
        self._transport = transport

    async def identify(self, code: str, redirect_uri: str) -> dict:
        """Exchange the one-time code and return {"id": int, "login": str}."""
        settings = get_settings()
        async with httpx.AsyncClient(transport=self._transport, timeout=10) as client:
            response = await client.post(
                TOKEN_URL,
                headers={"Accept": "application/json"},
                data={
                    "client_id": settings.github_client_id,
                    "client_secret": settings.github_client_secret.get_secret_value(),
                    "code": code,
                    "redirect_uri": redirect_uri,
                },
            )
            token = response.json().get("access_token") if response.is_success else None
            if not token:
                logger.warning("GitHub code exchange failed (HTTP %s)", response.status_code)
                raise OAuthError("GitHub sign-in failed")
            response = await client.get(
                USER_URL,
                headers={
                    "Authorization": f"Bearer {token}",
                    "Accept": "application/vnd.github+json",
                },
            )
            if not response.is_success:
                logger.warning("GitHub user lookup failed (HTTP %s)", response.status_code)
                raise OAuthError("GitHub sign-in failed")
            user = response.json()
            return {"id": int(user["id"]), "login": str(user["login"])}


def get_github_oauth() -> GitHubIdentity:
    return GitHubOAuth()
