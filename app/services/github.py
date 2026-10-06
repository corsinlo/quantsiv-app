"""GitHub App API calls for scanning (A52).

Installation tokens are down-scoped to one repository with read-only contents and metadata, and
revoked as soon as the clone is done (`installation_token` is an async context manager). Tokens
only ever travel in Authorization headers; errors carry fixed messages, never response text.
"""

import logging
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import httpx
import jwt

from app.config import get_settings
from app.services.errors import ScanError

logger = logging.getLogger(__name__)
API = "https://api.github.com"
HEADERS = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}


class GitHubApp:
    def __init__(self, transport: httpx.AsyncBaseTransport | None = None):
        self._transport = transport

    def _client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            base_url=API, headers=HEADERS, transport=self._transport, timeout=15
        )

    def app_jwt(self) -> str:
        """RS256 JWT for the GitHub App itself (10-minute maximum; 9 here, with clock skew)."""
        settings = get_settings()
        now = int(time.time())
        payload = {"iat": now - 60, "exp": now + 540, "iss": settings.github_app_id}
        # Hosts that keep a secret on one line store the PEM with literal \n sequences
        key = settings.github_app_private_key.get_secret_value().replace("\\n", "\n")
        return jwt.encode(payload, key, "RS256")

    async def installation_for_repo(self, repo_full_name: str) -> int | None:
        """The id of this app's installation on the repo, or None if the app can't access it."""
        async with self._client() as client:
            response = await client.get(
                f"/repos/{repo_full_name}/installation",
                headers={"Authorization": f"Bearer {self.app_jwt()}"},
            )
        if response.status_code == 404:
            return None
        if not response.is_success:
            logger.warning("installation lookup failed (HTTP %s)", response.status_code)
            raise ScanError("Could not check repository access")
        return int(response.json()["id"])

    @asynccontextmanager
    async def installation_token(
        self, installation_id: int, repo_full_name: str
    ) -> AsyncIterator[str]:
        """A token for one repository, read-only, revoked when the block exits (A52)."""
        repo_name = repo_full_name.split("/", 1)[1]
        async with self._client() as client:
            response = await client.post(
                f"/app/installations/{installation_id}/access_tokens",
                headers={"Authorization": f"Bearer {self.app_jwt()}"},
                json={
                    "repositories": [repo_name],
                    "permissions": {"contents": "read", "metadata": "read"},
                },
            )
            if not response.is_success:
                logger.warning("installation token request failed (HTTP %s)", response.status_code)
                raise ScanError("Repository access was refused")
            token = response.json()["token"]
            try:
                yield token
            finally:
                revoke = await client.delete(
                    "/installation/token", headers={"Authorization": f"Bearer {token}"}
                )
                if revoke.status_code != 204:
                    logger.warning("token revocation returned HTTP %s", revoke.status_code)

    async def repository(self, token: str, repo_full_name: str) -> dict:
        """Repository metadata: `private` and `size` (KB) are used before cloning."""
        async with self._client() as client:
            response = await client.get(
                f"/repos/{repo_full_name}", headers={"Authorization": f"Bearer {token}"}
            )
        if not response.is_success:
            logger.warning("repository lookup failed (HTTP %s)", response.status_code)
            raise ScanError("Could not read the repository")
        return response.json()


def get_github_app() -> GitHubApp:
    return GitHubApp()
