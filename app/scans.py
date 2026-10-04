"""Where the routes read scans from, always scoped to the signed-in user (A14).

There is no database until WP4, so the default store is empty and the pages show their empty
states instead of invented data (A29). WP4 replaces `get_scan_store` with a database-backed
store whose queries join through the user's installations (audit section 7, "Authorisation").
A scan that exists but belongs to someone else must look exactly like a missing one: `None`.
Tests override these dependencies with `app.dependency_overrides`.
"""

from typing import Protocol

from fastapi import HTTPException


class ScanStore(Protocol):
    async def list_recent(self, user_id: int, limit: int = 20) -> list[dict]: ...

    async def get(self, scan_id: int, user_id: int) -> dict | None: ...


class EmptyScanStore:
    async def list_recent(self, user_id: int, limit: int = 20) -> list[dict]:
        return []

    async def get(self, scan_id: int, user_id: int) -> dict | None:
        return None


def get_scan_store() -> ScanStore:
    return EmptyScanStore()


class RepoAccess(Protocol):
    async def can_scan(self, user_id: int, repo_full_name: str) -> bool:
        """True only if the repo is in one of the user's installations' repository lists."""
        ...


class UnavailableRepoAccess:
    async def can_scan(self, user_id: int, repo_full_name: str) -> bool:
        # Needs installation tokens from the GitHub App integration (WP5)
        raise HTTPException(501, "Manual scans are not available yet")


def get_repo_access() -> RepoAccess:
    return UnavailableRepoAccess()
