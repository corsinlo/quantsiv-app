"""Where the routes read scans from.

There is no database until WP4, so the default store is empty and the pages show their empty
states instead of invented data (A29). WP4 replaces `get_scan_store` with a database-backed store
(scoped to the signed-in user per A14); tests override it with `app.dependency_overrides`.
"""

from typing import Protocol


class ScanStore(Protocol):
    async def list_recent(self, limit: int = 20) -> list[dict]: ...

    async def get(self, scan_id: int) -> dict | None: ...


class EmptyScanStore:
    async def list_recent(self, limit: int = 20) -> list[dict]:
        return []

    async def get(self, scan_id: int) -> dict | None:
        return None


def get_scan_store() -> ScanStore:
    return EmptyScanStore()
