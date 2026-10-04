"""Where the routes read scans from, always scoped to the signed-in user (A14).

`user_id` is the signed-in user's GitHub user id (the session's `SessionUser.id`). Every query
joins scans through installations to that user (audit section 7, "Authorisation"): a scan that
exists but belongs to someone else looks exactly like a missing one, `None`.
Tests override these dependencies with `app.dependency_overrides`.
"""

from typing import Annotated, Protocol

from fastapi import Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.db import get_db
from app.models import Finding, Installation, Scan, User

FINDING_FIELDS = (
    "id",
    "file_path",
    "line_number",
    "algorithm",
    "algorithm_family",
    "primitive",
    "key_size",
    "quantum_safe",
    "severity",
    "confidence",
    "context_label",
    "raw_match",
)


class ScanStore(Protocol):
    async def list_recent(self, user_id: int, limit: int = 20) -> list[dict]: ...

    async def get(self, scan_id: int, user_id: int) -> dict | None: ...


def finding_to_dict(finding: Finding) -> dict:
    return {field: getattr(finding, field) for field in FINDING_FIELDS}


def scan_to_dict(scan: Scan) -> dict:
    return {
        "id": scan.id,
        "repo_full_name": scan.repo_full_name,
        "scan_type": scan.scan_type,
        "status": scan.status,
        "triggered_by": scan.triggered_by,
        "risk_score": scan.cbom.risk_score if scan.cbom else None,
        "error_message": scan.error_message,
        "created_at": scan.created_at,
        "completed_at": scan.completed_at,
        "findings": [finding_to_dict(f) for f in scan.findings],
    }


class DbScanStore:
    def __init__(self, db: AsyncSession):
        self.db = db

    def _scoped(self, user_id: int):
        return (
            select(Scan)
            .join(Installation, Scan.installation_id == Installation.id)
            .join(User, Installation.user_id == User.id)
            .where(User.github_user_id == user_id)
            .options(selectinload(Scan.findings), selectinload(Scan.cbom))
        )

    async def list_recent(self, user_id: int, limit: int = 20) -> list[dict]:
        query = self._scoped(user_id).order_by(Scan.created_at.desc(), Scan.id.desc())
        return [scan_to_dict(s) for s in await self.db.scalars(query.limit(limit))]

    async def get(self, scan_id: int, user_id: int) -> dict | None:
        scan = await self.db.scalar(self._scoped(user_id).where(Scan.id == scan_id))
        return scan_to_dict(scan) if scan else None


def get_scan_store(db: Annotated[AsyncSession, Depends(get_db)]) -> ScanStore:
    return DbScanStore(db)


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
