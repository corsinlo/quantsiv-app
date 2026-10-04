"""Test-only scan data. Never served by the app: tests install it via dependency_overrides."""

from app.models import ScanStatus

FINDINGS = [
    {
        "severity": "high",
        "algorithm": "ECDH",
        "primitive": "key-agree",
        "file_path": "net/handshake.py",
        "line_number": 12,
        "context_label": "Key exchange",
        "confidence": 0.9,
    },
    {
        "severity": "medium",
        "algorithm": "RSA",
        "primitive": "signature",
        "key_size": 2048,
        "file_path": "auth/jwt.py",
        "line_number": 47,
        "context_label": "Token signing",
        "confidence": None,
    },
    {"severity": "low", "algorithm": "DSA", "file_path": "legacy/sign.py"},
]


def scan(scan_id: int, status: ScanStatus, findings: list[dict] | None = None) -> dict:
    return {
        "id": scan_id,
        "repo_full_name": f"test-org/repo-{scan_id}",
        "status": status,
        "risk_score": 40 if status == ScanStatus.DONE else None,
        "findings": FINDINGS if findings is None else findings,
        "completed_at": "2026-10-04T06:20:00+00:00" if status == ScanStatus.DONE else None,
        "error_message": "Could not clone the repository" if status == ScanStatus.FAILED else None,
    }


SCANS = {
    1: scan(1, ScanStatus.DONE),
    2: scan(2, ScanStatus.DONE, findings=[]),
    3: scan(3, ScanStatus.FAILED),
    4: scan(4, ScanStatus.QUEUED),
    5: scan(5, ScanStatus.RUNNING),
}


# Test users. SCANS all belong to USER; OTHER_TENANT_SCAN belongs to OTHER_USER.
USER = {"id": 1001, "login": "test-user"}
OTHER_USER = {"id": 2002, "login": "other-user"}
OTHER_TENANT_SCAN = {**scan(99, ScanStatus.DONE), "repo_full_name": "other-org/secret"}
OWNERS = {**{scan_id: USER["id"] for scan_id in SCANS}, 99: OTHER_USER["id"]}
ALL_SCANS = {**SCANS, 99: OTHER_TENANT_SCAN}


class FakeScanStore:
    """Scopes like the WP4 store will: a scan is visible only to its owner."""

    async def list_recent(self, user_id: int, limit: int = 20) -> list[dict]:
        return [s for i, s in ALL_SCANS.items() if OWNERS[i] == user_id][:limit]

    async def get(self, scan_id: int, user_id: int) -> dict | None:
        return ALL_SCANS.get(scan_id) if OWNERS.get(scan_id) == user_id else None


class FakeRepoAccess:
    def __init__(self, allowed: set[str]):
        self.allowed = allowed

    async def can_scan(self, user_id: int, repo_full_name: str) -> bool:
        return repo_full_name in self.allowed


class FakeOAuth:
    """Stands in for GitHub: any code signs in as `user`."""

    def __init__(self, user: dict = USER):
        self.user = user
        self.calls: list[tuple[str, str]] = []

    async def identify(self, code: str, redirect_uri: str) -> dict:
        self.calls.append((code, redirect_uri))
        return self.user
