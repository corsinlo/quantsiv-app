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


class FakeScanStore:
    async def list_recent(self, limit: int = 20) -> list[dict]:
        return list(SCANS.values())[:limit]

    async def get(self, scan_id: int) -> dict | None:
        return SCANS.get(scan_id)
