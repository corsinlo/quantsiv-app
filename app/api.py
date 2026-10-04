"""
Dashboard pages and JSON API for Quantsiv. The GitHub webhook lives in app/routers/webhooks.py.
"""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

from app.auth import PageUser, SessionUser, User, verify_csrf
from app.models import ScanStatus
from app.scans import RepoAccess, ScanStore, get_repo_access, get_scan_store
from app.templating import templates

router = APIRouter()
Store = Annotated[ScanStore, Depends(get_scan_store)]
Access = Annotated[RepoAccess, Depends(get_repo_access)]


@router.get("/")
async def root():
    return {"message": "Quantsiv MVP API"}


@router.get("/health")
async def health_check():
    return {"status": "healthy"}


# Dashboard Routes
def _findings_count(scan: dict) -> int:
    return len(scan.get("findings") or [])


async def _scan_or_404(scan_id: int, user: SessionUser, store: ScanStore) -> dict:
    scan = await store.get(scan_id, user.id)
    if scan is None:  # missing and "not yours" look the same (A14)
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@router.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request, user: PageUser, store: Store):
    """Main dashboard page: the user's recent scans, or an empty state (A29)"""
    scans = await store.list_recent(user.id)
    done = [s for s in scans if s.get("status") == ScanStatus.DONE]
    scores = [s["risk_score"] for s in done if s.get("risk_score") is not None]
    stats = {
        "repos_scanned": len({s["repo_full_name"] for s in done}),
        "findings": sum(_findings_count(s) for s in done),
        "avg_risk_score": round(sum(scores) / len(scores)) if scores else None,
    }
    return templates.TemplateResponse(
        request,
        "dashboard.html",
        {"title": "Dashboard", "user": user, "scans": scans, "stats": stats},
    )


@router.get("/dashboard/scans/{scan_id}", response_class=HTMLResponse)
async def scan_details(request: Request, scan_id: int, user: PageUser, store: Store):
    """Scan results page"""
    scan = await _scan_or_404(scan_id, user, store)
    return templates.TemplateResponse(
        request,
        "scan_details.html",
        {"scan": scan, "user": user, "title": f"Scan results - {scan['repo_full_name']}"},
    )


@router.get("/dashboard/scans/{scan_id}/live", response_class=HTMLResponse)
async def scan_live(request: Request, scan_id: int, user: PageUser, store: Store):
    """Live scan progress page"""
    scan = await _scan_or_404(scan_id, user, store)
    return templates.TemplateResponse(
        request,
        "scan_live.html",
        {
            "scan_id": scan_id,
            "repo_name": scan["repo_full_name"],
            "user": user,
            "title": f"Scanning {scan_id}",
        },
    )


# API Endpoints for Frontend
@router.get("/api/scans/{scan_id}")
async def get_scan(scan_id: int, user: User, store: Store):
    """Get scan details as JSON"""
    return await _scan_or_404(scan_id, user, store)


class ScanRequest(BaseModel):
    # GitHub's owner/name rules; defence in depth next to the installation check (A14)
    repo_full_name: str = Field(pattern=r"^[A-Za-z0-9-]{1,39}/[A-Za-z0-9._-]{1,100}$")


@router.post("/api/scans", dependencies=[Depends(verify_csrf)])
async def trigger_manual_scan(body: ScanRequest, user: User, access: Access):
    """Manual scan: only repos in the user's installations (A14). Queueing arrives with WP4."""
    if not await access.can_scan(user.id, body.repo_full_name):
        raise HTTPException(status_code=404, detail="Repository not found")
    raise HTTPException(status_code=501, detail="Manual scans are not available yet")


@router.get("/worker/health")
async def worker_health():
    """Worker health isn't reported to the web service yet; don't claim it (A29)"""
    raise HTTPException(status_code=501, detail="Worker health is not reported yet")
