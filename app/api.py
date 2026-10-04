"""
Dashboard pages and JSON API for Quantsiv. The GitHub webhook lives in app/routers/webhooks.py.
"""

import re
from typing import Annotated

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from pydantic import BaseModel, Field

from app.auth import PageUser, SessionUser, User, verify_csrf
from app.models import ScanStatus
from app.queue import JobQueue, get_queue
from app.scans import RepoAccess, ScanStore, get_repo_access, get_scan_store
from app.templating import templates

router = APIRouter()
Store = Annotated[ScanStore, Depends(get_scan_store)]
Access = Annotated[RepoAccess, Depends(get_repo_access)]
Queue = Annotated[JobQueue, Depends(get_queue)]


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
        {
            "title": "Dashboard",
            "user": user,
            "scans": scans,
            "stats": stats,
            "flash": request.session.pop("flash", None),
        },
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


REPO_PATTERN = re.compile(r"[A-Za-z0-9-]{1,39}/[A-Za-z0-9._-]{1,100}")


class ScanRequest(BaseModel):
    # GitHub's owner/name rules; defence in depth next to the installation check (A14)
    repo_full_name: str = Field(pattern=rf"^{REPO_PATTERN.pattern}$")


@router.post("/api/scans", status_code=202, dependencies=[Depends(verify_csrf)])
async def trigger_manual_scan(body: ScanRequest, user: User, access: Access, queue: Queue):
    """Queue a scan of a repo in one of the user's installations (A14). The worker creates the
    scan record; hosted scanning covers public repositories only (D1)."""
    installation_id = await access.installation_for(user.id, body.repo_full_name)
    if installation_id is None:
        raise HTTPException(status_code=404, detail="Repository not found")
    await queue.enqueue_job(
        "scan_repository", installation_id, body.repo_full_name, triggered_by="manual"
    )
    return {"status": "queued"}


@router.post("/dashboard/scans", dependencies=[Depends(verify_csrf)])
async def dashboard_scan(
    request: Request,
    user: PageUser,
    access: Access,
    queue: Queue,
    repo_full_name: Annotated[str, Form()] = "",
):
    """The dashboard's scan form: a plain HTML POST that reports back via a flash message."""
    repo_full_name = repo_full_name.strip()
    if not REPO_PATTERN.fullmatch(repo_full_name):
        flash = ("error", "Enter a repository as owner/name, for example octo-org/hello-world.")
    elif (installation_id := await access.installation_for(user.id, repo_full_name)) is None:
        flash = ("error", f"{repo_full_name} is not in a GitHub installation you own.")
    else:
        await queue.enqueue_job(
            "scan_repository", installation_id, repo_full_name, triggered_by="manual"
        )
        flash = ("info", f"Scan of {repo_full_name} queued. It appears below once it starts.")
    request.session["flash"] = flash
    return RedirectResponse("/dashboard", status_code=303)


@router.get("/worker/health")
async def worker_health():
    """Worker health isn't reported to the web service yet; don't claim it (A29)"""
    raise HTTPException(status_code=501, detail="Worker health is not reported yet")
