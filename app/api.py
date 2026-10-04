"""
API endpoints for Quantsiv MVP
Handles GitHub App webhooks, dashboard, and scanning endpoints
"""

import hashlib
import hmac
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse

from app.config import get_settings
from app.models import Installation, ScanStatus
from app.scans import ScanStore, get_scan_store
from app.templating import templates
from app.worker import ScanWorker

router = APIRouter()
Store = Annotated[ScanStore, Depends(get_scan_store)]
worker = ScanWorker()


@router.get("/")
async def root():
    return {"message": "Quantsiv MVP API"}


@router.get("/health")
async def health_check():
    return {"status": "healthy"}


# GitHub App Webhook Endpoints
@router.get("/auth/github/login")
async def github_login():
    """Redirect to GitHub OAuth login"""
    # In real implementation: generate redirect URL to GitHub OAuth
    return {"url": "https://github.com/login/oauth/authorize?client_id=..."}


@router.post("/webhook/github")
async def github_webhook(request: Request):
    """Handle GitHub App webhooks"""
    # Verify webhook signature
    signature = request.headers.get("X-Hub-Signature-256")
    if not signature:
        raise HTTPException(status_code=400, detail="Missing signature")

    body = await request.body()
    expected_signature = (
        "sha256="
        + hmac.new(
            get_settings().github_webhook_secret.get_secret_value().encode(), body, hashlib.sha256
        ).hexdigest()
    )

    if not hmac.compare_digest(signature, expected_signature):
        raise HTTPException(status_code=403, detail="Invalid signature")

    # Parse payload
    payload = await request.json()
    event_type = request.headers.get("X-GitHub-Event")

    # Handle different event types
    if event_type == "installation":
        await handle_installation(payload)
    elif event_type == "installation_repositories":
        await handle_installation_repositories(payload)
    elif event_type == "push":
        await handle_push_event(payload)
    # Add more event handlers as needed

    return {"status": "processed"}


async def handle_installation(payload: dict):
    """Handle GitHub App installation"""
    action = payload.get("action")
    if action == "created":
        installation_data = payload.get("installation")
        account_data = payload.get("account")

        # Create or update installation record
        installation = Installation()
        installation.github_installation_id = installation_data.get("id")
        installation.account_name = account_data.get("login")
        installation.account_type = account_data.get("type")
        # In real implementation: save to DB and create user if needed

        print(f"GitHub App installed: {installation.account_name}")

        # Trigger initial scan of connected repos (up to plan limit)
        # await trigger_initial_scans(installation.id)


async def handle_installation_repositories(payload: dict):
    """Handle repository access changes for installation"""
    action = payload.get("action")
    repositories_added = payload.get("repositories_added", [])
    repositories_removed = payload.get("repositories_removed", [])

    print(f"Repositories action: {action}")
    print(f"  Added: {[r['full_name'] for r in repositories_added]}")
    print(f"  Removed: {[r['full_name'] for r in repositories_removed]}")

    # Trigger scans for newly added repositories
    # for repo in repositories_added:
    #     await worker.scan_repository(...)


async def handle_push_event(payload: dict):
    """Handle push events to trigger scans"""
    ref = payload.get("ref")
    repository = payload.get("repository")
    installation = payload.get("installation")

    # Only scan pushes to default branch (usually main/master)
    if ref and repository and installation:
        ref_parts = ref.split("/")
        if len(ref_parts) >= 3 and ref_parts[2] in ["main", "master"]:
            repo_full_name = repository.get("full_name")
            installation_id = installation.get("id")

            if repo_full_name and installation_id:
                print(f"Push to {repo_full_name}/{ref_parts[2]} - triggering scan")
                # Enqueue scan job
                # await worker.scan_repository(str(uuid.uuid4()), installation_id, repo_full_name, "push")


# Dashboard Routes
def _findings_count(scan: dict) -> int:
    return len(scan.get("findings") or [])


async def _scan_or_404(scan_id: int, store: ScanStore) -> dict:
    scan = await store.get(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@router.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request, store: Store):
    """Main dashboard page: recent scans from the store, or an empty state (A29)"""
    scans = await store.list_recent()
    done = [s for s in scans if s.get("status") == ScanStatus.DONE]
    scores = [s["risk_score"] for s in done if s.get("risk_score") is not None]
    stats = {
        "repos_scanned": len({s["repo_full_name"] for s in done}),
        "findings": sum(_findings_count(s) for s in done),
        "avg_risk_score": round(sum(scores) / len(scores)) if scores else None,
    }
    return templates.TemplateResponse(
        request, "dashboard.html", {"title": "Dashboard", "scans": scans, "stats": stats}
    )


@router.get("/dashboard/scans/{scan_id}", response_class=HTMLResponse)
async def scan_details(request: Request, scan_id: int, store: Store):
    """Scan results page"""
    scan = await _scan_or_404(scan_id, store)
    return templates.TemplateResponse(
        request,
        "scan_details.html",
        {"scan": scan, "title": f"Scan results - {scan['repo_full_name']}"},
    )


@router.get("/dashboard/scans/{scan_id}/live", response_class=HTMLResponse)
async def scan_live(request: Request, scan_id: int, store: Store):
    """Live scan progress page"""
    scan = await _scan_or_404(scan_id, store)
    return templates.TemplateResponse(
        request,
        "scan_live.html",
        {"scan_id": scan_id, "repo_name": scan["repo_full_name"], "title": f"Scanning {scan_id}"},
    )


# API Endpoints for Frontend
@router.get("/api/scans/{scan_id}")
async def get_scan(scan_id: int, store: Store):
    """Get scan details as JSON"""
    return await _scan_or_404(scan_id, store)


@router.post("/api/scans", status_code=501)
async def trigger_manual_scan():
    """Manual scans need the queue and the data layer (WP4); until then say so (A29)"""
    raise HTTPException(status_code=501, detail="Manual scans are not available yet")


@router.get("/worker/health")
async def worker_health():
    """Worker health isn't reported to the web service yet; don't claim it (A29)"""
    raise HTTPException(status_code=501, detail="Worker health is not reported yet")
