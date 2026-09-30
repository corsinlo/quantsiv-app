"""
API endpoints for Quantsiv MVP
Handles GitHub App webhooks, dashboard, and scanning endpoints
"""
from fastapi import APIRouter, Request, HTTPException, Depends
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
import uuid
import hmac
import hashlib
from typing import Optional

from app.models import User, Installation, Scan
from app.worker import ScanWorker

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")
worker = ScanWorker()

# In a real implementation, these would come from environment variables
GITHUB_APP_ID = "placeholder_app_id"
GITHUB_APP_PRIVATE_KEY = "placeholder_private_key"
GITHUB_WEBHOOK_SECRET = "placeholder_webhook_secret"
STRIPE_SECRET_KEY = "placeholder_stripe_key"

@router.get("/")
async def root():
    return {"message": "Quantsiv MVP API"}

@router.get("/health")
async def health_check():
    return {"status": "healthy"}

# GitHub App Webhook Endpoints
@router.get("/auth/github/login")
async def github_login():
    """Redirect to GitHub OAuth login"
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
    expected_signature = "sha256=" + hmac.new(
        GITHUB_WEBHOOK_SECRET.encode(),
        body,
        hashlib.sha256
    ).hexdigest()

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
@router.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request):
    """Main dashboard page"""
    return templates.TemplateResponse("dashboard.html", {"request": request, "title": "Quantsiv Dashboard"})

@router.get("/dashboard/scans/{scan_id}", response_class=HTMLResponse)
async def scan_details(request: Request, scan_id: int):
    """Scan results page"""
    # In real implementation: fetch scan data from DB
    scan_data = {
        "id": scan_id,
        "repo_full_name": "example/repo",
        "status": "done",
        "risk_score": 73,
        "findings": [
            {
                "severity": "critical",
                "algorithm": "RSA",
                "file_path": "auth/jwt.py",
                "line_number": 47,
                "context_label": "Token signing",
                "key_size": 2048
            }
        ]
    }
    return templates.TemplateResponse("scan_details.html", {
        "request": request,
        "scan": scan_data,
        "title": f"Scan Results - {scan_data['repo_full_name']}"
    })

@router.get("/dashboard/scans/{scan_id}/live", response_class=HTMLResponse)
async def scan_live(request: Request, scan_id: int):
    """Live scan progress page with SSE"""
    return templates.TemplateResponse("scan_live.html", {
        "request": request,
        "scan_id": scan_id,
        "title": f"Scanning - {scan_id}"
    })

# API Endpoints for Frontend
@router.get("/api/scans/{scan_id}")
async def get_scan(scan_id: int):
    """Get scan details as JSON"""
    # In real implementation: fetch from DB
    return {
        "id": scan_id,
        "repo_full_name": "example/repo",
        "status": "done",
        "risk_score": 73,
        "findings": [],
        "created_at": "2026-09-30T10:00:00Z",
        "completed_at": "2026-09-30T10:01:30Z"
    }

@router.post("/api/scans")
async def trigger_manual_scan(repo_full_name: str):
    """Trigger a manual scan (for testing)"""
    # In real implementation: validate auth, enqueue job
    return {
        "message": "Scan queued",
        "repo_full_name": repo_full_name,
        "scan_id": 1  # Placeholder
    }

# Health check for workers
@router.get("/worker/health")
async def worker_health():
    """Worker health check"""
    return {"status": "healthy", "worker": "ScanWorker"}
