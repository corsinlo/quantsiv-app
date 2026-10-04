"""CI-facing API (WP7): CBOM upload and estate export, authenticated by an organisation token.

Only CBOM JSON is accepted, never source. The response includes a deterministic gate verdict on
the CBOM *delta*: it fails when the upload adds quantum-vulnerable cryptography compared with the
previous upload for the same repository (D7: tools decide, people approve).
"""

import re
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.db import get_db
from app.models import (
    ApiToken,
    AuditEvent,
    CbomSnapshot,
    Installation,
    Scan,
    ScanStatus,
    utcnow,
)
from app.request_body import read_body
from app.services import ingest
from app.services.results import finding_rows, score
from app.services.scoring import severity_score
from app.services.tokens import PREFIX, hash_token
from quantsiv_scanner.gate import delta, gate, policy_from_cbom

router = APIRouter(prefix="/api/v1")
MAX_CBOM = 10 * 1024 * 1024
# GitHub owner/name, or GitLab-style group/subgroup/project (uploads can come from any CI)
REPOSITORY = re.compile(r"[A-Za-z0-9._-]{1,100}(/[A-Za-z0-9._-]{1,100}){1,5}")

Db = Annotated[AsyncSession, Depends(get_db)]


async def token_installation(request: Request, db: Db) -> Installation:
    """The installation an `Authorization: Bearer qsv_...` token belongs to; 401 otherwise."""
    scheme, _, token = request.headers.get("authorization", "").partition(" ")
    if scheme.lower() != "bearer" or not token.startswith(PREFIX):
        raise HTTPException(401, "API token required", headers={"WWW-Authenticate": "Bearer"})
    row = await db.scalar(
        select(ApiToken)
        .where(ApiToken.token_hash == hash_token(token), ApiToken.revoked_at.is_(None))
        .options(selectinload(ApiToken.installation))
    )
    if row is None:
        raise HTTPException(401, "invalid or revoked token", headers={"WWW-Authenticate": "Bearer"})
    row.last_used_at = utcnow()
    await db.commit()
    return row.installation


TokenInstallation = Annotated[Installation, Depends(token_installation)]


def _repository(value: str) -> str:
    if len(value) > 140 or not REPOSITORY.fullmatch(value) or ".." in value:
        raise HTTPException(422, "repository must look like owner/name")
    return value


async def _latest(db: AsyncSession, installation: Installation, repo: str) -> Scan | None:
    return await db.scalar(
        select(Scan)
        .where(
            Scan.installation_id == installation.id,
            Scan.repo_full_name == repo,
            Scan.scan_type == "cbom",
        )
        .order_by(Scan.id.desc())
        .options(selectinload(Scan.cbom))
        .limit(1)
    )


@router.post("/cbom", status_code=201)
async def upload_cbom(request: Request, installation: TokenInstallation, db: Db, repository: str):
    repo = _repository(repository)
    try:
        doc = ingest.validate(await read_body(request, MAX_CBOM))
    except ingest.InvalidCbom as exc:
        raise HTTPException(422, str(exc)) from None
    current = ingest.findings_from_cbom(doc)
    previous_scan = await _latest(db, installation, repo)
    baseline = previous_scan.cbom.cbom_json if previous_scan else None
    today = utcnow().date()
    policy = policy_from_cbom(doc)
    # The same function the MCP server's check_change and `quantsiv gate` call (WP10)
    verdict = gate(doc, baseline, repo, today, policy)
    added, removed = delta(doc, baseline)

    scored = score(current, repo, policy.lifetimes, today)
    scan = Scan(
        installation_id=installation.id,
        repo_full_name=repo,
        scan_type="cbom",
        triggered_by="action",
        status=ScanStatus.DONE,
        completed_at=utcnow(),
        findings=finding_rows(scored, installation),
        cbom=CbomSnapshot(
            cbom_json=doc,
            risk_score=severity_score([v.severity for v, _ in scored]),
            producer=ingest.producer(doc),
        ),
    )
    db.add(scan)
    await db.flush()
    db.add(
        AuditEvent(
            installation_id=installation.id,
            scan_id=scan.id,
            kind="gate",
            data={
                "repository": repo,
                "baseline_scan_id": previous_scan.id if previous_scan else None,
                **verdict.as_dict(),
            },
        )
    )
    await db.commit()

    def names(findings):
        return sorted({f["algorithm"] for f in findings})

    return {
        "scan_id": scan.id,
        "repository": repo,
        "producer": scan.cbom.producer,
        "assets": len(current),
        "baseline_scan_id": previous_scan.id if previous_scan else None,
        "added": names(added),
        "removed": names(removed),
        "new_quantum_vulnerable": sorted({e.algorithm for e in verdict.blocking}),
        "gate": "fail" if not verdict.passed else "pass",
        "verdict": verdict.as_dict(),
    }


@router.get("/audit")
async def export_audit(installation: TokenInstallation, db: Db, limit: int = 500):
    """The installation's audit events (gate verdicts), newest first: evidence-pack input."""
    events = await db.scalars(
        select(AuditEvent)
        .where(AuditEvent.installation_id == installation.id)
        .order_by(AuditEvent.id.desc())
        .limit(max(1, min(limit, 5000)))
    )
    return {
        "installation": installation.account_name,
        "events": [
            {
                "id": e.id,
                "at": e.created_at.isoformat(),
                "kind": e.kind,
                "scan_id": e.scan_id,
                "data": e.data,
            }
            for e in events
        ],
    }


@router.get("/cbom")
async def export_estate(installation: TokenInstallation, db: Db):
    """The latest uploaded CBOM of every repository, as one plain CycloneDX 1.6 document."""
    scans = await db.scalars(
        select(Scan)
        .where(Scan.installation_id == installation.id, Scan.scan_type == "cbom")
        .order_by(Scan.repo_full_name, Scan.id.desc())
        .options(selectinload(Scan.cbom))
    )
    latest: dict[str, dict] = {}
    for scan in scans:
        if scan.repo_full_name not in latest and scan.cbom:
            latest[scan.repo_full_name] = scan.cbom.cbom_json
    return JSONResponse(
        ingest.estate_cbom(installation.account_name, sorted(latest.items())),
        media_type="application/vnd.cyclonedx+json",
    )
