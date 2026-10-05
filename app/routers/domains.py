"""Domains for hosted TLS scans (A17): add, verify by DNS TXT record, scan, remove.

A domain is contacted only after the customer has published the TXT record and verification
succeeded, and the worker re-checks it before every scan (`worker.scan_tls`).
"""

import asyncio
from typing import Annotated

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.auth import PageUser, SessionUser, verify_csrf
from app.db import get_db
from app.models import Domain, Installation, User, utcnow
from app.queue import JobQueue, get_queue
from app.services.domains import (
    check_verification,
    expected_record,
    new_verification_token,
    normalise_domain,
    txt_record_name,
)
from app.templating import templates

router = APIRouter(prefix="/dashboard/domains")
Db = Annotated[AsyncSession, Depends(get_db)]
Queue = Annotated[JobQueue, Depends(get_queue)]


async def _installations(db: AsyncSession, user: SessionUser) -> list[Installation]:
    return list(
        await db.scalars(
            select(Installation)
            .join(User, Installation.user_id == User.id)
            .where(User.github_user_id == user.id)
            .order_by(Installation.account_name)
        )
    )


async def _owned_domain(db: AsyncSession, user: SessionUser, domain_id: int) -> Domain:
    owned = [i.id for i in await _installations(db, user)]
    row = await db.scalar(
        select(Domain)
        .where(Domain.id == domain_id, Domain.installation_id.in_(owned))
        .options(selectinload(Domain.installation))
    )
    if row is None:
        raise HTTPException(404, "Domain not found")
    return row


def _flash(request: Request, kind: str, text: str) -> RedirectResponse:
    request.session["flash"] = (kind, text)
    return RedirectResponse("/dashboard/domains", status_code=303)


@router.get("", response_class=HTMLResponse)
async def list_domains(request: Request, user: PageUser, db: Db):
    installations = await _installations(db, user)
    domains = list(
        await db.scalars(
            select(Domain)
            .where(Domain.installation_id.in_([i.id for i in installations]))
            .order_by(Domain.domain)
            .options(selectinload(Domain.installation))
        )
    )
    response = templates.TemplateResponse(
        request,
        "domains.html",
        {
            "title": "TLS domains",
            "user": user,
            "installations": installations,
            "domains": domains,
            "flash": request.session.pop("flash", None),
            "txt_name": txt_record_name,
            "txt_value": lambda d: expected_record(d.verification_token),
        },
    )
    response.headers["Cache-Control"] = "no-store"
    return response


@router.post("", dependencies=[Depends(verify_csrf)])
async def add_domain(
    request: Request,
    user: PageUser,
    db: Db,
    installation_id: Annotated[int, Form()],
    domain: Annotated[str, Form(max_length=300)],
    lifetime_years: Annotated[str, Form(max_length=3)] = "",
):
    if installation_id not in {i.id for i in await _installations(db, user)}:
        raise HTTPException(404, "Installation not found")
    try:
        name = normalise_domain(domain)
        if len(name) > 140:
            raise ValueError("That host name is too long.")
        years = None
        if lifetime_years.strip():
            if not lifetime_years.strip().isdigit() or not 0 <= int(lifetime_years) <= 100:
                raise ValueError("Lifetime must be a whole number of years from 0 to 100.")
            years = int(lifetime_years)
    except ValueError as exc:
        return _flash(request, "error", str(exc))
    db.add(
        Domain(
            installation_id=installation_id,
            domain=name,
            verification_token=new_verification_token(),
            confidentiality_lifetime_years=years,
        )
    )
    try:
        await db.commit()
    except IntegrityError:
        await db.rollback()
        return _flash(request, "error", f"{name} is already added for that installation.")
    return _flash(request, "info", f"{name} added. Publish the TXT record, then verify it.")


@router.post("/{domain_id}/verify", dependencies=[Depends(verify_csrf)])
async def verify_domain(request: Request, domain_id: int, user: PageUser, db: Db):
    row = await _owned_domain(db, user, domain_id)
    ok = await asyncio.to_thread(check_verification, row.domain, row.verification_token)
    if not ok:
        return _flash(
            request,
            "error",
            f"The TXT record for {row.domain} was not found yet. DNS changes can take a while.",
        )
    row.verified_at = utcnow()
    await db.commit()
    return _flash(request, "info", f"{row.domain} is verified.")


@router.post("/{domain_id}/scan", dependencies=[Depends(verify_csrf)])
async def scan_domain(request: Request, domain_id: int, user: PageUser, db: Db, queue: Queue):
    row = await _owned_domain(db, user, domain_id)
    if row.verified_at is None:
        return _flash(request, "error", f"{row.domain} is not verified, so it is not scanned.")
    await queue.enqueue_job("scan_tls", row.installation.github_installation_id, row.domain)
    return _flash(request, "info", f"TLS scan of {row.domain} queued. It appears on the dashboard.")


@router.post("/{domain_id}/remove", dependencies=[Depends(verify_csrf)])
async def remove_domain(request: Request, domain_id: int, user: PageUser, db: Db):
    row = await _owned_domain(db, user, domain_id)
    await db.delete(row)
    await db.commit()
    return _flash(request, "info", f"{row.domain} removed.")
