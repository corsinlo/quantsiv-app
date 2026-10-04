"""API token management for the signed-in user's installations (WP7)."""

from typing import Annotated

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.auth import PageUser, SessionUser, verify_csrf
from app.db import get_db
from app.models import ApiToken, Installation, User, utcnow
from app.services.tokens import new_token
from app.templating import templates

router = APIRouter(prefix="/dashboard/tokens")
Db = Annotated[AsyncSession, Depends(get_db)]


async def _installations(db: AsyncSession, user: SessionUser) -> list[Installation]:
    return list(
        await db.scalars(
            select(Installation)
            .join(User, Installation.user_id == User.id)
            .where(User.github_user_id == user.id)
            .order_by(Installation.account_name)
        )
    )


async def _page(request: Request, db: AsyncSession, user: SessionUser, new: str | None = None):
    installations = await _installations(db, user)
    tokens = list(
        await db.scalars(
            select(ApiToken)
            .where(ApiToken.installation_id.in_([i.id for i in installations]))
            .order_by(ApiToken.created_at.desc())
            .options(selectinload(ApiToken.installation))
        )
    )
    response = templates.TemplateResponse(
        request,
        "tokens.html",
        {
            "title": "API tokens",
            "user": user,
            "installations": installations,
            "tokens": tokens,
            "new_token": new,
        },
    )
    response.headers["Cache-Control"] = "no-store"
    return response


@router.get("", response_class=HTMLResponse)
async def list_tokens(request: Request, user: PageUser, db: Db):
    return await _page(request, db, user)


@router.post("", response_class=HTMLResponse, dependencies=[Depends(verify_csrf)])
async def create_token(
    request: Request,
    user: PageUser,
    db: Db,
    installation_id: Annotated[int, Form()],
    name: Annotated[str, Form(min_length=1, max_length=100)],
):
    if installation_id not in {i.id for i in await _installations(db, user)}:
        raise HTTPException(404, "Installation not found")
    token, digest, prefix = new_token()
    db.add(
        ApiToken(
            installation_id=installation_id,
            name=name.strip(),
            token_hash=digest,
            prefix=prefix,
            created_by=await db.scalar(select(User.id).where(User.github_user_id == user.id)),
        )
    )
    await db.commit()
    # Shown once, in this response only: never stored, logged, or put in a redirect or cookie
    return await _page(request, db, user, new=token)


@router.post("/{token_id}/revoke", dependencies=[Depends(verify_csrf)])
async def revoke_token(token_id: int, user: PageUser, db: Db):
    owned = [i.id for i in await _installations(db, user)]
    row = await db.scalar(
        select(ApiToken).where(ApiToken.id == token_id, ApiToken.installation_id.in_(owned))
    )
    if row is None:
        raise HTTPException(404, "Token not found")
    if row.revoked_at is None:
        row.revoked_at = utcnow()
        await db.commit()
    return RedirectResponse("/dashboard/tokens", status_code=303)
