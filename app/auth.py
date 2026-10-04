"""Sign-in, sessions, the current user and CSRF (A14).

Sessions use Starlette's SessionMiddleware: a signed, HttpOnly, SameSite=Lax cookie (Secure in
production) that holds only the GitHub user id and login, the CSRF token and the OAuth state.
It was chosen in WP3, before the database existed, over an opaque ID plus a sessions table.
Revocation is by expiry (8 hours) or by rotating SESSION_SECRET; switch to a sessions table if
per-session revocation becomes necessary. Sign-in upserts the `users` row.
"""

import hmac
import secrets
from dataclasses import dataclass
from typing import Annotated
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import RedirectResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.db import get_db
from app.models import upsert_user
from app.services.github_oauth import AUTHORIZE_URL, GitHubIdentity, OAuthError, get_github_oauth

SESSION_MAX_AGE = 8 * 60 * 60
CSRF_HEADER = "X-CSRF-Token"

router = APIRouter(prefix="/auth")


@dataclass(frozen=True)
class SessionUser:
    id: int
    login: str


class LoginRequired(Exception):
    """Raised by page routes for anonymous visitors; handled as a redirect to sign-in."""

    def __init__(self, next_path: str):
        self.next_path = next_path


def _user_from_session(request: Request) -> SessionUser | None:
    data = request.session.get("user")
    if not data:
        return None
    return SessionUser(id=int(data["id"]), login=str(data["login"]))


def current_user(request: Request) -> SessionUser:
    """For the JSON API: 401 when not signed in."""
    user = _user_from_session(request)
    if user is None:
        raise HTTPException(401, "sign-in required")
    return user


def page_user(request: Request) -> SessionUser:
    """For HTML pages: redirect to sign-in when not signed in."""
    user = _user_from_session(request)
    if user is None:
        raise LoginRequired(request.url.path)
    return user


def login_redirect(request: Request, exc: LoginRequired) -> RedirectResponse:
    return RedirectResponse(f"/auth/github/login?{urlencode({'next': exc.next_path})}", 303)


def csrf_token(request: Request | None) -> str:
    """The session's CSRF token, created on first use. Templates call this."""
    if request is None or "session" not in request.scope:
        return ""
    token = request.session.get("csrf")
    if not token:
        token = request.session["csrf"] = secrets.token_urlsafe(32)
    return token


async def verify_csrf(request: Request) -> None:
    """For state-changing routes: the header (htmx) or form field must match the session."""
    expected = request.session.get("csrf")
    sent = request.headers.get(CSRF_HEADER)
    if sent is None and request.headers.get("content-type", "").startswith(
        ("application/x-www-form-urlencoded", "multipart/form-data")
    ):
        sent = (await request.form()).get("csrf_token")
    if not expected or not isinstance(sent, str) or not hmac.compare_digest(sent, expected):
        raise HTTPException(403, "CSRF check failed")


User = Annotated[SessionUser, Depends(current_user)]
PageUser = Annotated[SessionUser, Depends(page_user)]


def _safe_next(path: str | None) -> str:
    # Only same-site paths: "/x", never "//host" or "https://host" (open redirect)
    if path and path.startswith("/") and not path.startswith("//") and "\\" not in path:
        return path
    return "/dashboard"


@router.get("/github/login")
async def github_login(request: Request, next: str | None = None):
    """Redirect to GitHub OAuth login"""
    state = secrets.token_urlsafe(32)
    request.session["oauth_state"] = state
    request.session["next"] = _safe_next(next)
    query = urlencode(
        {
            "client_id": get_settings().github_client_id,
            "redirect_uri": str(request.url_for("github_callback")),
            "state": state,
        }
    )
    return RedirectResponse(f"{AUTHORIZE_URL}?{query}", 303)


@router.get("/github/callback", name="github_callback")
async def github_callback(
    request: Request,
    oauth: Annotated[GitHubIdentity, Depends(get_github_oauth)],
    db: Annotated[AsyncSession, Depends(get_db)],
    code: str = "",
    state: str = "",
):
    expected = request.session.pop("oauth_state", None)
    if not expected or not code or not hmac.compare_digest(state, expected):
        raise HTTPException(400, "Sign-in expired or was tampered with. Please try again.")
    try:
        user = await oauth.identify(code, str(request.url_for("github_callback")))
    except OAuthError as exc:
        raise HTTPException(502, str(exc)) from None
    await upsert_user(db, user["id"], user["login"])
    await db.commit()
    next_path = _safe_next(request.session.get("next"))
    request.session.clear()  # new session on sign-in: no fixation
    request.session["user"] = user
    csrf_token(request)
    return RedirectResponse(next_path, 303)


@router.post("/logout", dependencies=[Depends(verify_csrf)])
async def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/", 303)
