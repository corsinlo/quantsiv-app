"""Legal pages (A33, WP8). The routes exist; the content waits for decision D4 and counsel.

Until `LEGAL_READY=true`, production answers 404 and other environments render a clearly
labelled placeholder, so nothing invented about the legal entity is ever published."""

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse

from app.config import get_settings
from app.templating import templates

router = APIRouter(prefix="/legal")
PAGES = {
    "privacy": "Privacy Policy",
    "terms": "Terms of Service",
    "refunds": "Refund Policy",
    "cookies": "Cookie Policy",
    "notice": "Legal Notice",
    "data-deletion": "Delete Your Data",
}


@router.get("/{slug}", response_class=HTMLResponse)
async def legal_page(request: Request, slug: str):
    if slug not in PAGES:
        raise HTTPException(404)
    settings = get_settings()
    if not settings.legal_ready and settings.env == "production":
        raise HTTPException(404)
    return templates.TemplateResponse(
        request,
        f"legal/{slug}.html",
        {"title": PAGES[slug], "ready": settings.legal_ready, "pages": PAGES},
    )
