"""The single Jinja2Templates instance (A46)."""

from datetime import datetime

from fastapi.templating import Jinja2Templates

from app.auth import csrf_token
from app.config import get_settings
from app.models import ScanStatus
from app.services.scoring import HNDL_EXPOSED, PQC_GUIDANCE


def display_datetime(value: datetime | str | None) -> str:
    """Format a timestamp for display; `—` when there is none (A43: never .strftime a str)."""
    if not value:
        return "—"
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value)
        except ValueError:
            return "—"
    return value.strftime("%d %b %Y, %H:%M %Z").strip().rstrip(",")


templates = Jinja2Templates(directory="app/templates")
templates.env.globals.update(
    legal_ready=lambda: get_settings().legal_ready,
    ScanStatus=ScanStatus,
    HNDL_EXPOSED=HNDL_EXPOSED,
    PQC_GUIDANCE=PQC_GUIDANCE,
    csrf_token=csrf_token,
)
templates.env.filters["display_datetime"] = display_datetime
