"""GitHub App webhook (A11-A13). It verifies, deduplicates and enqueues; the worker does the
work (`app.worker.handle_github_event`), so GitHub gets its answer well within 10 seconds."""

import hashlib
import hmac
import json
import logging
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request

from app.config import Settings, get_settings
from app.queue import JobQueue, get_queue
from app.request_body import read_body

logger = logging.getLogger(__name__)
router = APIRouter()

MAX_BODY = 25 * 1024 * 1024  # GitHub caps webhook payloads at 25 MB


@router.post("/webhook/github", status_code=202)
async def github_webhook(
    request: Request,
    settings: Annotated[Settings, Depends(get_settings)],
    queue: Annotated[JobQueue, Depends(get_queue)],
):
    body = await read_body(request, MAX_BODY)
    secret = settings.github_webhook_secret.get_secret_value().encode()
    expected = b"sha256=" + hmac.new(secret, body, hashlib.sha256).hexdigest().encode()
    # Compare bytes: str comparison raises TypeError (a 500) on non-ASCII input
    received = request.headers.get("X-Hub-Signature-256", "").encode("latin-1")
    if not hmac.compare_digest(received, expected):
        raise HTTPException(401, "invalid signature")
    delivery = request.headers.get("X-GitHub-Delivery")
    event = request.headers.get("X-GitHub-Event")
    if not delivery or not event:
        raise HTTPException(400, "missing GitHub headers")
    try:
        payload = json.loads(body)
    except ValueError:
        raise HTTPException(400, "body is not JSON") from None
    # ARQ refuses a second job with the same id, so redeliveries are processed once
    job = await queue.enqueue_job("handle_github_event", event, payload, _job_id=f"gh-{delivery}")
    if job is None:
        logger.info("webhook delivery %s already queued", delivery)
        return {"status": "duplicate"}
    return {"status": "queued"}
