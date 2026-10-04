"""Webhook handler (A11-A13): the 7 cases from audit section 7, plus size and JSON checks."""

import hashlib
import hmac
import json

import pytest
from fastapi.testclient import TestClient

from app import worker
from app.main import app
from app.queue import get_queue
from app.routers import webhooks

client = TestClient(app)
BODY = json.dumps({"zen": "hello"}).encode()


class FakeQueue:
    """Mimics ArqRedis.enqueue_job: a job id that already exists is refused (returns None)."""

    def __init__(self):
        self.jobs: dict[str, tuple] = {}

    async def enqueue_job(self, function, *args, _job_id=None, **kwargs):
        if _job_id in self.jobs:
            return None
        self.jobs[_job_id] = (function, args, kwargs)
        return object()


@pytest.fixture
def queue():
    fake = FakeQueue()
    app.dependency_overrides[get_queue] = lambda: fake
    yield fake
    app.dependency_overrides.pop(get_queue, None)


def sign(body: bytes, secret: str = "test-secret") -> str:
    return "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


def post(body: bytes = BODY, signature: str | bytes | None = None, delivery: str = "d-1"):
    headers = {"X-GitHub-Event": "ping", "X-GitHub-Delivery": delivery}
    if signature is not None:
        headers["X-Hub-Signature-256"] = signature
    return client.post("/webhook/github", content=body, headers=headers)


def test_valid_signature_is_queued(queue):
    response = post(signature=sign(BODY))
    assert response.status_code == 202
    assert queue.jobs["gh-d-1"] == ("handle_github_event", ("ping", {"zen": "hello"}), {})


def test_wrong_signature_is_401(queue):
    assert post(signature=sign(BODY, "wrong")).status_code == 401
    assert post(signature=sign(BODY, "placeholder_webhook_secret")).status_code == 401
    assert queue.jobs == {}


def test_missing_signature_is_401(queue):
    assert post().status_code == 401


def test_non_ascii_signature_is_401_not_500(queue):
    assert post(signature="sha256=\xe9".encode("latin-1")).status_code == 401


def test_duplicate_delivery_is_enqueued_once(queue):
    assert post(signature=sign(BODY), delivery="same").json() == {"status": "queued"}
    assert post(signature=sign(BODY), delivery="same").json() == {"status": "duplicate"}
    assert list(queue.jobs) == ["gh-same"]


def test_non_json_body_is_400(queue):
    body = b"not json"
    assert post(body=body, signature=sign(body)).status_code == 400


def test_missing_delivery_header_is_400(queue):
    response = client.post(
        "/webhook/github",
        content=BODY,
        headers={"X-GitHub-Event": "ping", "X-Hub-Signature-256": sign(BODY)},
    )
    assert response.status_code == 400


def test_oversized_body_is_413(queue, monkeypatch):
    monkeypatch.setattr(webhooks, "MAX_BODY", 10)
    assert post(signature=sign(BODY)).status_code == 413


# Worker side


class FakeRedis:
    def __init__(self):
        self.calls = []

    async def enqueue_job(self, *args, **kwargs):
        self.calls.append((args, kwargs))


def push(ref: str, **extra) -> dict:
    return {
        "ref": ref,
        "repository": {"full_name": "o/r", "default_branch": "main"},
        "installation": {"id": 7},
        **extra,
    }


async def test_installation_account_is_read_from_installation(worker_ctx):
    from sqlalchemy import select

    from app.models import Installation

    payload = {
        "action": "created",
        "installation": {"id": 7001, "account": {"login": "acme", "type": "Organization"}},
        "sender": {"id": 9001, "login": "acme-admin"},
    }
    assert await worker.handle_github_event(worker_ctx, "installation", payload) == (
        "installation-created"
    )
    async with worker_ctx["sessionmaker"]() as db:
        row = await db.scalar(
            select(Installation).where(Installation.github_installation_id == 7001)
        )
        assert (row.account_name, row.account_type) == ("acme", "Organization")


async def test_push_to_default_branch_queues_a_scan():
    redis = FakeRedis()
    assert await worker.handle_github_event({"redis": redis}, "push", push("refs/heads/main"))
    assert redis.calls == [(("scan_repository", 7, "o/r"), {"triggered_by": "push"})]


@pytest.mark.parametrize("ref", ["refs/tags/main", "refs/heads/main/feature", "refs/heads/dev"])
async def test_push_to_other_refs_is_ignored(ref):
    redis = FakeRedis()
    result = await worker.handle_github_event({"redis": redis}, "push", push(ref))
    assert result == "ignored-non-default-ref"
    assert redis.calls == []


async def test_branch_deletion_is_ignored():
    redis = FakeRedis()
    payload = push("refs/heads/main", deleted=True)
    assert await worker.handle_github_event({"redis": redis}, "push", payload) == (
        "ignored-deleted-branch"
    )
    assert redis.calls == []


async def test_info_logs_carry_no_account_names(caplog):
    caplog.set_level("INFO", logger="app")
    payload = {"action": "suspend", "installation": {"id": 7002, "account": {"login": "acme-corp"}}}
    await worker.handle_github_event({}, "installation", payload)
    assert "acme-corp" not in caplog.text
    assert "7002" in caplog.text


def test_no_print_calls_in_app():
    from pathlib import Path

    for path in Path("app").rglob("*.py"):
        assert "print(" not in path.read_text(encoding="utf-8"), path
