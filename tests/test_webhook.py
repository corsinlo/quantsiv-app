"""Signature check on the current webhook handler. WP3 replaces the handler and extends this."""

import hashlib
import hmac
import json

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)
BODY = json.dumps({"zen": "hello"}).encode()


def sign(body: bytes, secret: str = "test-secret") -> str:
    return "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


def test_signature_from_settings_is_accepted():
    response = client.post(
        "/webhook/github",
        content=BODY,
        headers={"X-Hub-Signature-256": sign(BODY), "X-GitHub-Event": "ping"},
    )
    assert response.status_code == 200


def test_wrong_signature_is_rejected():
    response = client.post(
        "/webhook/github",
        content=BODY,
        headers={"X-Hub-Signature-256": sign(BODY, "wrong"), "X-GitHub-Event": "ping"},
    )
    assert response.status_code == 403


def test_the_old_hard_coded_secret_is_rejected():
    response = client.post(
        "/webhook/github",
        content=BODY,
        headers={
            "X-Hub-Signature-256": sign(BODY, "placeholder_webhook_secret"),
            "X-GitHub-Event": "ping",
        },
    )
    assert response.status_code == 403


def test_missing_signature_is_rejected():
    response = client.post("/webhook/github", content=BODY, headers={"X-GitHub-Event": "ping"})
    assert response.status_code == 400
