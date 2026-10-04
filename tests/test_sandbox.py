"""Resource-limited runner for the future engine (A16)."""

import sys

import pytest

from app.services.errors import ScanError
from app.services.sandbox import Limits, run_limited


async def test_runs_and_returns_stdout(tmp_path):
    out = await run_limited([sys.executable, "-c", "print('ok')"], str(tmp_path))
    assert out.strip() == b"ok"


async def test_environment_is_minimal(tmp_path, monkeypatch):
    monkeypatch.setenv("GITHUB_APP_PRIVATE_KEY", "secret-must-not-leak")
    code = "import os; print(sorted(os.environ))"
    out = await run_limited([sys.executable, "-c", code], str(tmp_path))
    assert b"GITHUB_APP_PRIVATE_KEY" not in out


async def test_memory_limit(tmp_path):
    limits = Limits(memory_bytes=256 * 1024**2)
    with pytest.raises(ScanError, match="failed"):
        await run_limited([sys.executable, "-c", "x = bytearray(1024**3)"], str(tmp_path), limits)


async def test_timeout(tmp_path):
    with pytest.raises(ScanError, match="timed out"):
        await run_limited(
            [sys.executable, "-c", "import time; time.sleep(5)"], str(tmp_path), Limits(timeout=0.2)
        )
