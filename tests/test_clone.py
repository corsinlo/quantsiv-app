"""Hardened clone (A15, A16): the token never reaches argv, the URL or an error message."""

import asyncio
import base64
import os

import pytest

from app.services import clone
from app.services.errors import ScanError

TOKEN = "ghs_SECRET_TOKEN_VALUE"


class FakeProcess:
    def __init__(self, returncode=0, stderr=b"", hang=False):
        self.returncode = returncode
        self._stderr = stderr
        self._hang = hang
        self.killed = False

    async def communicate(self):
        if self._hang:
            await asyncio.sleep(10)
        return b"", self._stderr

    def kill(self):
        self.killed = True

    async def wait(self):
        return self.returncode


@pytest.fixture
def spawn(monkeypatch):
    calls = []

    def install(process: FakeProcess, make_git_dir: str | None = None):
        async def fake_exec(*argv, env=None, **kwargs):
            calls.append({"argv": argv, "env": env})
            if make_git_dir:
                os.makedirs(os.path.join(make_git_dir, ".git"))
            return process

        monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_exec)
        return calls

    return install


async def test_token_only_travels_in_the_environment(spawn, tmp_path):
    dest = str(tmp_path / "repo")
    calls = spawn(FakeProcess(), make_git_dir=dest)
    await clone.clone_repository("octo/hello", TOKEN, dest)
    (call,) = calls
    for arg in call["argv"]:
        assert TOKEN not in arg
        assert base64.b64encode(f"x-access-token:{TOKEN}".encode()).decode() not in arg
    assert "https://github.com/octo/hello.git" in call["argv"]  # no credentials in the URL
    header = call["env"]["GIT_CONFIG_VALUE_0"]
    assert header.startswith("Authorization: Basic ")
    assert base64.b64decode(header.split()[-1]).decode() == f"x-access-token:{TOKEN}"
    assert not os.path.exists(os.path.join(dest, ".git"))  # removed before scanning


async def test_hardening_flags(spawn, tmp_path):
    calls = spawn(FakeProcess())
    await clone.clone_repository("octo/hello", None, str(tmp_path / "r"))
    argv = calls[0]["argv"]
    for flag in (
        "core.symlinks=false",
        "core.hooksPath=/dev/null",
        "protocol.allow=never",
        "protocol.https.allow=always",
        "--depth=1",
        "--single-branch",
        "--no-tags",
        "--no-recurse-submodules",
    ):
        assert flag in argv
    assert argv[argv.index("--") + 1].startswith("https://github.com/")
    env = calls[0]["env"]
    assert env["GIT_LFS_SKIP_SMUDGE"] == "1"
    assert env["GIT_TERMINAL_PROMPT"] == "0"
    assert env["GIT_CONFIG_COUNT"] == "0"  # no token, no auth header


async def test_failure_message_is_fixed_and_never_echoes_git(spawn, tmp_path, caplog):
    leak = f"fatal: unable to access 'https://x-access-token:{TOKEN}@github.com/'".encode()
    spawn(FakeProcess(returncode=128, stderr=leak))
    with pytest.raises(ScanError) as exc:
        await clone.clone_repository("octo/hello", TOKEN, str(tmp_path / "r"))
    assert str(exc.value) == "Could not clone the repository"
    assert TOKEN not in caplog.text


async def test_timeout_kills_git(spawn, tmp_path):
    process = FakeProcess(hang=True)
    spawn(process)
    with pytest.raises(ScanError, match="timed out"):
        await clone.clone_repository("octo/hello", TOKEN, str(tmp_path / "r"), timeout=0.05)
    assert process.killed


@pytest.mark.parametrize("name", ["octo", "octo/hello/x", "--upload-pack=x/y", "o/r r", "../o/r"])
async def test_invalid_names_never_reach_git(spawn, tmp_path, name):
    calls = spawn(FakeProcess())
    with pytest.raises(ScanError, match="Invalid repository name"):
        await clone.clone_repository(name, TOKEN, str(tmp_path / "r"))
    assert calls == []
