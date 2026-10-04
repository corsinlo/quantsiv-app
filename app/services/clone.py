"""Hardened clone of an untrusted repository (A15, A16).

The token travels only in the child's environment (git >= 2.31 reads GIT_CONFIG_*), never in
argv, the URL, .git/config inside the scanned tree, logs or user-visible errors.
"""

import asyncio
import base64
import logging
import os
import re
import shutil

from app.services.errors import ScanError

logger = logging.getLogger(__name__)
REPO_RE = re.compile(r"[A-Za-z0-9-]{1,39}/[A-Za-z0-9._-]{1,100}")


async def clone_repository(
    repo_full_name: str, token: str | None, dest: str, timeout: int = 120
) -> None:
    if not REPO_RE.fullmatch(repo_full_name):
        raise ScanError("Invalid repository name")
    env = {
        "PATH": os.environ["PATH"],
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_ASKPASS": "/bin/true",
        "GIT_LFS_SKIP_SMUDGE": "1",
        "GIT_CONFIG_COUNT": "0",
    }
    if token:
        auth = base64.b64encode(f"x-access-token:{token}".encode()).decode()
        env.update(
            {
                "GIT_CONFIG_COUNT": "1",
                "GIT_CONFIG_KEY_0": "http.https://github.com/.extraheader",
                "GIT_CONFIG_VALUE_0": f"Authorization: Basic {auth}",
            }
        )
    # Untrusted input: no symlinks, no hooks, https only, no submodules, tags or LFS (A16)
    proc = await asyncio.create_subprocess_exec(
        "git",
        "-c",
        "core.symlinks=false",
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "protocol.allow=never",
        "-c",
        "protocol.https.allow=always",
        "clone",
        "--depth=1",
        "--single-branch",
        "--no-tags",
        "--no-recurse-submodules",
        "--",
        f"https://github.com/{repo_full_name}.git",
        dest,
        env=env,
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        await asyncio.wait_for(proc.communicate(), timeout)
    except TimeoutError:
        proc.kill()
        await proc.wait()
        raise ScanError("Cloning timed out") from None
    if proc.returncode != 0:
        # git's stderr can echo URLs and headers: log the exit code, never the text
        logger.warning("git clone failed (exit %s)", proc.returncode)
        raise ScanError("Could not clone the repository")
    # The scanner reads the working tree only; drop .git (config, packed history)
    await asyncio.to_thread(shutil.rmtree, os.path.join(dest, ".git"), ignore_errors=True)
