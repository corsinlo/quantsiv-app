"""Run an untrusted-input tool (the future scan engine, D2) as a separate, limited process (A16).

Limits applied here: wall-clock timeout, CPU seconds, address space, file size, no core dumps, a
and a minimal environment. The tree it reads is a throwaway copy without .git.

Not applied here: network isolation. A process cannot drop its own network access without
privileges the hosting platform (Railway) does not grant. That is why hosted scanning is limited
to public repositories (D1, docs/hosted-scanning.md): private repositories are scanned only by
the customer's own CI (WP7) until hosted scans can run in a network-less sandbox.
"""

import asyncio
import os
import resource
from dataclasses import dataclass

from app.services.errors import ScanError


@dataclass(frozen=True)
class Limits:
    timeout: float = 300
    cpu_seconds: int = 300
    memory_bytes: int = 2 * 1024**3
    file_bytes: int = 512 * 1024**2


DEFAULT_LIMITS = Limits()


def _apply(limits: Limits):
    def preexec() -> None:  # runs in the child, before exec
        resource.setrlimit(resource.RLIMIT_CPU, (limits.cpu_seconds, limits.cpu_seconds))
        resource.setrlimit(resource.RLIMIT_AS, (limits.memory_bytes, limits.memory_bytes))
        resource.setrlimit(resource.RLIMIT_FSIZE, (limits.file_bytes, limits.file_bytes))
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        os.setsid()

    return preexec


async def run_limited(argv: list[str], cwd: str, limits: Limits = DEFAULT_LIMITS) -> bytes:
    """Run argv with limits; return stdout. Fails with a fixed ScanError, never tool output."""
    proc = await asyncio.create_subprocess_exec(
        *argv,
        cwd=cwd,
        env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": cwd, "LANG": "C.UTF-8"},
        stdin=asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,
        preexec_fn=_apply(limits),
    )
    try:
        stdout, _ = await asyncio.wait_for(proc.communicate(), limits.timeout)
    except TimeoutError:
        proc.kill()
        await proc.wait()
        raise ScanError("The scanner timed out") from None
    if proc.returncode != 0:
        raise ScanError("The scanner failed")
    return stdout
