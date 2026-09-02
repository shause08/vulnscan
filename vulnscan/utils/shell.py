"""Secure subprocess wrapper with timeout and resource limits."""

import resource
import subprocess
import os
import tempfile
from typing import Optional

from vulnscan.utils.logging import get_logger

logger = get_logger(__name__)

_DEFAULT_TIMEOUT = 30
# Limit address space to 256 MiB for spawned binaries.
_AS_LIMIT = 256 * 1024 * 1024


def _set_limits() -> None:
    """Pre-exec hook: restrict resources for potentially hostile child processes."""
    try:
        resource.setrlimit(resource.RLIMIT_AS, (_AS_LIMIT, _AS_LIMIT))
        # No core dumps.
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    except ValueError:
        pass


def run(
    args: list[str],
    *,
    stdin_data: Optional[bytes] = None,
    timeout: int = _DEFAULT_TIMEOUT,
    cwd: Optional[str] = None,
    env: Optional[dict[str, str]] = None,
    limit_resources: bool = True,
) -> subprocess.CompletedProcess[bytes]:
    """Run a command and return its CompletedProcess.

    Never raises on non-zero exit; raises CalledProcessError only when explicitly
    asked, or TimeoutExpired / FileNotFoundError on real errors.
    """
    preexec = _set_limits if limit_resources else None
    logger.debug("run: %s", " ".join(args))
    try:
        result = subprocess.run(
            args,
            input=stdin_data,
            capture_output=True,
            timeout=timeout,
            cwd=cwd,
            env=env,
            preexec_fn=preexec,
        )
    except subprocess.TimeoutExpired as exc:
        logger.warning("Command timed out after %ds: %s", timeout, args[0])
        raise
    except FileNotFoundError:
        logger.error("Executable not found: %s", args[0])
        raise
    return result


def check_system_deps() -> list[str]:
    """Return a list of missing required system executables."""
    required = ["gcc", "gdb", "make"]
    missing = []
    for exe in required:
        result = subprocess.run(
            ["which", exe], capture_output=True
        )
        if result.returncode != 0:
            missing.append(exe)
    return missing
