"""Safe binary executor with signal capture and resource limits.

Executes a binary with controlled stdin/argv, applies a hard timeout,
and returns a structured result including crash detection and signal name.
"""

from __future__ import annotations

import dataclasses
import os
import resource
import signal
import subprocess
import time
from pathlib import Path
from typing import Optional

from vulnscan.utils.logging import get_logger

logger = get_logger(__name__)

# Per-execution resource limits for hostile binaries
_AS_LIMIT  = 256 * 1024 * 1024   # 256 MiB address space
_CPU_LIMIT = 10                   # 10 CPU-seconds
_FILE_LIMIT = 0                   # no new files written

_SIGNAL_NAMES: dict[int, str] = {
    signal.SIGSEGV: "SIGSEGV",
    signal.SIGABRT: "SIGABRT",
    signal.SIGFPE:  "SIGFPE",
    signal.SIGBUS:  "SIGBUS",
    signal.SIGILL:  "SIGILL",
    signal.SIGTRAP: "SIGTRAP",
    signal.SIGKILL: "SIGKILL",
    signal.SIGTERM: "SIGTERM",
    signal.SIGPIPE: "SIGPIPE",
}


@dataclasses.dataclass
class RunResult:
    binary: str
    stdin_data: bytes
    argv_extra: list[str]             # args after the binary name
    returncode: int
    signal_num: int                   # 0 if no signal
    signal_name: str                  # "SIGSEGV" / "" if none
    stdout: bytes
    stderr: bytes
    timed_out: bool
    crashed: bool
    duration_s: float
    env_vars: dict[str, str]          # extra env (e.g. ASAN_OPTIONS)

    @property
    def crash_summary(self) -> str:
        if self.timed_out:
            return "TIMEOUT"
        if self.crashed:
            return self.signal_name or f"EXIT({self.returncode})"
        return "OK"


def run(
    binary_path: Path,
    *,
    stdin_data: bytes = b"",
    argv_extra: list[str] | None = None,
    timeout: int = 10,
    env_vars: dict[str, str] | None = None,
    capture_output: bool = True,
    limit_resources: bool = True,
) -> RunResult:
    """Execute *binary_path* safely and return a RunResult."""
    argv = [str(binary_path)] + (argv_extra or [])
    env = _build_env(env_vars or {})

    t0 = time.monotonic()
    timed_out = False
    proc: Optional[subprocess.Popen] = None

    try:
        proc = subprocess.Popen(
            argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE if capture_output else subprocess.DEVNULL,
            stderr=subprocess.PIPE if capture_output else subprocess.DEVNULL,
            env=env,
            preexec_fn=_set_limits if limit_resources else None,
        )
        try:
            stdout, stderr = proc.communicate(input=stdin_data, timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            stdout, stderr = proc.communicate()
            timed_out = True

    except FileNotFoundError:
        logger.error("Binary not found: %s", binary_path)
        raise
    except Exception as exc:
        logger.error("Runner error for %s: %s", binary_path, exc)
        raise

    duration = time.monotonic() - t0
    rc = proc.returncode

    # On Unix, negative returncode = killed by -signal_number
    sig_num = 0
    if rc < 0:
        sig_num = -rc
    sig_name = _SIGNAL_NAMES.get(sig_num, f"SIG{sig_num}" if sig_num else "")

    crashed = (rc < 0) or timed_out

    logger.debug(
        "run %s → rc=%d sig=%s %.2fs stdin=%dB",
        binary_path.name, rc, sig_name or "none", duration, len(stdin_data),
    )

    return RunResult(
        binary=str(binary_path),
        stdin_data=stdin_data,
        argv_extra=argv_extra or [],
        returncode=rc,
        signal_num=sig_num,
        signal_name=sig_name,
        stdout=stdout if capture_output else b"",
        stderr=stderr if capture_output else b"",
        timed_out=timed_out,
        crashed=crashed,
        duration_s=round(duration, 3),
        env_vars=env_vars or {},
    )


def run_asan(
    binary_path: Path,
    *,
    stdin_data: bytes = b"",
    argv_extra: list[str] | None = None,
    timeout: int = 15,
) -> RunResult:
    """Run an ASan-instrumented binary and capture its full error report.

    ASan maps a large shadow-memory region (~16× the process AS), so we must
    NOT apply RLIMIT_AS here; the binary is already instrumented and sandboxed.
    """
    asan_opts = (
        "detect_leaks=0:"
        "abort_on_error=1:"
        "symbolize=1:"
        "color=never"
    )
    return run(
        binary_path,
        stdin_data=stdin_data,
        argv_extra=argv_extra,
        timeout=timeout,
        env_vars={"ASAN_OPTIONS": asan_opts},
        limit_resources=False,   # ASan needs large virtual address space
    )


# ── helpers ────────────────────────────────────────────────────────────────────

def _set_limits() -> None:
    """Pre-exec: restrict resources to contain hostile binaries."""
    try:
        resource.setrlimit(resource.RLIMIT_AS,   (_AS_LIMIT, _AS_LIMIT))
        resource.setrlimit(resource.RLIMIT_CPU,  (_CPU_LIMIT, _CPU_LIMIT))
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    except (ValueError, resource.error):
        pass


def _build_env(extra: dict[str, str]) -> dict[str, str]:
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": os.environ.get("HOME", "/tmp"),
    }
    env.update(extra)
    return env
