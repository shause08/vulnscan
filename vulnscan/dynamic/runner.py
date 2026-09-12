"""Exécuteur de binaires sécurisé avec capture de signal et limites de ressources.

Exécute un binaire avec un stdin/argv contrôlé, applique un timeout strict,
et retourne un résultat structuré incluant la détection de crash et le nom du signal.
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

# Limites de ressources par exécution pour les binaires potentiellement hostiles
_AS_LIMIT  = 256 * 1024 * 1024   # 256 Mio d'espace d'adressage
_CPU_LIMIT = 10                   # 10 secondes CPU
_FILE_LIMIT = 0                   # aucun nouveau fichier écrit

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
    argv_extra: list[str]             # arguments après le nom du binaire
    returncode: int
    signal_num: int                   # 0 si pas de signal
    signal_name: str                  # "SIGSEGV" / "" si aucun
    stdout: bytes
    stderr: bytes
    timed_out: bool
    crashed: bool
    duration_s: float
    env_vars: dict[str, str]          # variables d'env supplémentaires

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
    """Exécute *binary_path* de manière sécurisée et retourne un RunResult."""
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
        logger.error("Binaire introuvable : %s", binary_path)
        raise
    except Exception as exc:
        logger.error("Erreur du runner pour %s : %s", binary_path, exc)
        raise

    duration = time.monotonic() - t0
    rc = proc.returncode

    # Sous Unix, un returncode négatif = tué par -numéro_de_signal
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


# ── utilitaires ───────────────────────────────────────────────────────────────

def _set_limits() -> None:
    """Hook pré-exec : restreint les ressources pour contenir les processus fils hostiles."""
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
