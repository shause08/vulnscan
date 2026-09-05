"""Wrapper subprocess sécurisé avec timeout et limites de ressources."""

import resource
import subprocess
import os
import tempfile
from typing import Optional

from vulnscan.utils.logging import get_logger

logger = get_logger(__name__)

_DEFAULT_TIMEOUT = 30
# Limite l'espace d'adressage à 256 Mio pour les binaires lancés.
_AS_LIMIT = 256 * 1024 * 1024


def _set_limits() -> None:
    """Hook pré-exec : restreint les ressources des processus fils potentiellement hostiles."""
    try:
        resource.setrlimit(resource.RLIMIT_AS, (_AS_LIMIT, _AS_LIMIT))
        # Pas de core dumps.
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
    """Exécute une commande et retourne son CompletedProcess.

    Ne lève jamais d'exception sur un code de sortie non nul ; lève CalledProcessError
    uniquement si explicitement demandé, ou TimeoutExpired / FileNotFoundError sur
    de vraies erreurs.
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
        logger.warning("Commande expirée après %ds : %s", timeout, args[0])
        raise
    except FileNotFoundError:
        logger.error("Exécutable introuvable : %s", args[0])
        raise
    return result


def check_system_deps() -> list[str]:
    """Retourne la liste des exécutables système requis mais absents."""
    required = ["gcc", "gdb", "make"]
    missing = []
    for exe in required:
        result = subprocess.run(
            ["which", exe], capture_output=True
        )
        if result.returncode != 0:
            missing.append(exe)
    return missing
