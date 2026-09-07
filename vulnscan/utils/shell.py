"""Wrapper subprocess sécurisé avec timeout et limites de ressources."""

import resource
import subprocess
import os
import tempfile
from typing import Optional

from vulnscan.utils.logging import get_logger

logger = get_logger(__name__)

_DEFAULT_TIMEOUT = 30
# Limite l'espace d'adressage virtuel à 256 Mio pour contenir les processus fils potentiellement hostiles.
# Note : cette limite est incompatible avec ASan (qui mappe ~16× l'espace du processus) ;
# run_asan() dans runner.py passe limit_resources=False pour cette raison.
_AS_LIMIT = 256 * 1024 * 1024


def _set_limits() -> None:
    """Hook pré-exec : restreint les ressources des processus fils avant exec().

    Appelé depuis preexec_fn de subprocess.Popen — s'exécute dans le fils juste avant exec().
    """
    try:
        resource.setrlimit(resource.RLIMIT_AS, (_AS_LIMIT, _AS_LIMIT))
        # Désactive la génération de fichiers core dump pour éviter de remplir le disque
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
    """Retourne la liste des exécutables système requis mais absents du PATH."""
    required = ["gcc", "gdb", "make"]
    missing = []
    for exe in required:
        # which retourne un code non nul si l'exécutable est introuvable
        result = subprocess.run(
            ["which", exe], capture_output=True
        )
        if result.returncode != 0:
            missing.append(exe)
    return missing
