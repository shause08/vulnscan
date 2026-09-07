"""Configuration centralisée du logging pour vulnscan."""

import logging
import sys
from typing import Optional


def get_logger(name: str, level: Optional[int] = None) -> logging.Logger:
    """Retourne un logger nommé avec un handler stderr si aucun n'est encore configuré.

    L'utilisation d'un handler conditionnel évite d'ajouter des doublons quand
    le module est importé plusieurs fois dans des contextes différents (tests, CLI…).
    """
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(
            logging.Formatter(
                "[%(levelname)s] %(name)s: %(message)s"
            )
        )
        logger.addHandler(handler)
    if level is not None:
        logger.setLevel(level)
    return logger


def configure_root(verbose: bool = False) -> None:
    """Configure le niveau du logger racine vulnscan et réduit le bruit des librairies tierces."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.getLogger("vulnscan").setLevel(level)
    # Réduit au silence les loggers tiers bavards qui polluent la sortie (pwntools, lief).
    for noisy in ("pwnlib", "lief"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
