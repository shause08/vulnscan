"""Centralised logging configuration for vulnscan."""

import logging
import sys
from typing import Optional


def get_logger(name: str, level: Optional[int] = None) -> logging.Logger:
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
    level = logging.DEBUG if verbose else logging.INFO
    logging.getLogger("vulnscan").setLevel(level)
    # Silence noisy third-party loggers.
    for noisy in ("pwnlib", "lief"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
