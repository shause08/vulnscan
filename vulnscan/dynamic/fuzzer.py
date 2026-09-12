"""Fuzzer à mutations pour les entrées de binaires ELF.

Stratégies
----------
1. **Escalade de taille** — envoie des charges utiles croissantes (8, 16, 32 … 4096 octets)
   d'octets 'A' répétés. Déclenche de manière fiable les dépassements de tampon pile/tas.
2. **Patterns cycliques** — charges utiles pwntools `cyclic()` des mêmes tailles.
   Permet à la Phase 5 de calculer l'offset exact vers le RIP sauvegardé via `cyclic_find`.
3. **Sondes de chaîne de format** — charges utiles `%x.%p.%s.%n` / `%7$n` etc. pour
   déclencher des crashes de format string.
4. **Bornes entières** — valeurs argv comme "0", "-1", "4294967295", "65536", "4097"
   pour déclencher des bugs d'overflow entier + allocation.
5. **Mutations bit-flip / insertion d'octet** — appliquées à un ensemble d'entrées
   de départ pour une couverture plus large.

Point d'extension : la fonction `fuzz()` s'arrête après `max_crashes` crashes trouvés
ou `max_iterations` épuisées. Pour brancher AFL++, remplacer `fuzz()` par un wrapper
qui appelle `afl-fuzz` et parse son répertoire de crashes.
"""

from __future__ import annotations

import dataclasses
import itertools
import os
import random
import struct
import tempfile
from pathlib import Path
from typing import Iterator, Optional

from vulnscan.dynamic.runner import RunResult, run
from vulnscan.utils.logging import get_logger

logger = get_logger(__name__)

# Silence le bruit de contexte pwntools
import logging as _logging
_logging.getLogger("pwnlib").setLevel(_logging.ERROR)


@dataclasses.dataclass
class CrashResult:
    binary: str
    strategy: str            # quelle stratégie de mutation a produit le crash
    stdin_data: bytes        # l'entrée exacte qui a déclenché le crash
    argv_extra: list[str]   # arguments argv supplémentaires après le nom du binaire
    signal_name: str
    signal_num: int
    returncode: int
    stderr_snippet: str      # 512 premiers octets du stderr (rapport ASan etc.)
    iteration: int


@dataclasses.dataclass
class FuzzReport:
    binary: str
    iterations: int
    crashes: list[CrashResult]
    strategies_used: list[str]

    @property
    def unique_signals(self) -> set[str]:
        return {c.signal_name for c in self.crashes}

    @property
    def cyclic_crashes(self) -> list[CrashResult]:
        """Crashes provoqués par des patterns cycliques — utilisables pour le calcul d'offset."""
        return [c for c in self.crashes if c.strategy.startswith("cyclic")]


def fuzz(
    binary_path: Path,
    *,
    argv_extra: list[str] | None = None,
    timeout: int = 5,
    max_iterations: int = 200,
    max_crashes: int = 10,
    seed: int = 42,
    strategies: Optional[list[str]] = None,
) -> FuzzReport:
    """Lance le fuzzer à mutations sur *binary_path*.

    Paramètres
    ----------
    argv_extra      : arguments supplémentaires après le binaire (ex. ["200"]).
    timeout         : timeout par exécution en secondes.
    max_iterations  : s'arrête après ce nombre de charges utiles testées.
    max_crashes     : s'arrête dès que ce nombre de crashes est atteint.
    seed            : graine RNG pour la reproductibilité.
    strategies      : sous-ensemble de noms de stratégies à exécuter (défaut : toutes).
    """
    rng = random.Random(seed)
    all_strategies = ["size_escalation", "cyclic", "format_string",
                      "integer_boundary", "mutation"]
    active = strategies or all_strategies

    report = FuzzReport(
        binary=str(binary_path),
        iterations=0,
        crashes=[],
        strategies_used=active,
    )

    gen = _payload_generator(binary_path, argv_extra or [], rng, active)

    for iteration, (strategy, stdin_data, iter_argv) in enumerate(gen):
        if iteration >= max_iterations or len(report.crashes) >= max_crashes:
            break

        result = run(
            binary_path,
            stdin_data=stdin_data,
            argv_extra=iter_argv if iter_argv else argv_extra,
            timeout=timeout,
        )
        report.iterations += 1

        if result.crashed:
            crash = CrashResult(
                binary=str(binary_path),
                strategy=strategy,
                stdin_data=stdin_data,
                argv_extra=iter_argv or argv_extra or [],
                signal_name=result.signal_name,
                signal_num=result.signal_num,
                returncode=result.returncode,
                stderr_snippet=(result.stderr[:512]).decode(errors="replace"),
                iteration=iteration,
            )
            report.crashes.append(crash)
            logger.info(
                "CRASH #%d  strategy=%-20s  signal=%-8s  input=%dB  iter=%d",
                len(report.crashes), strategy,
                result.signal_name or f"rc={result.returncode}",
                len(stdin_data), iteration,
            )

    logger.info(
        "Fuzzing terminé : %d itération(s), %d crash(es) trouvé(s)",
        report.iterations, len(report.crashes),
    )
    return report


# ── générateurs de charges utiles ─────────────────────────────────────────────

def _payload_generator(
    binary_path: Path,
    argv_extra: list[str],
    rng: random.Random,
    active: list[str],
) -> Iterator[tuple[str, bytes, list[str]]]:
    """Produit des tuples (nom_stratégie, octets_stdin, argv_override)."""
    gens: list[Iterator] = []

    if "size_escalation" in active:
        gens.append(_size_escalation())
    if "cyclic" in active:
        gens.append(_cyclic_payloads())
    if "format_string" in active:
        gens.append(_format_string_payloads())
    if "integer_boundary" in active:
        gens.append(_integer_boundary_payloads())
    if "mutation" in active:
        gens.append(_mutation_payloads(rng))

    # Round-robin entre stratégies
    for payload in itertools.chain.from_iterable(zip(*gens)):
        yield payload


# ── stratégie : escalade de taille ───────────────────────────────────────────

def _size_escalation() -> Iterator[tuple[str, bytes, list[str]]]:
    """Génère des charges utiles de taille croissante pour détecter les dépassements de tampon.

    Les tailles 63/64/65 et 127/128/129 encadrent les puissances de deux courantes
    pour déclencher les dépassements de tampon autour des buffers typiques.
    """
    sizes = [8, 16, 32, 48, 63, 64, 65, 100, 128, 256, 512, 1024, 2048, 4096]
    for size in sizes:
        payload = b"A" * size + b"\n"
        yield ("size_escalation", payload, [])


# ── stratégie : patterns cycliques ───────────────────────────────────────────

def _cyclic_payloads() -> Iterator[tuple[str, bytes, list[str]]]:
    """Génère des patterns pwntools cyclic() pour le calcul d'offset."""
    try:
        from pwn import cyclic, context
        context.log_level = "error"
        sizes = [64, 128, 256, 512]
        for size in sizes:
            payload = cyclic(size) + b"\n"
            yield (f"cyclic_{size}", payload, [])
    except ImportError:
        # Repli : séquence De Bruijn approchée sans pwntools
        for size in [64, 128, 256, 512]:
            payload = _debruijn(size) + b"\n"
            yield (f"cyclic_{size}", payload, [])


def _debruijn(length: int) -> bytes:
    """Approximation simple d'une séquence De Bruijn."""
    alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    n = len(alphabet)
    result = bytearray()
    for i in range(length):
        result.append(alphabet[i % n])
    return bytes(result)


# ── stratégie : chaîne de format ──────────────────────────────────────────────

def _format_string_payloads() -> Iterator[tuple[str, bytes, list[str]]]:
    """Génère des sondes de chaîne de format couvrant lecture arbitraire (%x, %p), écriture (%n) et crashs (%s)."""
    probes = [
        b"%x.%x.%x.%x.%x.%x.%x.%x\n",
        b"%p.%p.%p.%p.%p.%p.%p.%p\n",
        b"%s%s%s%s%s%s%s%s\n",
        b"%n\n",
        b"%7$n\n",
        b"AAAA%x%x%x%x%x%x%x%x%x%x\n",
        b"AAAA%10$n\n",
        b"%" + b"x" * 200 + b"\n",
        b"%99999999d\n",
        b"|%p|" * 20 + b"\n",
    ]
    for p in probes:
        yield ("format_string", p, [])


# ── stratégie : bornes entières (argv-based) ──────────────────────────────────

def _integer_boundary_payloads() -> Iterator[tuple[str, bytes, list[str]]]:
    """Valeurs limites passées en argv[1] pour les binaires qui parsent un entier.

    Pour les valeurs qui ressemblent à des compteurs d'éléments, on envoie aussi
    count*ELEM_SIZE octets afin que le bug d'underflow d'allocation soit atteignable.
    ELEM_SIZE=64 correspond au binaire du corpus ; la limite plafonne stdin à 512 Kio.
    """
    boundary_vals = [
        "0", "1", "-1", "255", "256", "65535", "65536",
        "4294967295",   # UINT_MAX
        "2147483647",   # INT_MAX
        "2147483648",   # INT_MAX + 1
        "4097",         # déclenche le débordement uint16 : 4097*64 mod 65536 = 64
        "1025",         # 1025*64 mod 65536 = 64
    ]
    _ELEM_SIZE  = 64
    _MAX_STDIN  = 512 * 1024  # 512 Kio max

    for val in boundary_vals:
        try:
            n = abs(int(val))
        except ValueError:
            n = 64

        # Petite valeur : envoie n octets
        stdin_simple = b"A" * min(n, 4096) + b"\n"
        yield ("integer_boundary", stdin_simple, [val])

        # Essaie aussi d'envoyer count*ELEM_SIZE octets (déclenche l'underflow de taille d'alloc)
        count_bytes = min(n * _ELEM_SIZE, _MAX_STDIN)
        if count_bytes > len(stdin_simple):
            stdin_large = b"A" * count_bytes
            yield ("integer_boundary_large", stdin_large, [val])


# ── stratégie : mutations aléatoires ─────────────────────────────────────────

_SEEDS = [
    b"A" * 64,
    b"hello world\n",
    b"\x00" * 64,
    b"\xff" * 64,
    b"1234567890\n",
]


def _mutation_payloads(rng: random.Random) -> Iterator[tuple[str, bytes, list[str]]]:
    """Applique 8 mutations aléatoires à chaque entrée de départ pour explorer les cas limites."""
    for seed in _SEEDS:
        for _ in range(8):
            mutated = _mutate(bytearray(seed), rng)
            yield ("mutation", bytes(mutated) + b"\n", [])


def _mutate(data: bytearray, rng: random.Random) -> bytearray:
    if not data:
        return data
    op = rng.randint(0, 3)
    if op == 0:  # inversion de bit
        idx = rng.randint(0, len(data) - 1)
        bit = 1 << rng.randint(0, 7)
        data[idx] ^= bit
    elif op == 1:  # insertion d'octet
        idx = rng.randint(0, len(data))
        data.insert(idx, rng.randint(0, 255))
    elif op == 2:  # suppression d'octet
        if len(data) > 1:
            idx = rng.randint(0, len(data) - 1)
            del data[idx]
    else:  # écrasement de chunk avec des valeurs intéressantes
        interesting = [b"\x00", b"\xff", b"\x7f", b"\x80", b"A", b"%x", b"\n"]
        chunk = rng.choice(interesting) * rng.randint(1, min(32, len(data)))
        start = rng.randint(0, max(0, len(data) - len(chunk)))
        data[start: start + len(chunk)] = chunk
    return data
