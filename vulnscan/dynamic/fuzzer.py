"""Mutation-based fuzzer for ELF binary inputs.

Strategies
----------
1. **Size escalation** — sends growing payloads (8, 16, 32 … 4096 bytes) of
   repeated 'A' bytes.  Reliably triggers stack/heap buffer overflows.
2. **Cyclic patterns** — pwntools `cyclic()` payloads of the same sizes.
   Allows Phase 5 to compute the exact offset to saved RIP via `cyclic_find`.
3. **Format string probes** — payloads of `%x.%p.%s.%n` / `%7$n` etc. to
   trigger format-string crashes.
4. **Integer boundaries** — argv values like "0", "-1", "4294967295",
   "65536", "4097" to trigger integer-overflow + allocation bugs.
5. **Bit-flip / byte-insert mutations** — applied to a set of seed inputs for
   broader coverage.

Extension point: the `fuzz()` function returns after `max_crashes` are found
or `max_iterations` are exhausted.  To plug in AFL++, replace `fuzz()` with a
thin wrapper that calls `afl-fuzz` and parses its crashes directory.
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

# Silence pwntools context noise
import logging as _logging
_logging.getLogger("pwnlib").setLevel(_logging.ERROR)


@dataclasses.dataclass
class CrashResult:
    binary: str
    strategy: str            # which mutation strategy produced the crash
    stdin_data: bytes        # the exact input that triggered the crash
    argv_extra: list[str]   # extra argv beyond the binary name
    signal_name: str
    signal_num: int
    returncode: int
    stderr_snippet: str      # first 512 bytes of stderr (ASan report etc.)
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
        """Crashes caused by cyclic patterns — usable for offset calculation."""
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
    """Run the mutation fuzzer on *binary_path*.

    Parameters
    ----------
    argv_extra  : extra arguments appended after the binary (e.g. ["200"]).
    timeout     : per-execution timeout in seconds.
    max_iterations : stop after this many payloads tested.
    max_crashes : stop early once this many crashes are found.
    seed        : RNG seed for reproducibility.
    strategies  : subset of strategy names to run (default: all).
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
        "Fuzzing done: %d iterations, %d crash(es) found",
        report.iterations, len(report.crashes),
    )
    return report


# ── payload generators ────────────────────────────────────────────────────────

def _payload_generator(
    binary_path: Path,
    argv_extra: list[str],
    rng: random.Random,
    active: list[str],
) -> Iterator[tuple[str, bytes, list[str]]]:
    """Yield (strategy_name, stdin_bytes, argv_override) tuples."""
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

    # Round-robin across strategies
    for payload in itertools.chain.from_iterable(zip(*gens)):
        yield payload


# ── strategy: size escalation ─────────────────────────────────────────────────

def _size_escalation() -> Iterator[tuple[str, bytes, list[str]]]:
    sizes = [8, 16, 32, 48, 63, 64, 65, 100, 128, 256, 512, 1024, 2048, 4096]
    for size in sizes:
        payload = b"A" * size + b"\n"
        yield ("size_escalation", payload, [])


# ── strategy: cyclic patterns ─────────────────────────────────────────────────

def _cyclic_payloads() -> Iterator[tuple[str, bytes, list[str]]]:
    """Generate pwntools cyclic() patterns for offset calculation."""
    try:
        from pwn import cyclic, context
        context.log_level = "error"
        sizes = [64, 128, 256, 512]
        for size in sizes:
            payload = cyclic(size) + b"\n"
            yield (f"cyclic_{size}", payload, [])
    except ImportError:
        # Fallback: De Bruijn-like sequence without pwntools
        for size in [64, 128, 256, 512]:
            payload = _debruijn(size) + b"\n"
            yield (f"cyclic_{size}", payload, [])


def _debruijn(length: int) -> bytes:
    """Simple De Bruijn sequence approximation."""
    alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    n = len(alphabet)
    result = bytearray()
    for i in range(length):
        result.append(alphabet[i % n])
    return bytes(result)


# ── strategy: format string ───────────────────────────────────────────────────

def _format_string_payloads() -> Iterator[tuple[str, bytes, list[str]]]:
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


# ── strategy: integer boundary (argv-based) ───────────────────────────────────

def _integer_boundary_payloads() -> Iterator[tuple[str, bytes, list[str]]]:
    """Boundary values passed as argv[1] for binaries that parse an integer.

    For values that look like element-counts, we also send count*ELEM_SIZE bytes
    so that the allocation-underflow bug (integer_overflow corpus) is reachable.
    ELEM_SIZE=64 matches the corpus binary; the limit caps stdin at 512 KiB.
    """
    boundary_vals = [
        "0", "1", "-1", "255", "256", "65535", "65536",
        "4294967295",   # UINT_MAX
        "2147483647",   # INT_MAX
        "2147483648",   # INT_MAX + 1
        "4097",         # triggers uint16 wrap: 4097*64 mod 65536 = 64
        "1025",         # 1025*64 mod 65536 = 64
    ]
    _ELEM_SIZE  = 64
    _MAX_STDIN  = 512 * 1024  # 512 KiB hard cap

    for val in boundary_vals:
        try:
            n = abs(int(val))
        except ValueError:
            n = 64

        # Small value: just send n bytes
        stdin_simple = b"A" * min(n, 4096) + b"\n"
        yield ("integer_boundary", stdin_simple, [val])

        # Also try sending count*ELEM_SIZE bytes (triggers alloc-size underflow)
        count_bytes = min(n * _ELEM_SIZE, _MAX_STDIN)
        if count_bytes > len(stdin_simple):
            stdin_large = b"A" * count_bytes
            yield ("integer_boundary_large", stdin_large, [val])


# ── strategy: random mutations ────────────────────────────────────────────────

_SEEDS = [
    b"A" * 64,
    b"hello world\n",
    b"\x00" * 64,
    b"\xff" * 64,
    b"1234567890\n",
]


def _mutation_payloads(rng: random.Random) -> Iterator[tuple[str, bytes, list[str]]]:
    for seed in _SEEDS:
        for _ in range(8):
            mutated = _mutate(bytearray(seed), rng)
            yield ("mutation", bytes(mutated) + b"\n", [])


def _mutate(data: bytearray, rng: random.Random) -> bytearray:
    if not data:
        return data
    op = rng.randint(0, 3)
    if op == 0:  # bit flip
        idx = rng.randint(0, len(data) - 1)
        bit = 1 << rng.randint(0, 7)
        data[idx] ^= bit
    elif op == 1:  # byte insert
        idx = rng.randint(0, len(data))
        data.insert(idx, rng.randint(0, 255))
    elif op == 2:  # byte delete
        if len(data) > 1:
            idx = rng.randint(0, len(data) - 1)
            del data[idx]
    else:  # chunk overwrite with interesting values
        interesting = [b"\x00", b"\xff", b"\x7f", b"\x80", b"A", b"%x", b"\n"]
        chunk = rng.choice(interesting) * rng.randint(1, min(32, len(data)))
        start = rng.randint(0, max(0, len(data) - len(chunk)))
        data[start: start + len(chunk)] = chunk
    return data
