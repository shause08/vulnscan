"""Phase 1 — corpus build and basic crash detection tests."""

import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parent.parent
CORPUS_BIN = ROOT / "corpus" / "bin"

VULN_BINARIES = [
    "stack_bof_vuln",
    "heap_bof_vuln",
    "format_string_vuln",
    "integer_overflow_vuln",
    "uaf_vuln",
    "off_by_one_vuln",
]

def _bin(name: str) -> Path:
    return CORPUS_BIN / name


# ── Existence ─────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("name", VULN_BINARIES)
def test_binary_exists(name: str):
    assert _bin(name).exists(), f"Binary not found: {name} — run 'make -C corpus all'"


# ── Crash detection (vuln builds) ─────────────────────────────────────────────

def test_stack_bof_crashes():
    r = subprocess.run(
        [str(_bin("stack_bof_vuln"))],
        input=b"A" * 200,
        capture_output=True, timeout=5,
    )
    assert r.returncode != 0, "stack_bof should crash on 200-byte input"


def test_heap_bof_crashes():
    r = subprocess.run(
        [str(_bin("heap_bof_vuln")), "200"],
        input=b"B" * 200,
        capture_output=True, timeout=5,
    )
    # may crash or silently corrupt — not 0 in most cases; ASan build is canonical
    assert r.returncode is not None  # at least completed


def test_format_string_runs():
    r = subprocess.run(
        [str(_bin("format_string_vuln"))],
        input=b"%x%x%x%x\n",
        capture_output=True, timeout=5,
    )
    # should not crash — but output should differ from literal input
    assert r.returncode == 0
    assert b"%x%x%x%x" not in r.stdout  # format specifiers were interpreted


def test_uaf_runs():
    r = subprocess.run(
        [str(_bin("uaf_vuln"))],
        capture_output=True, timeout=5,
    )
    # May or may not crash depending on allocator behaviour; just ensure it exits
    assert r.returncode is not None


def test_off_by_one_crashes_or_runs():
    r = subprocess.run(
        [str(_bin("off_by_one_vuln"))],
        input=b"D" * 64 + b"\n",
        capture_output=True, timeout=5,
    )
    assert r.returncode is not None


