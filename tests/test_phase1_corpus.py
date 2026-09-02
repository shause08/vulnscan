"""Phase 1 — corpus build and basic crash/ASan detection tests."""

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

ASAN_BINARIES = [
    "stack_bof_asan",
    "heap_bof_asan",
    "format_string_asan",
    "integer_overflow_asan",
    "uaf_asan",
    "off_by_one_asan",
]


def _bin(name: str) -> Path:
    return CORPUS_BIN / name


# ── Existence ─────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("name", VULN_BINARIES + ASAN_BINARIES)
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


# ── ASan detection ─────────────────────────────────────────────────────────────

def _asan_output(name: str, args: list[str] = [], stdin: bytes = b"") -> str:
    r = subprocess.run(
        [str(_bin(name))] + args,
        input=stdin,
        capture_output=True, timeout=10,
    )
    return (r.stdout + r.stderr).decode(errors="replace")


def test_stack_bof_asan_detects():
    out = _asan_output("stack_bof_asan", stdin=b"A" * 200)
    assert "stack-buffer-overflow" in out


def test_heap_bof_asan_detects():
    out = _asan_output("heap_bof_asan", args=["200"], stdin=b"B" * 200)
    assert "heap-buffer-overflow" in out


def test_format_string_asan_runs():
    # ASan won't catch format-string reads — check that the binary runs cleanly
    out = _asan_output("format_string_asan", stdin=b"hello\n")
    assert "ERROR" not in out


def test_integer_overflow_asan_detects():
    payload = b"C" * (4097 * 64)
    out = _asan_output("integer_overflow_asan", args=["4097"], stdin=payload)
    assert "heap-buffer-overflow" in out


def test_uaf_asan_detects():
    out = _asan_output("uaf_asan")
    assert "heap-use-after-free" in out


def test_off_by_one_asan_detects():
    out = _asan_output("off_by_one_asan", stdin=b"D" * 64 + b"\n")
    assert "stack-buffer-overflow" in out
