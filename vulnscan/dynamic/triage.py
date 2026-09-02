"""Crash triage: GDB batch analysis, exploitability classification, offset finding.

Workflow
--------
1. Write the crashing input to a temp file.
2. Run GDB in --batch mode with a script that:
     - Runs the binary with stdin redirected from the temp file
     - Captures registers (rip, rbp, rsp) at crash time
     - Tries to run the `exploitable` CERT plugin if available
     - Prints a backtrace
3. Parse GDB output to extract:
     - The crashing RIP value
     - Whether that value looks like a cyclic pattern (→ offset computable)
     - The exploitability verdict from `exploitable` (if present)
4. If RIP contains cyclic-pattern bytes, call `pwn.cyclic_find` to compute
   the exact offset from input start to saved return address.
5. Return a TriageResult consumed by the severity engine.

Fallback (no GDB or no exploitable plugin)
-------------------------------------------
Parse the signal number and the crash address from the RunResult. If the
crash address looks like a cyclic-pattern value we can still compute the
offset. Classify as UNKNOWN exploitability.
"""

from __future__ import annotations

import dataclasses
import re
import struct
import tempfile
import os
from pathlib import Path
from typing import Optional

from vulnscan.utils.logging import get_logger
from vulnscan.utils.shell import run as shell_run

logger = get_logger(__name__)

# Exploitability ratings (CERT exploitable plugin vocabulary)
EXPLOITABLE           = "EXPLOITABLE"
PROBABLY_EXPLOITABLE  = "PROBABLY_EXPLOITABLE"
PROBABLY_NOT          = "PROBABLY_NOT_EXPLOITABLE"
UNKNOWN               = "UNKNOWN"

_RE_RIP     = re.compile(r"rip\s+(0x[0-9a-f]+)", re.IGNORECASE)
_RE_SIGSEGV = re.compile(r"Program received signal (SIG\w+)", re.IGNORECASE)
_RE_EXPLOIT = re.compile(
    r"(EXPLOITABLE|PROBABLY_EXPLOITABLE|PROBABLY_NOT_EXPLOITABLE|NOT_EXPLOITABLE|UNKNOWN)",
    re.IGNORECASE,
)
_RE_REASON  = re.compile(r"Exploitability Classification: (\w+)\s*\nDescription: (.+)")


@dataclasses.dataclass
class TriageResult:
    binary: str
    stdin_data: bytes
    argv_extra: list[str]
    signal_name: str
    rip_value: Optional[int]           # RIP at crash (None if unknown)
    rip_hex: str                       # "0xdeadbeef" or ""
    offset_to_rip: Optional[int]       # bytes from input start to saved RIP
    exploitability: str                # one of the constants above
    exploitability_reason: str
    backtrace: str                     # first 5 frames as text
    gdb_available: bool
    exploitable_plugin: bool


def triage(
    binary_path: Path,
    crash_input: bytes,
    *,
    argv_extra: list[str] | None = None,
    timeout: int = 20,
) -> TriageResult:
    """Triage a crash: run GDB, extract RIP, compute offset, classify."""
    gdb_ok = _gdb_available()

    if gdb_ok:
        return _triage_gdb(binary_path, crash_input, argv_extra or [], timeout)
    else:
        logger.warning("GDB not found — falling back to signal-only triage")
        return _triage_fallback(binary_path, crash_input, argv_extra or [])


# ── GDB-based triage ─────────────────────────────────────────────────────────

def _triage_gdb(
    binary_path: Path,
    crash_input: bytes,
    argv_extra: list[str],
    timeout: int,
) -> TriageResult:
    with tempfile.NamedTemporaryFile(delete=False, suffix=".crash_input") as tf:
        tf.write(crash_input)
        input_file = tf.name

    try:
        gdb_script = _build_gdb_script(str(binary_path), input_file, argv_extra)
        with tempfile.NamedTemporaryFile(
            mode="w", delete=False, suffix=".gdb", encoding="utf-8"
        ) as sf:
            sf.write(gdb_script)
            script_file = sf.name

        result = shell_run(
            ["gdb", "--batch", "-x", script_file],
            timeout=timeout,
            limit_resources=False,
        )
        output = (result.stdout + result.stderr).decode(errors="replace")
        logger.debug("GDB output (%d chars):\n%s", len(output), output[:800])
    except Exception as exc:
        logger.warning("GDB execution failed: %s", exc)
        output = ""
    finally:
        for f in [input_file, script_file]:
            try:
                os.unlink(f)
            except OSError:
                pass

    return _parse_gdb_output(str(binary_path), crash_input, argv_extra, output)


def _build_gdb_script(binary: str, input_file: str, argv_extra: list[str]) -> str:
    argv_str = " ".join(argv_extra)
    has_exploitable = _exploitable_available()
    lines = [
        "set pagination off",
        "set disassembly-flavor intel",
        "set confirm off",
        f'file "{binary}"',
        f"set args {argv_str}",
        f'run < "{input_file}"',
        "echo ===REGISTERS===\\n",
        "info registers rip rbp rsp",
        "echo ===BACKTRACE===\\n",
        "backtrace 8",
    ]
    lines += [
        "echo ===STACK_TOP===\\n",
        # Print the 8 bytes at RSP — this is the (possibly corrupted) return address
        "x/2xg $rsp",
    ]
    if has_exploitable:
        lines += [
            "echo ===EXPLOITABLE===\\n",
            "exploitable -v",
        ]
    lines.append("quit")
    return "\n".join(lines) + "\n"


def _parse_gdb_output(
    binary: str,
    crash_input: bytes,
    argv_extra: list[str],
    output: str,
) -> TriageResult:
    # Signal
    m = _RE_SIGSEGV.search(output)
    signal_name = m.group(1) if m else ""

    # RIP value — prefer value at RSP (corrupted return address) over current RIP
    rip_value: Optional[int] = None
    rip_hex = ""
    _re_xg = re.compile(r"0x[0-9a-f]+\s*:\s*(0x[0-9a-f]+)")

    # Try to extract the value popped by ret from the stack_top section
    if "===STACK_TOP===" in output:
        stack_section = output.split("===STACK_TOP===", 1)[1].split("===", 1)[0]
        m = _re_xg.search(stack_section)
        if m:
            rip_hex = m.group(1)
            try:
                rip_value = int(rip_hex, 16)
            except ValueError:
                pass

    # Fall back to the RIP register value
    if rip_value is None and "===REGISTERS===" in output:
        reg_section = output.split("===REGISTERS===", 1)[1].split("===", 1)[0]
        m = _RE_RIP.search(reg_section)
        if m:
            rip_hex = m.group(1)
            try:
                rip_value = int(rip_hex, 16)
            except ValueError:
                pass

    # Backtrace
    bt = ""
    if "===BACKTRACE===" in output:
        bt = output.split("===BACKTRACE===", 1)[1].split("===", 1)[0].strip()

    # Exploitability
    exploitability = UNKNOWN
    exploit_reason = ""
    has_plugin = _exploitable_available()
    if has_plugin and "===EXPLOITABLE===" in output:
        exp_section = output.split("===EXPLOITABLE===", 1)[1]
        m = _RE_EXPLOIT.search(exp_section)
        if m:
            exploitability = m.group(1).upper()
        m = _RE_REASON.search(exp_section)
        if m:
            exploit_reason = m.group(2).strip()
    else:
        # Heuristic: if RIP looks like a cyclic pattern → probably exploitable
        exploitability, exploit_reason = _heuristic_exploitability(rip_value, signal_name)

    # Offset calculation via cyclic_find
    offset = _find_offset(rip_value, crash_input)

    return TriageResult(
        binary=binary,
        stdin_data=crash_input,
        argv_extra=argv_extra,
        signal_name=signal_name,
        rip_value=rip_value,
        rip_hex=rip_hex,
        offset_to_rip=offset,
        exploitability=exploitability,
        exploitability_reason=exploit_reason,
        backtrace=bt[:1000],
        gdb_available=True,
        exploitable_plugin=has_plugin,
    )


# ── Fallback (no GDB) ─────────────────────────────────────────────────────────

def _triage_fallback(
    binary_path: Path,
    crash_input: bytes,
    argv_extra: list[str],
) -> TriageResult:
    offset = _find_offset(None, crash_input)
    exploitability, reason = _heuristic_exploitability(None, "")
    return TriageResult(
        binary=str(binary_path),
        stdin_data=crash_input,
        argv_extra=argv_extra,
        signal_name="",
        rip_value=None,
        rip_hex="",
        offset_to_rip=offset,
        exploitability=exploitability,
        exploitability_reason=reason,
        backtrace="",
        gdb_available=False,
        exploitable_plugin=False,
    )


# ── Offset calculation ────────────────────────────────────────────────────────

def _find_offset(rip_value: Optional[int], crash_input: bytes) -> Optional[int]:
    """Try to compute the offset from crash_input start to saved RIP.

    Uses pwntools cyclic_find if the RIP value looks like a cyclic pattern.
    Falls back to a brute-force search in the raw input bytes.
    """
    if not crash_input:
        return None

    try:
        import logging as _l
        _l.getLogger("pwnlib").setLevel(_l.ERROR)
        from pwn import cyclic_find, cyclic, context
        context.log_level = "error"

        # Try RIP value directly (little-endian 4-byte lookup in cyclic alphabet)
        if rip_value is not None:
            try:
                # cyclic_find accepts int (4-byte) or bytes (4-byte subsequence)
                offset = cyclic_find(rip_value & 0xFFFFFFFF)
                if 0 <= offset <= len(crash_input):
                    logger.debug("cyclic_find(0x%x) → offset=%d", rip_value, offset)
                    return offset
            except Exception:
                pass

        # Search the input for a 4-byte cyclic subsequence that appears in it
        pattern_len = len(crash_input)
        try:
            pat = cyclic(pattern_len)
        except Exception:
            return None

        # Find where the first cyclic character appears in crash_input
        for i in range(len(crash_input) - 4):
            chunk = crash_input[i: i + 4]
            try:
                off = cyclic_find(chunk)
                if 0 <= off < pattern_len:
                    return off
            except Exception:
                continue

    except ImportError:
        pass

    return None


# ── Exploitability heuristics ─────────────────────────────────────────────────

def _heuristic_exploitability(
    rip_value: Optional[int],
    signal_name: str,
) -> tuple[str, str]:
    """Classify exploitability without the exploitable plugin."""
    if rip_value is not None:
        # RIP is in the cyclic-pattern alphabet range → attacker controlled
        high_byte = (rip_value >> 24) & 0xFF
        if 0x40 <= high_byte <= 0x7A:  # ASCII printable range
            return PROBABLY_EXPLOITABLE, "RIP contains ASCII bytes — likely attacker-controlled"
        if rip_value == 0 or rip_value > 0x7FFFFFFFFFFF:
            return PROBABLY_NOT, "RIP is null/kernel-space — likely NULL dereference"
        return PROBABLY_EXPLOITABLE, "RIP redirected — potential control-flow hijack"
    if signal_name in ("SIGSEGV", "SIGBUS"):
        return UNKNOWN, "Crash without register data — assume potentially exploitable"
    if signal_name == "SIGABRT":
        return PROBABLY_NOT, "SIGABRT usually from assertion/abort — not directly exploitable"
    return UNKNOWN, ""


# ── Severity engine ───────────────────────────────────────────────────────────

def estimate_severity(
    triage: TriageResult,
    vuln_class: "VulnClass",
    protections: "Protection",
) -> "Severity":
    """Combine triage + vuln_class + protections into a Severity level.

    Scale documented in docs/algorithmes.md.
    """
    from vulnscan.report.model import Severity, VulnClass

    exploit = triage.exploitability
    has_offset = triage.offset_to_rip is not None

    # Base score by class
    base = {
        VulnClass.STACK_BOF:      4,
        VulnClass.HEAP_BOF:       3,
        VulnClass.FORMAT_STRING:  3,
        VulnClass.USE_AFTER_FREE: 3,
        VulnClass.INTEGER_OVERFLOW: 2,
        VulnClass.OFF_BY_ONE:     2,
        VulnClass.UNKNOWN:        1,
    }.get(vuln_class, 1)

    # Adjust for exploitability
    if exploit == EXPLOITABLE:
        base += 2
    elif exploit == PROBABLY_EXPLOITABLE:
        base += 1
    elif exploit == PROBABLY_NOT:
        base -= 1

    # Offset known → more precise (more dangerous)
    if has_offset:
        base += 1

    # Mitigations present → lower score
    if protections.canary:
        base -= 1
    if protections.nx:
        base -= 1
    if protections.pie:
        base -= 1
    if protections.relro == "full":
        base -= 1

    # Clamp to [1, 5] and map to Severity
    base = max(1, min(5, base))
    return [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL][base - 1]


# ── Utilities ─────────────────────────────────────────────────────────────────

def _gdb_available() -> bool:
    import shutil
    return shutil.which("gdb") is not None


def _exploitable_available() -> bool:
    """Check if the CERT exploitable GDB plugin is installed."""
    if not _gdb_available():
        return False
    try:
        result = shell_run(
            ["gdb", "--batch", "-ex", "source /usr/share/exploitable/exploitable.py",
             "-ex", "quit"],
            timeout=5, limit_resources=False,
        )
        return result.returncode == 0
    except Exception:
        pass
    # Also check common alternative paths
    import os
    paths = [
        os.path.expanduser("~/.gdb/exploitable/exploitable.py"),
        "/usr/lib/debug/exploitable.py",
    ]
    return any(os.path.exists(p) for p in paths)
