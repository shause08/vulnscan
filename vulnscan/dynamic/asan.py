"""AddressSanitizer output parser.

Parses the stderr of ASan-instrumented binaries and maps each error type to
a VulnClass + rich Finding with the call stack as evidence.

Supported ASan error types
--------------------------
  stack-buffer-overflow
  heap-buffer-overflow
  heap-use-after-free
  global-buffer-overflow
  stack-use-after-return
  use-after-poison
  double-free
  alloc-dealloc-mismatch
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Optional

from vulnscan.dynamic.runner import RunResult, run_asan
from vulnscan.report.model import Finding, Severity, VulnClass
from vulnscan.utils.logging import get_logger

logger = get_logger(__name__)

# ── ASan error type → (VulnClass, base_severity) ────────────────────────────

_TYPE_MAP: dict[str, tuple[VulnClass, Severity]] = {
    "stack-buffer-overflow":    (VulnClass.STACK_BOF,      Severity.HIGH),
    "heap-buffer-overflow":     (VulnClass.HEAP_BOF,       Severity.HIGH),
    "heap-use-after-free":      (VulnClass.USE_AFTER_FREE,  Severity.HIGH),
    "global-buffer-overflow":   (VulnClass.STACK_BOF,      Severity.MEDIUM),
    "stack-buffer-underflow":   (VulnClass.STACK_BOF,      Severity.MEDIUM),
    "stack-use-after-return":   (VulnClass.USE_AFTER_FREE,  Severity.MEDIUM),
    "use-after-poison":         (VulnClass.USE_AFTER_FREE,  Severity.MEDIUM),
    "double-free":              (VulnClass.USE_AFTER_FREE,  Severity.HIGH),
    "alloc-dealloc-mismatch":   (VulnClass.USE_AFTER_FREE,  Severity.MEDIUM),
    "attempting free on address which was not malloc()-ed":
                                (VulnClass.USE_AFTER_FREE,  Severity.MEDIUM),
    # Segfault triggered by format-string %s / %n — the crash IS the bug
    "segv":                     (VulnClass.UNKNOWN,         Severity.MEDIUM),
    "deadly signal":            (VulnClass.STACK_BOF,       Severity.HIGH),
}

# ── Regex patterns ────────────────────────────────────────────────────────────

_RE_ERROR   = re.compile(r"ERROR: AddressSanitizer: ([\w-]+)", re.IGNORECASE)
_RE_ACCESS  = re.compile(r"(READ|WRITE) of size (\d+)", re.IGNORECASE)
_RE_FRAME   = re.compile(r"#(\d+)\s+0x[0-9a-f]+ in (\S+)\s+(.+)")
_RE_ADDR    = re.compile(r"on address (0x[0-9a-f]+)", re.IGNORECASE)
_RE_FILELINE= re.compile(r"(\S+):(\d+)")


class ASanReport:
    """Structured representation of one ASan error."""

    def __init__(self, raw: str) -> None:
        self.raw = raw
        self.error_type: str = ""
        self.access_op: str = ""      # "READ" | "WRITE" | ""
        self.access_size: int = 0
        self.address: str = ""
        self.frames: list[dict] = []  # [{idx, func, location}, …]
        self._parse()

    def _parse(self) -> None:
        m = _RE_ERROR.search(self.raw)
        if m:
            self.error_type = m.group(1).lower()
        # Handle "nested bug" / DEADLYSIGNAL — still a valid error report
        if not self.error_type and "DEADLYSIGNAL" in self.raw:
            # Re-scan for the initial error type before DEADLYSIGNAL
            m2 = re.search(r"ERROR: AddressSanitizer: ([\w-]+)", self.raw)
            if m2:
                self.error_type = m2.group(1).lower()

        m = _RE_ACCESS.search(self.raw)
        if m:
            self.access_op   = m.group(1).upper()
            self.access_size = int(m.group(2))

        m = _RE_ADDR.search(self.raw)
        if m:
            self.address = m.group(1)

        for m in _RE_FRAME.finditer(self.raw):
            loc = m.group(3).strip()
            # Strip ASAN_OPTIONS colour codes / parentheses
            loc = re.sub(r"\x1b\[[0-9;]*m", "", loc)
            self.frames.append({
                "idx":      int(m.group(1)),
                "func":     m.group(2),
                "location": loc,
            })

    @property
    def is_valid(self) -> bool:
        return bool(self.error_type)

    @property
    def first_user_frame(self) -> Optional[dict]:
        """First stack frame NOT in ASan/libc internals."""
        skip_prefixes = (
            "__interceptor_", "__sanitizer_", "__asan_", "_asan_", "asan_",
            "__libc_", "__GI_", "libc_",
        )
        skip_exact = {"??", "<unknown>"}
        for f in self.frames:
            fn = f["func"]
            if not any(fn.startswith(s) for s in skip_prefixes) and fn not in skip_exact:
                return f
        # Fall back to first non-sanitizer frame
        for f in self.frames:
            fn = f["func"]
            if not any(fn.startswith(s) for s in skip_prefixes):
                return f
        return self.frames[0] if self.frames else None

    def to_finding(self) -> Optional[Finding]:
        if not self.is_valid:
            return None

        vc, base_sev = _TYPE_MAP.get(
            self.error_type,
            (VulnClass.UNKNOWN, Severity.MEDIUM),
        )

        frame = self.first_user_frame
        func  = frame["func"] if frame else "<unknown>"
        loc   = frame["location"] if frame else ""

        op_desc = (f"{self.access_op} of {self.access_size}B" if self.access_op
                   else "access")
        lines = [f"ASan: {self.error_type}"]
        lines.append(f"operation : {op_desc}" + (f" at {self.address}" if self.address else ""))
        if frame:
            lines.append(f"in {func}() ({loc})")
        # Include first 3 user-visible frames as backtrace
        skip_prefixes = ("__interceptor_", "__sanitizer_", "__asan_", "_asan_",
                         "asan_", "__libc_", "__GI_", "libc_")
        user_frames = [
            f for f in self.frames
            if not any(f["func"].startswith(s) for s in skip_prefixes)
        ][:3]
        if user_frames:
            lines.append("backtrace :")
            for fr in user_frames:
                lines.append(f"  #{fr['idx']} {fr['func']} ({fr['location']})")
        evidence = "\n".join(lines)

        return Finding(
            vuln_class=vc,
            function=func,
            location=loc or self.address,
            severity=base_sev,
            confidence="dynamic",
            analysis="dynamic",
            evidence=evidence,
            cwe=_cwe(vc),
        )


def parse_output(text: str) -> list[ASanReport]:
    """Split multi-error ASan output into individual ASanReport objects."""
    # Each error block starts with "==PID==ERROR:"
    blocks = re.split(r"(?====\d+==ERROR:)", text)
    reports = []
    for block in blocks:
        if "ERROR:" in block:
            r = ASanReport(block)
            if r.is_valid:
                reports.append(r)
    return reports


def run_and_parse(
    binary_path: Path,
    *,
    stdin_data: bytes = b"",
    argv_extra: list[str] | None = None,
    timeout: int = 15,
) -> list[Finding]:
    """Run the ASan build of *binary_path* and return Findings from its output."""
    result: RunResult = run_asan(
        binary_path,
        stdin_data=stdin_data,
        argv_extra=argv_extra,
        timeout=timeout,
    )
    combined = (result.stdout + result.stderr).decode(errors="replace")
    reports   = parse_output(combined)
    findings  = [r.to_finding() for r in reports]
    return [f for f in findings if f is not None]


# ── helpers ───────────────────────────────────────────────────────────────────

def _cwe(vc: VulnClass) -> str:
    return {
        VulnClass.STACK_BOF:     "CWE-121",
        VulnClass.HEAP_BOF:      "CWE-122",
        VulnClass.USE_AFTER_FREE:"CWE-416",
        VulnClass.FORMAT_STRING: "CWE-134",
        VulnClass.OFF_BY_ONE:    "CWE-193",
    }.get(vc, "CWE-unknown")
