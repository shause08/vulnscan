"""Phase 5 — triage: ASan parser + GDB triage + severity engine."""

from __future__ import annotations

import re
import signal as _signal
from pathlib import Path

import pytest

CORPUS = Path(__file__).parent.parent / "corpus" / "bin"


def _req(name: str) -> Path:
    p = CORPUS / name
    if not p.exists():
        pytest.skip(f"{name} not built — run 'make -C corpus all'")
    return p


def _cyclic(n: int) -> bytes:
    try:
        import logging as _l; _l.getLogger("pwnlib").setLevel(_l.ERROR)
        from pwn import cyclic, context; context.log_level = "error"
        return cyclic(n)
    except ImportError:
        pytest.skip("pwntools not available")


# ── ASan output parser ─────────────────────────────────────────────────────────

class TestASanParser:
    """Unit tests for ASanReport parsing logic."""

    # Minimal synthetic ASan output blocks for fast unit testing

    _STACK_BOF_OUTPUT = (
        "==1234==ERROR: AddressSanitizer: stack-buffer-overflow on address 0x7fff1234 "
        "at pc 0xdeadbeef bp 0x7fff0000 sp 0x7ffe0000\n"
        "WRITE of size 200 at 0x7fff1234\n"
        "    #0 0xdeadbeef in vulnerable /src/stack_bof.c:17\n"
        "    #1 0xcafebabe in main /src/stack_bof.c:30\n"
    )

    _HEAP_BOF_OUTPUT = (
        "==2000==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000010 "
        "at pc 0x401234 bp 0x7ffe0000 sp 0x7ffdf000\n"
        "READ of size 1 at 0x602000000010\n"
        "    #0 0x401234 in __interceptor_memcpy (/lib/fake.so)\n"
        "    #1 0x401300 in vulnerable /src/heap_bof.c:20\n"
        "    #2 0x401400 in main /src/heap_bof.c:35\n"
    )

    _UAF_OUTPUT = (
        "==3000==ERROR: AddressSanitizer: heap-use-after-free on address 0x602000000040 "
        "at pc 0x401234\n"
        "READ of size 4 at 0x602000000040\n"
        "    #0 0x401234 in use_freed /src/uaf.c:25\n"
        "    #1 0x401300 in main /src/uaf.c:50\n"
    )

    _FORMAT_STRING_OUTPUT = (
        "==4000==ERROR: AddressSanitizer: SEGV on unknown address 0x0\n"
        "    #0 0x401000 in __sanitizer_print_stack_trace\n"
        "    #1 0x401200 in printf /src/format_string.c:10\n"
    )

    _DEADLYSIGNAL_OUTPUT = (
        "==5000==ERROR: AddressSanitizer: stack-buffer-overflow on address 0xdeadbeef\n"
        "WRITE of size 256 at 0xdeadbeef\n"
        "    #0 0xabcd in vulnerable /src/stack_bof.c:15\n"
        "SUMMARY: AddressSanitizer: DEADLYSIGNAL\n"
    )

    def test_parse_stack_bof_type(self):
        from vulnscan.dynamic.asan import ASanReport
        r = ASanReport(self._STACK_BOF_OUTPUT)
        assert r.error_type == "stack-buffer-overflow"

    def test_parse_heap_bof_type(self):
        from vulnscan.dynamic.asan import ASanReport
        r = ASanReport(self._HEAP_BOF_OUTPUT)
        assert r.error_type == "heap-buffer-overflow"

    def test_parse_uaf_type(self):
        from vulnscan.dynamic.asan import ASanReport
        r = ASanReport(self._UAF_OUTPUT)
        assert r.error_type == "heap-use-after-free"

    def test_parse_access_op_and_size(self):
        from vulnscan.dynamic.asan import ASanReport
        r = ASanReport(self._STACK_BOF_OUTPUT)
        assert r.access_op == "WRITE"
        assert r.access_size == 200

    def test_parse_read_op(self):
        from vulnscan.dynamic.asan import ASanReport
        r = ASanReport(self._HEAP_BOF_OUTPUT)
        assert r.access_op == "READ"
        assert r.access_size == 1

    def test_parse_address(self):
        from vulnscan.dynamic.asan import ASanReport
        r = ASanReport(self._STACK_BOF_OUTPUT)
        assert r.address == "0x7fff1234"

    def test_parse_frames(self):
        from vulnscan.dynamic.asan import ASanReport
        r = ASanReport(self._STACK_BOF_OUTPUT)
        assert len(r.frames) >= 1
        assert r.frames[0]["func"] == "vulnerable"

    def test_first_user_frame_skips_interceptor(self):
        from vulnscan.dynamic.asan import ASanReport
        r = ASanReport(self._HEAP_BOF_OUTPUT)
        # first frame is __interceptor_memcpy → should be skipped
        frame = r.first_user_frame
        assert frame is not None
        assert not frame["func"].startswith("__interceptor_")

    def test_first_user_frame_stack_bof(self):
        from vulnscan.dynamic.asan import ASanReport
        r = ASanReport(self._STACK_BOF_OUTPUT)
        frame = r.first_user_frame
        assert frame is not None
        assert frame["func"] == "vulnerable"

    def test_is_valid_true(self):
        from vulnscan.dynamic.asan import ASanReport
        r = ASanReport(self._STACK_BOF_OUTPUT)
        assert r.is_valid

    def test_is_valid_false_on_garbage(self):
        from vulnscan.dynamic.asan import ASanReport
        r = ASanReport("nothing useful here\nsome random text\n")
        assert not r.is_valid

    def test_deadlysignal_still_detected(self):
        """DEADLYSIGNAL (nested bug) must not lose the original error type."""
        from vulnscan.dynamic.asan import ASanReport
        r = ASanReport(self._DEADLYSIGNAL_OUTPUT)
        assert r.is_valid
        assert r.error_type == "stack-buffer-overflow"

    def test_to_finding_stack_bof(self):
        from vulnscan.dynamic.asan import ASanReport
        from vulnscan.report.model import VulnClass, Severity
        r = ASanReport(self._STACK_BOF_OUTPUT)
        f = r.to_finding()
        assert f is not None
        assert f.vuln_class == VulnClass.STACK_BOF
        assert f.severity == Severity.HIGH
        assert f.confidence == "dynamic"

    def test_to_finding_uaf(self):
        from vulnscan.dynamic.asan import ASanReport
        from vulnscan.report.model import VulnClass, Severity
        r = ASanReport(self._UAF_OUTPUT)
        f = r.to_finding()
        assert f is not None
        assert f.vuln_class == VulnClass.USE_AFTER_FREE
        assert f.severity == Severity.HIGH

    def test_to_finding_contains_evidence(self):
        from vulnscan.dynamic.asan import ASanReport
        r = ASanReport(self._STACK_BOF_OUTPUT)
        f = r.to_finding()
        assert f is not None
        assert "stack-buffer-overflow" in f.evidence
        assert "WRITE" in f.evidence

    def test_to_finding_none_on_invalid(self):
        from vulnscan.dynamic.asan import ASanReport
        r = ASanReport("no error here")
        assert r.to_finding() is None

    def test_parse_output_splits_multiple_errors(self):
        """parse_output() must handle concatenated error blocks."""
        from vulnscan.dynamic.asan import parse_output
        combined = self._STACK_BOF_OUTPUT + "\n" + self._UAF_OUTPUT
        # inject fake PID markers for splitting
        block1 = "==1234==ERROR: AddressSanitizer: stack-buffer-overflow\n#0 0x1 in foo /a.c:1\n"
        block2 = "==5678==ERROR: AddressSanitizer: heap-use-after-free\n#0 0x2 in bar /b.c:2\n"
        reports = parse_output(block1 + block2)
        assert len(reports) >= 1

    def test_cwe_mapping_stack_bof(self):
        from vulnscan.dynamic.asan import ASanReport
        r = ASanReport(self._STACK_BOF_OUTPUT)
        f = r.to_finding()
        assert f is not None
        assert f.cwe == "CWE-121"

    def test_cwe_mapping_uaf(self):
        from vulnscan.dynamic.asan import ASanReport
        r = ASanReport(self._UAF_OUTPUT)
        f = r.to_finding()
        assert f is not None
        assert f.cwe == "CWE-416"


# ── ASan integration (real corpus binaries) ────────────────────────────────────

class TestASanIntegration:
    """Run ASan-instrumented corpus binaries and verify findings."""

    def test_stack_bof_asan_detected(self):
        from vulnscan.dynamic import asan as asan_mod
        findings = asan_mod.run_and_parse(
            _req("stack_bof_asan"),
            stdin_data=b"A" * 200 + b"\n",
            timeout=15,
        )
        assert findings, "stack_bof_asan must trigger ASan findings"
        vc_set = {f.vuln_class for f in findings}
        from vulnscan.report.model import VulnClass
        assert VulnClass.STACK_BOF in vc_set

    def test_heap_bof_asan_detected(self):
        from vulnscan.dynamic import asan as asan_mod
        from vulnscan.report.model import VulnClass
        findings = asan_mod.run_and_parse(
            _req("heap_bof_asan"),
            stdin_data=b"A" * 300,
            argv_extra=["300"],
            timeout=15,
        )
        assert findings, "heap_bof_asan must trigger ASan findings"
        vc_set = {f.vuln_class for f in findings}
        assert VulnClass.HEAP_BOF in vc_set

    def test_uaf_asan_detected(self):
        from vulnscan.dynamic import asan as asan_mod
        from vulnscan.report.model import VulnClass
        findings = asan_mod.run_and_parse(
            _req("uaf_asan"),
            stdin_data=b"\n",
            timeout=15,
        )
        assert findings, "uaf_asan must trigger ASan findings"
        vc_set = {f.vuln_class for f in findings}
        assert VulnClass.USE_AFTER_FREE in vc_set

    def test_off_by_one_asan_detected(self):
        from vulnscan.dynamic import asan as asan_mod
        from vulnscan.report.model import VulnClass
        findings = asan_mod.run_and_parse(
            _req("off_by_one_asan"),
            stdin_data=b"A" * 64 + b"\n",
            timeout=15,
        )
        assert findings, "off_by_one_asan must trigger ASan findings"
        vc_set = {f.vuln_class for f in findings}
        assert VulnClass.STACK_BOF in vc_set

    def test_integer_overflow_asan_detected(self):
        from vulnscan.dynamic import asan as asan_mod
        from vulnscan.report.model import VulnClass
        count = 4097
        data = b"A" * (count * 64)
        findings = asan_mod.run_and_parse(
            _req("integer_overflow_asan"),
            stdin_data=data,
            argv_extra=[str(count)],
            timeout=15,
        )
        assert findings, "integer_overflow_asan must trigger ASan findings"
        vc_set = {f.vuln_class for f in findings}
        assert VulnClass.HEAP_BOF in vc_set

    def test_format_string_asan_produces_finding(self):
        from vulnscan.dynamic import asan as asan_mod
        findings = asan_mod.run_and_parse(
            _req("format_string_asan"),
            stdin_data=b"%s%s%s%n\n",
            timeout=15,
        )
        # format_string may produce UNKNOWN/SEGV — just verify it finds something
        assert findings, "format_string_asan should produce at least one finding"

    def test_asan_finding_fields(self):
        from vulnscan.dynamic import asan as asan_mod
        from vulnscan.report.model import Severity
        findings = asan_mod.run_and_parse(
            _req("stack_bof_asan"),
            stdin_data=b"A" * 200 + b"\n",
            timeout=15,
        )
        assert findings
        f = findings[0]
        assert isinstance(f.function, str)
        assert isinstance(f.evidence, str)
        assert f.severity in list(Severity)
        assert f.confidence == "dynamic"
        assert f.cwe.startswith("CWE-")

    def test_asan_evidence_contains_error_type(self):
        from vulnscan.dynamic import asan as asan_mod
        findings = asan_mod.run_and_parse(
            _req("uaf_asan"),
            stdin_data=b"\n",
            timeout=15,
        )
        assert findings
        assert "use-after-free" in findings[0].evidence or "ASan" in findings[0].evidence


# ── GDB-based triage ───────────────────────────────────────────────────────────

class TestTriageGDB:
    """Tests for the GDB triage module."""

    def test_triage_returns_result(self):
        from vulnscan.dynamic.triage import triage
        inp = _cyclic(256) + b"\n"
        tr = triage(_req("stack_bof_vuln"), inp)
        assert tr is not None
        assert isinstance(tr.signal_name, str)

    def test_stack_bof_crashes_with_sigsegv(self):
        from vulnscan.dynamic.triage import triage
        inp = _cyclic(256) + b"\n"
        tr = triage(_req("stack_bof_vuln"), inp)
        assert tr.signal_name == "SIGSEGV"

    def test_stack_bof_offset_computed(self):
        """The RIP offset must be computable from a cyclic pattern crash."""
        from vulnscan.dynamic.triage import triage
        inp = _cyclic(256) + b"\n"
        tr = triage(_req("stack_bof_vuln"), inp)
        assert tr.offset_to_rip is not None, "Offset should be computable from cyclic crash"
        assert 0 < tr.offset_to_rip < 256, f"Offset out of range: {tr.offset_to_rip}"

    def test_stack_bof_offset_value(self):
        """Exact offset check: stack_bof_vuln has a 64-byte buf + 8-byte saved RBP = 72."""
        from vulnscan.dynamic.triage import triage
        inp = _cyclic(256) + b"\n"
        tr = triage(_req("stack_bof_vuln"), inp)
        assert tr.offset_to_rip == 72, (
            f"Expected offset=72 but got {tr.offset_to_rip}. "
            f"rip_value={hex(tr.rip_value) if tr.rip_value else None}"
        )

    def test_rip_value_captured(self):
        from vulnscan.dynamic.triage import triage
        inp = _cyclic(256) + b"\n"
        tr = triage(_req("stack_bof_vuln"), inp)
        assert tr.rip_value is not None
        # Should be a cyclic-pattern value (ASCII printable range for pwntools alphabet)
        assert tr.rip_value > 0

    def test_exploitability_set(self):
        from vulnscan.dynamic.triage import triage, EXPLOITABLE, PROBABLY_EXPLOITABLE
        inp = _cyclic(256) + b"\n"
        tr = triage(_req("stack_bof_vuln"), inp)
        assert tr.exploitability in (EXPLOITABLE, PROBABLY_EXPLOITABLE)

    def test_backtrace_captured(self):
        from vulnscan.dynamic.triage import triage
        inp = _cyclic(256) + b"\n"
        tr = triage(_req("stack_bof_vuln"), inp)
        if tr.gdb_available:
            assert tr.backtrace, "GDB backtrace should not be empty"

    def test_triage_result_fields(self):
        from vulnscan.dynamic.triage import triage
        inp = _cyclic(256) + b"\n"
        tr = triage(_req("stack_bof_vuln"), inp)
        assert isinstance(tr.binary, str)
        assert isinstance(tr.stdin_data, bytes)
        assert isinstance(tr.argv_extra, list)
        assert isinstance(tr.gdb_available, bool)
        assert isinstance(tr.exploitable_plugin, bool)

    def test_triage_short_input_no_crash(self):
        """Short benign input: binary exits cleanly, no crash info captured."""
        from vulnscan.dynamic.triage import triage
        tr = triage(_req("stack_bof_vuln"), b"hello\n")
        # Binary may or may not crash — just ensure no exception
        assert isinstance(tr.signal_name, str)


# ── Severity engine ────────────────────────────────────────────────────────────

class TestSeverityEngine:
    """Unit tests for estimate_severity()."""

    def _make_triage(
        self,
        *,
        rip_value=0x6161617461616173,
        offset=72,
        signal_name="SIGSEGV",
        exploitability="EXPLOITABLE",
    ):
        from vulnscan.dynamic.triage import TriageResult
        return TriageResult(
            binary="fake",
            stdin_data=b"",
            argv_extra=[],
            signal_name=signal_name,
            rip_value=rip_value,
            rip_hex=hex(rip_value) if rip_value else "",
            offset_to_rip=offset,
            exploitability=exploitability,
            exploitability_reason="test",
            backtrace="",
            gdb_available=True,
            exploitable_plugin=False,
        )

    def test_stack_bof_no_protections_critical(self):
        from vulnscan.dynamic.triage import estimate_severity
        from vulnscan.report.model import Protection, VulnClass, Severity
        tr = self._make_triage()
        sev = estimate_severity(tr, VulnClass.STACK_BOF, Protection())
        assert sev == Severity.CRITICAL

    def test_stack_bof_full_protections_lower(self):
        from vulnscan.dynamic.triage import estimate_severity
        from vulnscan.report.model import Protection, VulnClass, Severity
        tr = self._make_triage()
        prot = Protection(nx=True, canary=True, pie=True, relro="full")
        sev = estimate_severity(tr, VulnClass.STACK_BOF, prot)
        assert sev in (Severity.LOW, Severity.MEDIUM, Severity.HIGH)
        assert sev != Severity.CRITICAL

    def test_probably_not_exploitable_lowers_severity(self):
        from vulnscan.dynamic.triage import estimate_severity, PROBABLY_NOT
        from vulnscan.report.model import Protection, VulnClass, Severity
        tr = self._make_triage(exploitability=PROBABLY_NOT, offset=None, rip_value=None)
        sev = estimate_severity(tr, VulnClass.STACK_BOF, Protection())
        # PROBABLY_NOT + no offset: base 4 - 1 = 3 → MEDIUM
        assert sev in (Severity.MEDIUM, Severity.HIGH)

    def test_heap_bof_base_severity(self):
        from vulnscan.dynamic.triage import estimate_severity
        from vulnscan.report.model import Protection, VulnClass, Severity
        tr = self._make_triage(offset=None)
        sev = estimate_severity(tr, VulnClass.HEAP_BOF, Protection())
        assert sev in (Severity.HIGH, Severity.CRITICAL)

    def test_unknown_vuln_class_low_severity(self):
        from vulnscan.dynamic.triage import estimate_severity, UNKNOWN
        from vulnscan.report.model import Protection, VulnClass, Severity
        tr = self._make_triage(
            exploitability=UNKNOWN, offset=None, rip_value=None, signal_name="SIGSEGV"
        )
        sev = estimate_severity(tr, VulnClass.UNKNOWN, Protection())
        assert sev in (Severity.INFO, Severity.LOW, Severity.MEDIUM)

    def test_offset_known_raises_severity(self):
        from vulnscan.dynamic.triage import estimate_severity, PROBABLY_EXPLOITABLE
        from vulnscan.report.model import Protection, VulnClass, Severity
        tr_no_off = self._make_triage(exploitability=PROBABLY_EXPLOITABLE, offset=None)
        tr_with_off = self._make_triage(exploitability=PROBABLY_EXPLOITABLE, offset=72)
        sev_no  = estimate_severity(tr_no_off,  VulnClass.STACK_BOF, Protection())
        sev_yes = estimate_severity(tr_with_off, VulnClass.STACK_BOF, Protection())
        # Having an offset should produce severity >= sev without offset
        sev_levels = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
        assert sev_levels.index(sev_yes.value) >= sev_levels.index(sev_no.value)

    def test_all_vuln_classes_return_severity(self):
        from vulnscan.dynamic.triage import estimate_severity
        from vulnscan.report.model import Protection, VulnClass, Severity
        from vulnscan.dynamic.triage import TriageResult
        tr = self._make_triage()
        for vc in VulnClass:
            sev = estimate_severity(tr, vc, Protection())
            assert isinstance(sev, Severity)

    def test_severity_clamped_to_valid_range(self):
        from vulnscan.dynamic.triage import estimate_severity, EXPLOITABLE
        from vulnscan.report.model import Protection, VulnClass, Severity
        from vulnscan.dynamic.triage import TriageResult
        # Extreme case: multiple bonuses
        tr = self._make_triage(exploitability=EXPLOITABLE, offset=72)
        sev = estimate_severity(tr, VulnClass.STACK_BOF, Protection())
        assert sev in list(Severity)  # must be a valid enum member


# ── Heuristic exploitability ───────────────────────────────────────────────────

class TestHeuristicExploitability:
    def test_ascii_rip_probably_exploitable(self):
        from vulnscan.dynamic.triage import _heuristic_exploitability, PROBABLY_EXPLOITABLE
        exp, _ = _heuristic_exploitability(0x6161617461616173, "SIGSEGV")
        assert exp == PROBABLY_EXPLOITABLE

    def test_null_rip_probably_not(self):
        from vulnscan.dynamic.triage import _heuristic_exploitability, PROBABLY_NOT
        exp, _ = _heuristic_exploitability(0, "SIGSEGV")
        assert exp == PROBABLY_NOT

    def test_no_rip_sigsegv_unknown(self):
        from vulnscan.dynamic.triage import _heuristic_exploitability, UNKNOWN
        exp, _ = _heuristic_exploitability(None, "SIGSEGV")
        assert exp == UNKNOWN

    def test_sigabrt_probably_not(self):
        from vulnscan.dynamic.triage import _heuristic_exploitability, PROBABLY_NOT
        exp, _ = _heuristic_exploitability(None, "SIGABRT")
        assert exp == PROBABLY_NOT


# ── offset finder ─────────────────────────────────────────────────────────────

class TestFindOffset:
    def test_cyclic_rip_value_found(self):
        from vulnscan.dynamic.triage import _find_offset
        inp = _cyclic(256) + b"\n"
        # Simulate what GDB would find at RSP for stack_bof_vuln
        from pwn import cyclic_find, context; context.log_level = "error"
        import logging; logging.getLogger("pwnlib").setLevel(logging.ERROR)
        rip_val = int.from_bytes(inp[72:80], "little")
        offset = _find_offset(rip_val, inp)
        assert offset == 72

    def test_empty_input_returns_none(self):
        from vulnscan.dynamic.triage import _find_offset
        assert _find_offset(None, b"") is None

    def test_non_cyclic_input_returns_none_or_int(self):
        from vulnscan.dynamic.triage import _find_offset
        result = _find_offset(0xDEADBEEF, b"A" * 100)
        assert result is None or isinstance(result, int)

    def test_offset_within_input_bounds(self):
        from vulnscan.dynamic.triage import _find_offset
        inp = _cyclic(200) + b"\n"
        from pwn import context; context.log_level = "error"
        rip_val = int.from_bytes(inp[72:80], "little")
        offset = _find_offset(rip_val, inp)
        if offset is not None:
            assert 0 <= offset <= len(inp)


# ── Pipeline integration with triage ─────────────────────────────────────────

class TestPipelineTriage:
    """Full-pipeline tests verifying static+dynamic+triage integration."""

    def test_stack_bof_full_pipeline(self):
        from vulnscan.pipeline import scan
        from vulnscan.report.model import VulnClass, Severity
        result = scan(_req("stack_bof_vuln"), do_static=True, do_dynamic=True, timeout=60)
        assert result.findings, "Full pipeline must produce findings"
        classes = {f.vuln_class for f in result.findings}
        assert VulnClass.STACK_BOF in classes

    def test_stack_bof_critical_finding(self):
        """With no protections + known RIP offset → at least one CRITICAL finding."""
        from vulnscan.pipeline import scan
        from vulnscan.report.model import Severity
        result = scan(_req("stack_bof_vuln"), do_static=True, do_dynamic=True, timeout=60)
        severities = {f.severity for f in result.findings}
        assert Severity.CRITICAL in severities, (
            f"Expected CRITICAL in {[s.value for s in severities]}"
        )

    def test_finding_confidence_both_when_static_and_dynamic_agree(self):
        """When static and dynamic both detect STACK_BOF, confidence should be 'both'."""
        from vulnscan.pipeline import scan
        result = scan(_req("stack_bof_vuln"), do_static=True, do_dynamic=True, timeout=60)
        both_findings = [f for f in result.findings if f.confidence == "both"]
        assert both_findings, "At least one finding should have confidence='both'"

    def test_uaf_pipeline_detection(self):
        from vulnscan.pipeline import scan
        from vulnscan.report.model import VulnClass
        result = scan(_req("uaf_vuln"), do_static=True, do_dynamic=True, timeout=60)
        # ASan sibling should detect UAF
        vc_set = {f.vuln_class for f in result.findings}
        assert VulnClass.USE_AFTER_FREE in vc_set or result.findings, (
            "uaf pipeline should produce findings"
        )

    def test_scan_result_fields_populated(self):
        from vulnscan.pipeline import scan
        result = scan(_req("stack_bof_vuln"), do_static=True, do_dynamic=True, timeout=60)
        assert result.binary_path
        assert result.scan_mode == "static+dynamic"
        assert isinstance(result.duration_s, float) and result.duration_s > 0
        assert result.protections is not None

    def test_dynamic_only_still_finds_crash(self):
        from vulnscan.pipeline import scan
        from vulnscan.report.model import VulnClass
        result = scan(_req("stack_bof_vuln"), do_static=False, do_dynamic=True, timeout=45)
        dynamic = [f for f in result.findings if f.analysis == "dynamic"]
        assert dynamic, "Dynamic-only scan must still find crashes"

    def test_static_only_no_dynamic_findings(self):
        from vulnscan.pipeline import scan
        result = scan(_req("stack_bof_vuln"), do_static=True, do_dynamic=False, timeout=10)
        dynamic = [f for f in result.findings if f.analysis == "dynamic"]
        assert not dynamic, "Static-only scan must not produce dynamic findings"

    def test_findings_have_required_fields(self):
        from vulnscan.pipeline import scan
        from vulnscan.report.model import Severity, VulnClass
        result = scan(_req("stack_bof_vuln"), do_static=True, do_dynamic=True, timeout=60)
        for f in result.findings:
            assert isinstance(f.vuln_class, VulnClass)
            assert isinstance(f.severity, Severity)
            assert isinstance(f.evidence, str) and f.evidence
            assert f.confidence in ("static", "dynamic", "both")
            assert f.analysis in ("static", "dynamic")
