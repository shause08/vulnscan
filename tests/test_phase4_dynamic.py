"""Phase 4 — dynamic analysis: runner and fuzzer."""

import subprocess
import signal
from pathlib import Path
import pytest

CORPUS = Path(__file__).parent.parent / "corpus" / "bin"


def _req(name: str) -> Path:
    p = CORPUS / name
    if not p.exists():
        pytest.skip(f"{name} not built — run 'make -C corpus all'")
    return p


# ── runner ─────────────────────────────────────────────────────────────────────

class TestRunner:
    def test_clean_exit(self):
        from vulnscan.dynamic.runner import run
        r = run(_req("format_string_vuln"), stdin_data=b"hello\n", timeout=5)
        assert r.returncode == 0
        assert not r.crashed
        assert r.signal_name == ""

    def test_sigsegv_detected(self):
        from vulnscan.dynamic.runner import run
        r = run(_req("stack_bof_vuln"), stdin_data=b"A" * 200 + b"\n", timeout=5)
        assert r.crashed
        assert r.signal_num == signal.SIGSEGV
        assert r.signal_name == "SIGSEGV"

    def test_crash_summary_sigsegv(self):
        from vulnscan.dynamic.runner import run
        r = run(_req("stack_bof_vuln"), stdin_data=b"A" * 200 + b"\n", timeout=5)
        assert r.crash_summary == "SIGSEGV"

    def test_timeout_detected(self):
        from vulnscan.dynamic.runner import run
        # 'sleep 10' should timeout at 1s
        import shutil
        sleep_bin = shutil.which("sleep")
        if not sleep_bin:
            pytest.skip("sleep not found")
        from pathlib import Path as P
        r = run(P(sleep_bin), argv_extra=["10"], timeout=1, stdin_data=b"")
        assert r.timed_out
        assert r.crash_summary == "TIMEOUT"

    def test_format_string_output(self):
        from vulnscan.dynamic.runner import run
        r = run(_req("format_string_vuln"), stdin_data=b"%x.%x\n", timeout=5)
        # Should not crash, and output should contain hex values (not the literal %x)
        assert r.returncode == 0
        assert b"%x" not in r.stdout

    def test_argv_passed_correctly(self):
        from vulnscan.dynamic.runner import run
        # heap_bof expects argv[1] = byte count
        r = run(_req("heap_bof_vuln"), stdin_data=b"A" * 10, argv_extra=["10"], timeout=5)
        assert isinstance(r.returncode, int)

    def test_run_result_fields(self):
        from vulnscan.dynamic.runner import run
        r = run(_req("format_string_vuln"), stdin_data=b"test\n", timeout=5)
        assert isinstance(r.binary, str)
        assert isinstance(r.stdout, bytes)
        assert isinstance(r.stderr, bytes)
        assert isinstance(r.duration_s, float)
        assert r.duration_s >= 0

    def test_missing_binary_raises(self):
        from vulnscan.dynamic.runner import run
        with pytest.raises(FileNotFoundError):
            run(Path("/nonexistent/binary"), stdin_data=b"")


# ── fuzzer ─────────────────────────────────────────────────────────────────────

class TestFuzzer:
    def test_stack_bof_finds_crash(self):
        from vulnscan.dynamic.fuzzer import fuzz
        report = fuzz(_req("stack_bof_vuln"), max_iterations=80, max_crashes=1,
                      strategies=["size_escalation", "cyclic"])
        assert report.crashes, "Fuzzer should find a crash in stack_bof_vuln"

    def test_stack_bof_cyclic_crash(self):
        from vulnscan.dynamic.fuzzer import fuzz
        report = fuzz(_req("stack_bof_vuln"), max_iterations=80, max_crashes=3,
                      strategies=["cyclic"])
        cyclic = report.cyclic_crashes
        assert cyclic, "Cyclic-pattern crash needed for offset calculation"
        assert cyclic[0].signal_name == "SIGSEGV"

    def test_format_string_finds_crash(self):
        from vulnscan.dynamic.fuzzer import fuzz
        report = fuzz(_req("format_string_vuln"), max_iterations=40, max_crashes=1,
                      strategies=["format_string"])
        assert report.crashes, "Fuzzer should crash format_string_vuln with %s/%n"

    def test_integer_overflow_finds_crash(self):
        from vulnscan.dynamic.fuzzer import fuzz
        report = fuzz(_req("integer_overflow_vuln"), max_iterations=60, max_crashes=1,
                      strategies=["integer_boundary"])
        assert report.crashes, "Fuzzer should crash integer_overflow_vuln"

    def test_report_fields(self):
        from vulnscan.dynamic.fuzzer import fuzz
        report = fuzz(_req("stack_bof_vuln"), max_iterations=40, max_crashes=1)
        assert isinstance(report.binary, str)
        assert isinstance(report.iterations, int)
        assert isinstance(report.crashes, list)
        assert isinstance(report.strategies_used, list)

    def test_crash_result_fields(self):
        from vulnscan.dynamic.fuzzer import fuzz
        report = fuzz(_req("stack_bof_vuln"), max_iterations=80, max_crashes=1,
                      strategies=["cyclic"])
        assert report.crashes
        c = report.crashes[0]
        assert isinstance(c.stdin_data, bytes)
        assert len(c.stdin_data) > 0
        assert c.signal_num != 0
        assert isinstance(c.iteration, int)
        assert c.strategy

    def test_no_crash_on_benign(self):
        from vulnscan.dynamic.fuzzer import fuzz
        # format_string_vuln with only size escalation (A*N) should not crash
        # (format specifiers are only in the format_string strategy)
        report = fuzz(_req("format_string_vuln"), max_iterations=30, max_crashes=3,
                      strategies=["size_escalation"])
        # May or may not crash — what matters is no Python exception
        assert isinstance(report.crashes, list)

    def test_unique_signals(self):
        from vulnscan.dynamic.fuzzer import fuzz
        report = fuzz(_req("stack_bof_vuln"), max_iterations=60, max_crashes=5)
        if report.crashes:
            assert isinstance(report.unique_signals, set)

    def test_reproducibility(self):
        from vulnscan.dynamic.fuzzer import fuzz
        # Same seed → same crashes
        r1 = fuzz(_req("stack_bof_vuln"), max_iterations=40, max_crashes=3, seed=99)
        r2 = fuzz(_req("stack_bof_vuln"), max_iterations=40, max_crashes=3, seed=99)
        assert len(r1.crashes) == len(r2.crashes)
        if r1.crashes:
            assert r1.crashes[0].stdin_data == r2.crashes[0].stdin_data

    def test_strategy_filter(self):
        from vulnscan.dynamic.fuzzer import fuzz
        report = fuzz(_req("stack_bof_vuln"), max_iterations=20,
                      strategies=["format_string"])
        assert report.strategies_used == ["format_string"]

    def test_max_crashes_respected(self):
        from vulnscan.dynamic.fuzzer import fuzz
        report = fuzz(_req("stack_bof_vuln"), max_iterations=200, max_crashes=2)
        assert len(report.crashes) <= 2


# ── pipeline integration ───────────────────────────────────────────────────────

class TestPipelineDynamic:
    def test_dynamic_scan_finds_crash(self):
        from vulnscan.pipeline import scan
        result = scan(_req("stack_bof_vuln"), do_static=False, do_dynamic=True, timeout=30)
        dynamic_findings = [f for f in result.findings if f.analysis == "dynamic"]
        assert dynamic_findings, "Pipeline dynamic scan should find at least one crash"

    def test_dynamic_finding_fields(self):
        from vulnscan.pipeline import scan
        from vulnscan.report.model import Severity
        result = scan(_req("stack_bof_vuln"), do_static=False, do_dynamic=True, timeout=30)
        for f in result.findings:
            if f.analysis == "dynamic":
                assert f.confidence == "dynamic"
                assert f.severity in list(Severity)
                assert "signal" in f.evidence or "strategy" in f.evidence or "crash" in f.evidence.lower()
                break

    def test_full_scan_combines_static_and_dynamic(self):
        from vulnscan.pipeline import scan
        result = scan(_req("stack_bof_vuln"), do_static=True, do_dynamic=True, timeout=30)
        analyses = {f.analysis for f in result.findings}
        assert "static" in analyses
        assert "dynamic" in analyses
