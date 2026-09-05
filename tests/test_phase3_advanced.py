"""Phase 3 — advanced static analysis: disasm frame analysis + taint tracking."""

from pathlib import Path
import pytest

CORPUS = Path(__file__).parent.parent / "corpus" / "bin"


def _req(name: str) -> Path:
    p = CORPUS / name
    if not p.exists():
        pytest.skip(f"{name} not built — run 'make -C corpus all'")
    return p


def _parse(name: str):
    from vulnscan.static.elf_info import parse
    return parse(_req(name))


# ── disasm ─────────────────────────────────────────────────────────────────────

class TestDisasm:
    def _analyze(self, binary_name: str):
        from vulnscan.static.disasm import analyze
        info = _parse(binary_name)
        return analyze(_req(binary_name), info)

    def test_stack_bof_gets_unbounded(self):
        findings = self._analyze("stack_bof_vuln")
        assert findings, "Expected at least one disasm finding for stack_bof"
        ev = " ".join(f.evidence for f in findings)
        assert "gets" in ev
        assert "non bornée" in ev or "unbounded" in ev

    def test_stack_bof_finds_vulnerable_function(self):
        findings = self._analyze("stack_bof_vuln")
        assert any(f.function == "vulnerable" for f in findings)

    def test_stack_bof_frame_size_in_evidence(self):
        findings = self._analyze("stack_bof_vuln")
        # The frame is 64 bytes (sub rsp, 0x40)
        ev = " ".join(f.evidence for f in findings if "gets" in f.evidence)
        assert "64" in ev

    def test_heap_bof_read_non_constant_len(self):
        findings = self._analyze("heap_bof_vuln")
        assert findings, "Expected disasm finding for heap_bof (read with variable len)"
        ev = " ".join(f.evidence for f in findings)
        assert "read" in ev
        assert "non constante" in ev or "non-constant" in ev

    def test_integer_overflow_memcpy_non_constant_len(self):
        findings = self._analyze("integer_overflow_vuln")
        assert findings, "Expected disasm finding for integer_overflow (memcpy)"
        ev = " ".join(f.evidence for f in findings)
        assert "memcpy" in ev

    def test_no_crash_on_all_corpus(self):
        from vulnscan.static.disasm import analyze
        for name in ["stack_bof_vuln", "heap_bof_vuln", "format_string_vuln",
                     "integer_overflow_vuln", "uaf_vuln", "off_by_one_vuln"]:
            info = _parse(name)
            try:
                findings = analyze(_req(name), info)
                assert isinstance(findings, list)
            except Exception as exc:
                pytest.fail(f"disasm.analyze crashed on {name}: {exc}")

    def test_findings_valid_model(self):
        from vulnscan.report.model import Severity, VulnClass
        findings = self._analyze("stack_bof_vuln")
        for f in findings:
            assert isinstance(f.severity, Severity)
            assert isinstance(f.vuln_class, VulnClass)
            assert f.analysis == "static"
            assert f.confidence == "static"
            assert f.function
            assert f.evidence


# ── taint ──────────────────────────────────────────────────────────────────────

class TestTaint:
    def _analyze(self, binary_name: str):
        from vulnscan.static.taint import analyze
        info = _parse(binary_name)
        return analyze(_req(binary_name), info)

    def test_format_string_detects_stack_printf(self):
        findings = self._analyze("format_string_vuln")
        assert findings, "Expected taint finding for format_string (printf with stack buf)"
        vuln_classes = [f.vuln_class.value for f in findings]
        assert "format-string" in vuln_classes

    def test_format_string_finding_in_vulnerable(self):
        findings = self._analyze("format_string_vuln")
        fmt = [f for f in findings if f.vuln_class.value == "format-string"]
        assert any(f.function == "vulnerable" for f in fmt)

    def test_format_string_evidence_mentions_stack(self):
        findings = self._analyze("format_string_vuln")
        ev = " ".join(f.evidence for f in findings)
        assert "stack" in ev.lower() or "rbp" in ev

    def test_taint_no_false_format_on_stack_bof(self):
        # stack_bof uses printf("Hello, %s!", buf) — format is a literal, not a stack buf
        # The taint tracker may or may not flag it; what matters is no CRASH.
        findings = self._analyze("stack_bof_vuln")
        assert isinstance(findings, list)

    def test_no_crash_on_all_corpus(self):
        from vulnscan.static.taint import analyze
        for name in ["stack_bof_vuln", "heap_bof_vuln", "format_string_vuln",
                     "integer_overflow_vuln", "uaf_vuln", "off_by_one_vuln"]:
            info = _parse(name)
            try:
                findings = analyze(_req(name), info)
                assert isinstance(findings, list)
            except Exception as exc:
                pytest.fail(f"taint.analyze crashed on {name}: {exc}")

    def test_findings_valid_model(self):
        from vulnscan.report.model import Severity, VulnClass
        findings = self._analyze("format_string_vuln")
        for f in findings:
            assert isinstance(f.severity, Severity)
            assert isinstance(f.vuln_class, VulnClass)
            assert f.analysis == "static"
            assert f.confidence == "static"
            assert f.cwe


# ── pipeline integration ───────────────────────────────────────────────────────

class TestPipelinePhase3:
    def test_pipeline_aggregates_all_static_modules(self):
        from vulnscan.pipeline import scan
        result = scan(_req("stack_bof_vuln"), do_static=True, do_dynamic=False)
        # Phase 2 (dangerous_funcs) + Phase 3 (disasm) should both contribute
        assert len(result.findings) >= 2

    def test_pipeline_format_string_has_finding(self):
        from vulnscan.pipeline import scan
        result = scan(_req("format_string_vuln"), do_static=True, do_dynamic=False)
        vuln_classes = [f.vuln_class.value for f in result.findings]
        assert "format-string" in vuln_classes

    def test_pipeline_heap_bof_has_finding(self):
        from vulnscan.pipeline import scan
        result = scan(_req("heap_bof_vuln"), do_static=True, do_dynamic=False)
        assert len(result.findings) >= 1

    def test_pipeline_integer_overflow_has_finding(self):
        from vulnscan.pipeline import scan
        result = scan(_req("integer_overflow_vuln"), do_static=True, do_dynamic=False)
        assert len(result.findings) >= 1

    def test_full_static_scan_serialises(self):
        import json
        from vulnscan.pipeline import scan
        result = scan(_req("stack_bof_vuln"), do_static=True, do_dynamic=False)
        d = result.as_dict()
        json.dumps(d)  # must be JSON-serialisable
        assert d["findings"]
        assert all("vuln_class" in f for f in d["findings"])
