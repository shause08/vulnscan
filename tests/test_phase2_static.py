"""Phase 2 — static analysis: protections and dangerous function detection."""

from pathlib import Path
import pytest

CORPUS = Path(__file__).parent.parent / "corpus" / "bin"


def _req(name: str) -> Path:
    p = CORPUS / name
    if not p.exists():
        pytest.skip(f"{name} not built — run 'make -C corpus all'")
    return p


# ── elf_info ──────────────────────────────────────────────────────────────────

class TestELFInfo:
    def test_arch_x86_64(self):
        from vulnscan.static.elf_info import parse
        info = parse(_req("stack_bof_vuln"))
        assert info.arch == "x86-64"
        assert info.bits == 64

    def test_not_pie(self):
        from vulnscan.static.elf_info import parse
        info = parse(_req("stack_bof_vuln"))
        assert info.is_pie is False

    def test_pie_binary(self):
        from vulnscan.static.elf_info import parse
        info = parse(_req("stack_bof_normal"))
        # Normal build has PIE by default on modern gcc
        assert isinstance(info.is_pie, bool)

    def test_imports_nonempty(self):
        from vulnscan.static.elf_info import parse
        info = parse(_req("stack_bof_vuln"))
        assert len(info.imports) > 0

    def test_gets_in_imports(self):
        from vulnscan.static.elf_info import parse
        info = parse(_req("stack_bof_vuln"))
        assert "gets" in info.import_names()

    def test_plt_map_nonempty(self):
        from vulnscan.static.elf_info import parse
        info = parse(_req("stack_bof_vuln"))
        assert len(info.plt_map) > 0

    def test_plt_map_contains_gets(self):
        from vulnscan.static.elf_info import parse
        info = parse(_req("stack_bof_vuln"))
        assert "gets" in info.plt_map.values()

    def test_function_at_finds_vulnerable(self):
        from vulnscan.static.elf_info import parse
        info = parse(_req("stack_bof_vuln"))
        # There should be a function named 'vulnerable' in the symbol table
        names = {fn.name for fn in info.functions}
        assert "vulnerable" in names

    def test_sections_include_text(self):
        from vulnscan.static.elf_info import parse
        info = parse(_req("stack_bof_vuln"))
        assert ".text" in info.sections


# ── protections ───────────────────────────────────────────────────────────────

class TestProtections:
    def test_vuln_build_no_nx(self):
        from vulnscan.static.protections import detect
        p = detect(_req("stack_bof_vuln"))
        assert p.nx is False

    def test_normal_build_has_nx(self):
        from vulnscan.static.protections import detect
        p = detect(_req("stack_bof_normal"))
        assert p.nx is True

    def test_vuln_build_no_canary(self):
        from vulnscan.static.protections import detect
        p = detect(_req("stack_bof_vuln"))
        assert p.canary is False

    def test_normal_build_has_canary(self):
        from vulnscan.static.protections import detect
        p = detect(_req("stack_bof_normal"))
        assert p.canary is True

    def test_vuln_build_no_relro(self):
        from vulnscan.static.protections import detect
        p = detect(_req("stack_bof_vuln"))
        assert p.relro == "no"

    def test_normal_build_relro(self):
        from vulnscan.static.protections import detect
        p = detect(_req("stack_bof_normal"))
        assert p.relro in ("partial", "full")

    def test_vuln_build_no_pie(self):
        from vulnscan.static.protections import detect
        p = detect(_req("stack_bof_vuln"))
        assert p.pie is False

    def test_protection_fields_types(self):
        from vulnscan.static.protections import detect
        p = detect(_req("stack_bof_vuln"))
        assert isinstance(p.nx, bool)
        assert isinstance(p.canary, bool)
        assert isinstance(p.pie, bool)
        assert p.relro in ("no", "partial", "full")


# ── dangerous_funcs ───────────────────────────────────────────────────────────

class TestDangerousFuncs:
    def _analyze(self, binary_name: str):
        from vulnscan.static.elf_info import parse
        from vulnscan.static.dangerous_funcs import analyze
        p = _req(binary_name)
        return analyze(p, parse(p))

    def test_stack_bof_detects_gets(self):
        findings = self._analyze("stack_bof_vuln")
        vuln_classes = [f.vuln_class.value for f in findings]
        assert "stack-buffer-overflow" in vuln_classes

    def test_stack_bof_gets_is_critical(self):
        from vulnscan.report.model import Severity
        findings = self._analyze("stack_bof_vuln")
        gets_findings = [f for f in findings if "gets" in f.evidence]
        assert gets_findings, "No finding mentioning gets()"
        assert any(f.severity == Severity.CRITICAL for f in gets_findings)

    def test_stack_bof_call_site_in_vulnerable(self):
        findings = self._analyze("stack_bof_vuln")
        caller_names = {f.function for f in findings}
        assert "vulnerable" in caller_names

    def test_heap_bof_detects_read(self):
        findings = self._analyze("heap_bof_vuln")
        evidence_all = " ".join(f.evidence for f in findings)
        assert "read" in evidence_all

    def test_format_string_detects_printf(self):
        findings = self._analyze("format_string_vuln")
        vuln_classes = [f.vuln_class.value for f in findings]
        assert "format-string" in vuln_classes

    def test_integer_overflow_detects_memcpy(self):
        findings = self._analyze("integer_overflow_vuln")
        evidence_all = " ".join(f.evidence for f in findings)
        assert "memcpy" in evidence_all

    def test_findings_have_required_fields(self):
        from vulnscan.report.model import Severity, VulnClass
        findings = self._analyze("stack_bof_vuln")
        assert findings, "Expected at least one finding"
        for f in findings:
            assert isinstance(f.severity, Severity)
            assert isinstance(f.vuln_class, VulnClass)
            assert f.function
            assert f.evidence
            assert f.confidence == "static"
            assert f.analysis == "static"

    def test_findings_serialise(self):
        findings = self._analyze("stack_bof_vuln")
        for f in findings:
            d = f.as_dict()
            assert "vuln_class" in d
            assert "severity" in d

    def test_no_crash_on_all_corpus(self):
        """Static analysis must not raise on any corpus binary."""
        from vulnscan.static.elf_info import parse
        from vulnscan.static.dangerous_funcs import analyze
        for name in ["stack_bof_vuln", "heap_bof_vuln", "format_string_vuln",
                     "integer_overflow_vuln", "uaf_vuln", "off_by_one_vuln"]:
            p = _req(name)
            try:
                findings = analyze(p, parse(p))
                assert isinstance(findings, list)
            except Exception as exc:
                pytest.fail(f"Static analysis crashed on {name}: {exc}")


# ── pipeline integration ───────────────────────────────────────────────────────

class TestPipelineStatic:
    def test_scan_static_only(self):
        from vulnscan.pipeline import scan
        result = scan(
            _req("stack_bof_vuln"),
            do_static=True,
            do_dynamic=False,
        )
        assert result.arch == "x86-64"
        assert result.protections.nx is False
        assert result.protections.canary is False
        assert len(result.findings) > 0

    def test_scan_result_serialises(self):
        import json
        from vulnscan.pipeline import scan
        result = scan(_req("stack_bof_vuln"), do_static=True, do_dynamic=False)
        d = result.as_dict()
        # Must be JSON-serialisable
        json.dumps(d)
        assert d["protections"]["nx"] is False
        assert d["findings"]
