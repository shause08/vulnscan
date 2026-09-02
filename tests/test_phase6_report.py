"""Phase 6 — report generation: JSON + HTML."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

CORPUS = Path(__file__).parent.parent / "corpus" / "bin"


def _req(name: str) -> Path:
    p = CORPUS / name
    if not p.exists():
        pytest.skip(f"{name} not built — run 'make -C corpus all'")
    return p


def _make_result(
    *,
    n_findings: int = 2,
    include_critical: bool = True,
):
    """Build a minimal ScanResult for unit testing."""
    from vulnscan.report.model import (
        Finding, Protection, ScanResult, Severity, VulnClass,
    )
    prot = Protection(nx=True, canary=False, relro="partial", pie=False, fortify=False)
    findings = []
    if include_critical:
        findings.append(Finding(
            vuln_class=VulnClass.STACK_BOF,
            function="vulnerable",
            location="0x401234",
            severity=Severity.CRITICAL,
            confidence="both",
            analysis="dynamic",
            evidence="crash via cyclic: offset_to_rip=72 exploitability=EXPLOITABLE",
            cwe="CWE-121",
        ))
    if n_findings >= 2:
        findings.append(Finding(
            vuln_class=VulnClass.FORMAT_STRING,
            function="process",
            location="0x401500",
            severity=Severity.HIGH,
            confidence="static",
            analysis="static",
            evidence="printf called with user-controlled format argument",
            cwe="CWE-134",
        ))
    return ScanResult(
        binary_path="/tmp/test_binary",
        arch="x86-64",
        protections=prot,
        findings=findings,
        scan_mode="static+dynamic",
        duration_s=1.23,
    )


# ── JSON rendering ─────────────────────────────────────────────────────────────

class TestJSONReport:
    def test_render_json_is_valid(self):
        from vulnscan.report.generator import render_json
        r = _make_result()
        text = render_json(r)
        data = json.loads(text)  # must not raise
        assert isinstance(data, dict)

    def test_render_json_top_level_keys(self):
        from vulnscan.report.generator import render_json
        data = json.loads(render_json(_make_result()))
        for key in ("binary_path", "arch", "timestamp", "duration_s",
                    "scan_mode", "protections", "findings", "summary"):
            assert key in data, f"Missing key: {key}"

    def test_render_json_findings_count(self):
        from vulnscan.report.generator import render_json
        data = json.loads(render_json(_make_result(n_findings=2)))
        assert len(data["findings"]) == 2

    def test_render_json_finding_structure(self):
        from vulnscan.report.generator import render_json
        data = json.loads(render_json(_make_result()))
        f = data["findings"][0]
        for key in ("vuln_class", "function", "location", "severity",
                    "confidence", "analysis", "evidence"):
            assert key in f, f"Finding missing key: {key}"

    def test_render_json_severity_values_are_strings(self):
        from vulnscan.report.generator import render_json
        data = json.loads(render_json(_make_result()))
        for f in data["findings"]:
            assert isinstance(f["severity"], str)
            assert f["severity"] in ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL")

    def test_render_json_vuln_class_values_are_strings(self):
        from vulnscan.report.generator import render_json
        data = json.loads(render_json(_make_result()))
        valid = {
            "stack-buffer-overflow", "heap-buffer-overflow", "format-string",
            "integer-overflow", "use-after-free", "off-by-one", "unknown",
        }
        for f in data["findings"]:
            assert f["vuln_class"] in valid

    def test_render_json_summary_counts(self):
        from vulnscan.report.generator import render_json
        data = json.loads(render_json(_make_result(n_findings=2, include_critical=True)))
        assert data["summary"]["CRITICAL"] == 1
        assert data["summary"]["HIGH"] == 1
        assert data["summary"]["MEDIUM"] == 0

    def test_render_json_protections_structure(self):
        from vulnscan.report.generator import render_json
        data = json.loads(render_json(_make_result()))
        prot = data["protections"]
        assert "nx" in prot and "canary" in prot and "relro" in prot
        assert "pie" in prot and "fortify" in prot

    def test_render_json_empty_findings(self):
        from vulnscan.report.generator import render_json
        from vulnscan.report.model import ScanResult, Protection
        r = ScanResult(
            binary_path="/tmp/clean",
            arch="x86-64",
            protections=Protection(),
            findings=[],
            scan_mode="static",
        )
        data = json.loads(render_json(r))
        assert data["findings"] == []
        assert all(v == 0 for v in data["summary"].values())

    def test_render_json_pretty_printed(self):
        from vulnscan.report.generator import render_json
        text = render_json(_make_result())
        assert "\n" in text
        assert "  " in text  # indented

    def test_render_json_cwe_preserved(self):
        from vulnscan.report.generator import render_json
        data = json.loads(render_json(_make_result()))
        crit = next(f for f in data["findings"] if f["severity"] == "CRITICAL")
        assert crit["cwe"] == "CWE-121"


# ── HTML rendering ─────────────────────────────────────────────────────────────

class TestHTMLReport:
    def test_render_html_returns_string(self):
        from vulnscan.report.generator import render_html
        html = render_html(_make_result())
        assert isinstance(html, str)

    def test_render_html_is_valid_html_doctype(self):
        from vulnscan.report.generator import render_html
        html = render_html(_make_result())
        assert html.strip().lower().startswith("<!doctype html")

    def test_render_html_contains_binary_name(self):
        from vulnscan.report.generator import render_html
        html = render_html(_make_result())
        assert "test_binary" in html

    def test_render_html_contains_arch(self):
        from vulnscan.report.generator import render_html
        html = render_html(_make_result())
        assert "x86-64" in html

    def test_render_html_contains_severity_labels(self):
        from vulnscan.report.generator import render_html
        html = render_html(_make_result())
        assert "CRITICAL" in html
        assert "HIGH" in html

    def test_render_html_contains_vuln_class(self):
        from vulnscan.report.generator import render_html
        html = render_html(_make_result())
        assert "stack-buffer-overflow" in html
        assert "format-string" in html

    def test_render_html_contains_function_names(self):
        from vulnscan.report.generator import render_html
        html = render_html(_make_result())
        assert "vulnerable" in html
        assert "process" in html

    def test_render_html_contains_cwe(self):
        from vulnscan.report.generator import render_html
        html = render_html(_make_result())
        assert "CWE-121" in html

    def test_render_html_contains_protection_names(self):
        from vulnscan.report.generator import render_html
        html = render_html(_make_result())
        for name in ("NX", "Canary", "RELRO", "PIE", "Fortify"):
            assert name in html, f"Protection '{name}' not found in HTML"

    def test_render_html_protections_reflect_values(self):
        from vulnscan.report.generator import render_html
        html = render_html(_make_result())
        # nx=True → "yes", canary=False → "no"
        assert "yes" in html  # NX is true
        assert "no" in html   # Canary is false

    def test_render_html_no_external_assets(self):
        """Self-contained: no <link> or <script src=...>."""
        from vulnscan.report.generator import render_html
        import re
        html = render_html(_make_result())
        # No external stylesheets
        assert not re.search(r'<link[^>]+href=["\']https?://', html, re.I)
        # No external scripts
        assert not re.search(r'<script[^>]+src=["\']https?://', html, re.I)

    def test_render_html_has_inline_css(self):
        from vulnscan.report.generator import render_html
        html = render_html(_make_result())
        assert "<style>" in html

    def test_render_html_severity_sorted(self):
        """CRITICAL findings must appear before LOW findings in rendered HTML."""
        from vulnscan.report.generator import render_html
        from vulnscan.report.model import Finding, VulnClass, Severity
        from vulnscan.report.model import ScanResult, Protection
        low_f = Finding(
            vuln_class=VulnClass.OFF_BY_ONE, function="foo", location="0x0",
            severity=Severity.LOW, confidence="static", analysis="static",
            evidence="minor",
        )
        crit_f = Finding(
            vuln_class=VulnClass.STACK_BOF, function="bar", location="0x0",
            severity=Severity.CRITICAL, confidence="both", analysis="dynamic",
            evidence="rip overwrite",
        )
        r = ScanResult(
            binary_path="/tmp/bin", arch="x86-64", protections=Protection(),
            findings=[low_f, crit_f], scan_mode="static+dynamic",
        )
        html = render_html(r)
        crit_pos = html.index("CRITICAL")
        low_pos  = html.index("LOW")
        assert crit_pos < low_pos, "CRITICAL must appear before LOW in sorted HTML"

    def test_render_html_empty_findings_message(self):
        from vulnscan.report.generator import render_html
        from vulnscan.report.model import ScanResult, Protection
        r = ScanResult(
            binary_path="/tmp/clean", arch="x86-64",
            protections=Protection(), findings=[], scan_mode="static",
        )
        html = render_html(r)
        assert "No findings" in html or "0" in html

    def test_render_html_confidence_both_highlighted(self):
        from vulnscan.report.generator import render_html
        html = render_html(_make_result())
        # Findings with confidence="both" should have a special CSS class
        assert "both" in html

    def test_render_html_scan_mode_displayed(self):
        from vulnscan.report.generator import render_html
        html = render_html(_make_result())
        assert "static+dynamic" in html

    def test_render_html_duration_displayed(self):
        from vulnscan.report.generator import render_html
        html = render_html(_make_result())
        assert "1.23" in html


# ── save() helper ─────────────────────────────────────────────────────────────

class TestSaveHelper:
    def test_save_writes_html(self):
        from vulnscan.report.generator import save
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "report.html"
            save(_make_result(), out)
            assert out.exists()
            assert "<!DOCTYPE" in out.read_text()

    def test_save_html_utf8_encoded(self):
        from vulnscan.report.generator import save
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "report.html"
            save(_make_result(), out)
            content = out.read_text(encoding="utf-8")
            assert len(content) > 0


# ── CLI integration ───────────────────────────────────────────────────────────

class TestCLIReport:
    def test_cli_writes_html_report(self):
        """vulnscan scan --no-dynamic writes an HTML report."""
        import subprocess, sys
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "report.html"
            result = subprocess.run(
                [sys.executable, "-m", "vulnscan.cli", "scan",
                 str(_req("stack_bof_vuln")), "--no-dynamic", "--out", str(out)],
                capture_output=True, timeout=30, cwd=str(Path(__file__).parent.parent),
            )
            assert out.exists(), f"HTML not written. stderr: {result.stderr.decode()}"
            assert "<!DOCTYPE" in out.read_text()
            assert "stack_bof_vuln" in out.read_text()

    def test_cli_summary_printed_to_stdout(self):
        """The CLI should print a text summary to stdout after scanning."""
        import subprocess, sys
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "report.html"
            result = subprocess.run(
                [sys.executable, "-m", "vulnscan.cli", "scan",
                 str(_req("stack_bof_vuln")), "--no-dynamic", "--out", str(out)],
                capture_output=True, timeout=30, cwd=str(Path(__file__).parent.parent),
            )
            stdout = result.stdout.decode()
            assert "vulnscan" in stdout.lower() or "Findings" in stdout or "=" in stdout

    def test_cli_nonexistent_binary_returns_error(self):
        import subprocess, sys
        result = subprocess.run(
            [sys.executable, "-m", "vulnscan.cli", "scan", "/nonexistent/binary"],
            capture_output=True, timeout=10,
        )
        assert result.returncode != 0


# ── Real pipeline → report ────────────────────────────────────────────────────

class TestReportFromRealScan:
    def test_json_report_from_static_scan(self):
        from vulnscan.pipeline import scan
        from vulnscan.report.generator import render_json
        result = scan(_req("stack_bof_vuln"), do_static=True, do_dynamic=False, timeout=15)
        text = render_json(result)
        data = json.loads(text)
        assert len(data["findings"]) > 0
        assert data["arch"] == "x86-64"

    def test_html_report_from_static_scan(self):
        from vulnscan.pipeline import scan
        from vulnscan.report.generator import render_html
        result = scan(_req("stack_bof_vuln"), do_static=True, do_dynamic=False, timeout=15)
        html = render_html(result)
        assert "stack_bof_vuln" in html
        assert "x86-64" in html
        assert "stack-buffer-overflow" in html

    def test_all_corpus_binaries_produce_valid_json(self):
        from vulnscan.pipeline import scan
        from vulnscan.report.generator import render_json
        binaries = ["stack_bof_vuln", "format_string_vuln", "heap_bof_vuln"]
        for name in binaries:
            p = CORPUS / name
            if not p.exists():
                continue
            result = scan(p, do_static=True, do_dynamic=False, timeout=10)
            data = json.loads(render_json(result))
            assert "findings" in data, f"{name}: JSON missing 'findings'"
            assert "summary" in data, f"{name}: JSON missing 'summary'"
