"""Phase 0 smoke tests — CLI skeleton, utilities, data model."""

import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parent.parent


def test_version_flag():
    result = subprocess.run(
        [sys.executable, "-m", "vulnscan.cli", "--version"],
        capture_output=True, text=True,
        cwd=ROOT,
    )
    assert result.returncode == 0
    assert "vulnscan" in result.stdout


def test_check_deps_command():
    result = subprocess.run(
        [sys.executable, "-m", "vulnscan.cli", "check-deps"],
        capture_output=True, text=True,
        cwd=ROOT,
    )
    # Return code 0 (all present) or 1 (some missing) — either is valid here.
    assert result.returncode in (0, 1)
    assert "gcc" in result.stdout or "OK" in result.stdout


def test_scan_missing_binary(tmp_path):
    result = subprocess.run(
        [sys.executable, "-m", "vulnscan.cli", "scan", str(tmp_path / "nope")],
        capture_output=True, text=True,
        cwd=ROOT,
    )
    assert result.returncode == 1


def test_shell_run_basic():
    from vulnscan.utils.shell import run
    r = run(["echo", "hello"], limit_resources=False)
    assert r.returncode == 0
    assert b"hello" in r.stdout


def test_shell_run_timeout():
    from vulnscan.utils.shell import run
    with pytest.raises(subprocess.TimeoutExpired):
        run(["sleep", "10"], timeout=1, limit_resources=False)


def test_shell_check_deps_returns_list():
    from vulnscan.utils.shell import check_system_deps
    missing = check_system_deps()
    assert isinstance(missing, list)


def test_model_finding_serialisation():
    from vulnscan.report.model import Finding, Severity, VulnClass
    f = Finding(
        vuln_class=VulnClass.STACK_BOF,
        function="main",
        location="0x401234",
        severity=Severity.CRITICAL,
        confidence="static",
        analysis="static",
        evidence="calls gets()",
        offset=42,
    )
    d = f.as_dict()
    assert d["vuln_class"] == "stack-buffer-overflow"
    assert d["severity"] == "CRITICAL"
    assert d["offset"] == 42


def test_model_scan_result_serialisation():
    from vulnscan.report.model import Protection, ScanResult
    sr = ScanResult(
        binary_path="/tmp/test",
        arch="x86-64",
        protections=Protection(nx=True, canary=False),
        findings=[],
    )
    d = sr.as_dict()
    assert d["protections"]["nx"] is True
    assert isinstance(d["findings"], list)
    assert "summary" in d
