"""End-to-end scan orchestration."""

from __future__ import annotations

import time
from pathlib import Path

from vulnscan.report.model import Finding, Protection, ScanResult, VulnClass, Severity
from vulnscan.utils.logging import get_logger

logger = get_logger(__name__)


def scan(
    binary: Path,
    *,
    do_static: bool = True,
    do_dynamic: bool = True,
    timeout: int = 30,
) -> ScanResult:
    """Run the full detection pipeline on *binary* and return a ScanResult."""
    logger.info("Starting scan: %s", binary)
    t0 = time.monotonic()

    protections = Protection()
    arch = "unknown"
    findings: list[Finding] = []

    if do_static:
        findings += _run_static(binary, protections_out=protections)
        arch = _last_arch

    if do_dynamic:
        findings += _run_dynamic(binary, protections=protections, timeout=timeout)

    # Merge: elevate confidence to "both" when static + dynamic agree on same function/class
    findings = _merge_findings(findings)

    result = ScanResult(
        binary_path=str(binary.resolve()),
        arch=arch,
        protections=protections,
        findings=findings,
        scan_mode=(
            "static+dynamic" if (do_static and do_dynamic)
            else "static" if do_static
            else "dynamic"
        ),
    )
    result.duration_s = round(time.monotonic() - t0, 3)
    logger.info(
        "Scan complete in %.1fs — %d finding(s)", result.duration_s, len(findings)
    )
    return result


# ── module-level arch cache ───────────────────────────────────────────────────

_last_arch: str = "unknown"


# ── dynamic pipeline ──────────────────────────────────────────────────────────

def _run_dynamic(
    binary: Path,
    *,
    protections: Protection,
    timeout: int = 30,
) -> list[Finding]:
    """Fuzz → triage crashes → run ASan build → merge findings."""
    from vulnscan.dynamic.fuzzer import fuzz, CrashResult
    from vulnscan.dynamic.triage import triage, estimate_severity
    from vulnscan.dynamic import asan as asan_mod

    findings: list[Finding] = []

    # ── 1. Fuzz the vuln build ────────────────────────────────────────────────
    logger.info("[dynamic] Fuzzing %s …", binary.name)
    fuzz_report = fuzz(
        binary,
        timeout=min(timeout, 8),
        max_iterations=150,
        max_crashes=5,
    )
    logger.info(
        "[dynamic] %d iter, %d crash(es)", fuzz_report.iterations, len(fuzz_report.crashes)
    )

    # ── 2. Triage each unique crash ───────────────────────────────────────────
    seen_strategies: set[str] = set()
    for crash in fuzz_report.crashes:
        strat_key = _strategy_group(crash.strategy)
        if strat_key in seen_strategies:
            continue
        seen_strategies.add(strat_key)

        vc = _strategy_to_vc(crash.strategy)

        try:
            triage_result = triage(
                binary,
                crash.stdin_data,
                argv_extra=crash.argv_extra if crash.argv_extra else None,
                timeout=min(timeout, 15),
            )
            sev = estimate_severity(triage_result, vc, protections)
            lines = [
                f"strategy : {crash.strategy}",
                f"signal   : {crash.signal_name}",
                f"exploitability : {triage_result.exploitability}",
            ]
            if triage_result.offset_to_rip is not None:
                lines.append(f"offset_to_rip  : {triage_result.offset_to_rip} bytes")
            if triage_result.rip_hex:
                lines.append(f"rip_value      : {triage_result.rip_hex}")
            lines.append(f"input (24B)    : {crash.stdin_data[:24]!r}…")
            evidence = "\n".join(lines)
            if triage_result.offset_to_rip is not None:
                # Promote to CRITICAL if we have a confirmed RIP offset
                sev = Severity.CRITICAL if sev in (Severity.HIGH, Severity.MEDIUM) else sev
        except Exception as exc:
            logger.warning("[dynamic] Triage failed: %s", exc)
            sev = Severity.HIGH
            evidence = "\n".join([
                f"strategy : {crash.strategy}",
                f"signal   : {crash.signal_name}",
                f"input (24B) : {crash.stdin_data[:24]!r}…",
            ])

        findings.append(Finding(
            vuln_class=vc,
            function="<dynamic>",
            location=f"signal={crash.signal_name}",
            severity=sev,
            confidence="dynamic",
            analysis="dynamic",
            evidence=evidence,
        ))

    # ── 3. Run ASan build (if it exists alongside the vuln binary) ────────────
    asan_binary = _find_asan_sibling(binary)
    if asan_binary:
        logger.info("[dynamic] Running ASan build: %s", asan_binary.name)
        asan_inputs = _collect_asan_inputs(fuzz_report)
        for stdin_data, argv_extra in asan_inputs:
            try:
                asan_findings = asan_mod.run_and_parse(
                    asan_binary,
                    stdin_data=stdin_data,
                    argv_extra=argv_extra,
                    timeout=min(timeout, 15),
                )
                for f in asan_findings:
                    # Upgrade severity if same class already found by fuzzer
                    if any(
                        existing.vuln_class == f.vuln_class
                        for existing in findings
                        if existing.analysis == "dynamic"
                    ):
                        f = _with_confidence(f, "both")
                    findings.append(f)
            except Exception as exc:
                logger.warning("[dynamic] ASan run failed: %s", exc)
    else:
        logger.debug("[dynamic] No ASan sibling found for %s", binary.name)

    return findings


# ── static pipeline ───────────────────────────────────────────────────────────

def _run_static(binary: Path, protections_out: Protection) -> list[Finding]:
    global _last_arch
    from vulnscan.static import elf_info as elf_mod
    from vulnscan.static import protections as prot_mod
    from vulnscan.static import dangerous_funcs as df_mod

    logger.info("[static] Parsing ELF …")
    try:
        info = elf_mod.parse(binary)
    except Exception as exc:
        logger.error("[static] ELF parse failed: %s", exc)
        return []

    _last_arch = info.arch

    logger.info("[static] Detecting protections …")
    try:
        prot = prot_mod.detect(binary)
        protections_out.nx      = prot.nx
        protections_out.canary  = prot.canary
        protections_out.relro   = prot.relro
        protections_out.pie     = prot.pie
        protections_out.fortify = prot.fortify
        protections_out.rpath   = prot.rpath
        protections_out.aslr    = prot.aslr
    except Exception as exc:
        logger.warning("[static] Protection detection failed: %s", exc)

    logger.info("[static] Scanning dangerous functions …")
    findings: list[Finding] = []
    try:
        findings += df_mod.analyze(binary, info)
    except Exception as exc:
        logger.warning("[static] Dangerous-func analysis failed: %s", exc)

    logger.info("[static] Frame / buffer-size analysis …")
    try:
        from vulnscan.static import disasm as disasm_mod
        findings += disasm_mod.analyze(binary, info)
    except Exception as exc:
        logger.warning("[static] Disasm analysis failed: %s", exc)

    logger.info("[static] Taint tracking …")
    try:
        from vulnscan.static import taint as taint_mod
        findings += taint_mod.analyze(binary, info)
    except Exception as exc:
        logger.warning("[static] Taint analysis failed: %s", exc)

    return findings


# ── finding correlation ────────────────────────────────────────────────────────

def _merge_findings(findings: list[Finding]) -> list[Finding]:
    """Elevate confidence to 'both' when static + dynamic findings share a vuln class."""
    static_classes  = {f.vuln_class for f in findings if f.analysis == "static"}
    dynamic_classes = {f.vuln_class for f in findings if f.analysis == "dynamic"}
    overlap = static_classes & dynamic_classes

    merged = []
    for f in findings:
        if f.vuln_class in overlap and f.confidence in ("static", "dynamic"):
            import dataclasses
            f = dataclasses.replace(f, confidence="both")
        merged.append(f)
    return merged


# ── helpers ───────────────────────────────────────────────────────────────────

def _strategy_group(strategy: str) -> str:
    """Collapse related strategy names to avoid triaging the same crash twice."""
    if strategy.startswith("cyclic"):
        return "cyclic"
    if strategy.startswith("integer_boundary"):
        return "integer_boundary"
    return strategy


def _strategy_to_vc(strategy: str) -> VulnClass:
    if "format" in strategy:
        return VulnClass.FORMAT_STRING
    if "integer" in strategy:
        return VulnClass.INTEGER_OVERFLOW
    return VulnClass.STACK_BOF


def _find_asan_sibling(binary: Path) -> Path | None:
    """Look for a _asan build next to the vuln binary."""
    name = binary.name
    # e.g. stack_bof_vuln → stack_bof_asan
    asan_name = name.replace("_vuln", "_asan").replace("_normal", "_asan")
    if asan_name == name:
        return None
    candidate = binary.parent / asan_name
    return candidate if candidate.exists() else None


def _collect_asan_inputs(fuzz_report) -> list[tuple[bytes, list[str] | None]]:
    """Gather one representative input per crash strategy for ASan runs."""
    seen: set[str] = set()
    inputs = []
    for crash in fuzz_report.crashes:
        key = _strategy_group(crash.strategy)
        if key not in seen:
            seen.add(key)
            inputs.append((crash.stdin_data, crash.argv_extra or None))
    return inputs


def _with_confidence(f: Finding, confidence: str) -> Finding:
    import dataclasses
    return dataclasses.replace(f, confidence=confidence)
