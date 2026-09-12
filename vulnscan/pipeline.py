"""Orchestration du pipeline de scan de bout en bout."""

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
    """Lance le pipeline de détection complet sur *binary* et retourne un ScanResult."""
    logger.info("Démarrage du scan : %s", binary)
    t0 = time.monotonic()

    protections = Protection()
    arch = "unknown"
    findings: list[Finding] = []

    if do_static:
        findings += _run_static(binary, protections_out=protections)
        arch = _last_arch

    if do_dynamic:
        findings += _run_dynamic(binary, protections=protections, timeout=timeout)

    # Fusion : élève la confiance à "both" quand statique + dynamique s'accordent sur la même fonction/classe
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
        "Scan terminé en %.1fs — %d vulnérabilité(s)", result.duration_s, len(findings)
    )
    return result


# ── cache d'architecture (niveau module) ──────────────────────────────────────

_last_arch: str = "unknown"


# ── pipeline dynamique ────────────────────────────────────────────────────────

def _run_dynamic(
    binary: Path,
    *,
    protections: Protection,
    timeout: int = 30,
) -> list[Finding]:
    """Fuzzing → triage des crashes → résultats."""
    from vulnscan.dynamic.fuzzer import fuzz, CrashResult
    from vulnscan.dynamic.triage import triage, estimate_severity

    findings: list[Finding] = []

    # ── 1. Fuzzing du binaire vuln ────────────────────────────────────────────
    logger.info("[dynamic] Fuzzing de %s …", binary.name)
    fuzz_report = fuzz(
        binary,
        timeout=min(timeout, 8),
        max_iterations=150,
        max_crashes=5,
    )
    logger.info(
        "[dynamic] %d itération(s), %d crash(es)", fuzz_report.iterations, len(fuzz_report.crashes)
    )

    # ── 2. Triage de chaque crash unique ─────────────────────────────────────
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
                # Promouvoir à CRITICAL si l'offset vers RIP est confirmé
                sev = Severity.CRITICAL if sev in (Severity.HIGH, Severity.MEDIUM) else sev
        except Exception as exc:
            logger.warning("[dynamic] Triage échoué : %s", exc)
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

    return findings


# ── pipeline statique ─────────────────────────────────────────────────────────

def _run_static(binary: Path, protections_out: Protection) -> list[Finding]:
    global _last_arch
    from vulnscan.static import elf_info as elf_mod
    from vulnscan.static import protections as prot_mod
    from vulnscan.static import dangerous_funcs as df_mod

    logger.info("[static] Analyse ELF …")
    try:
        info = elf_mod.parse(binary)
    except Exception as exc:
        logger.error("[static] Échec de l'analyse ELF : %s", exc)
        return []

    _last_arch = info.arch

    logger.info("[static] Détection des protections …")
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
        logger.warning("[static] Détection des protections échouée : %s", exc)

    logger.info("[static] Recherche de fonctions dangereuses …")
    findings: list[Finding] = []
    try:
        findings += df_mod.analyze(binary, info)
    except Exception as exc:
        logger.warning("[static] Analyse des fonctions dangereuses échouée : %s", exc)

    logger.info("[static] Analyse de taille de frame / tampon …")
    try:
        from vulnscan.static import disasm as disasm_mod
        findings += disasm_mod.analyze(binary, info)
    except Exception as exc:
        logger.warning("[static] Analyse disasm échouée : %s", exc)

    logger.info("[static] Propagation de teinte …")
    try:
        from vulnscan.static import taint as taint_mod
        findings += taint_mod.analyze(binary, info)
    except Exception as exc:
        logger.warning("[static] Analyse de teinte échouée : %s", exc)

    return findings


# ── corrélation des findings ──────────────────────────────────────────────────

def _merge_findings(findings: list[Finding]) -> list[Finding]:
    """Élève la confiance à 'both' quand statique + dynamique partagent une classe de vulnérabilité,
    puis déduplique les findings dynamiques identiques issus de plusieurs runs du fuzzer."""
    import dataclasses as _dc

    static_classes  = {f.vuln_class for f in findings if f.analysis == "static"}
    dynamic_classes = {f.vuln_class for f in findings if f.analysis == "dynamic"}
    overlap = static_classes & dynamic_classes

    # Élévation de confiance static+dynamic
    elevated = []
    for f in findings:
        if f.vuln_class in overlap and f.confidence in ("static", "dynamic"):
            f = _dc.replace(f, confidence="both")
        elevated.append(f)

    # Déduplication des findings DYNAMIQUES uniquement : plusieurs runs ASan/fuzzer
    # sur des entrées différentes peuvent produire le même finding (même classe,
    # même fonction). On garde celui de meilleure confiance puis sévérité.
    # Les findings statiques sont tous conservés (chaque analyseur apporte son evidence).
    _conf_rank = {"both": 2, "dynamic": 1, "static": 1}
    _sev_order = {Severity.INFO: 1, Severity.LOW: 2, Severity.MEDIUM: 3,
                  Severity.HIGH: 4, Severity.CRITICAL: 5}

    static_findings  = [f for f in elevated if f.analysis == "static"]
    dynamic_findings = [f for f in elevated if f.analysis == "dynamic"]

    seen: dict[tuple, Finding] = {}
    for f in dynamic_findings:
        key = (f.vuln_class, f.function)
        if key not in seen:
            seen[key] = f
        else:
            prev = seen[key]
            if (_conf_rank.get(f.confidence, 0), _sev_order.get(f.severity, 0)) > \
               (_conf_rank.get(prev.confidence, 0), _sev_order.get(prev.severity, 0)):
                seen[key] = f

    return static_findings + list(seen.values())


# ── fonctions utilitaires ─────────────────────────────────────────────────────

def _strategy_group(strategy: str) -> str:
    """Regroupe les stratégies apparentées pour éviter de triager deux fois le même crash."""
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


