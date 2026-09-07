"""Analyseur de sortie AddressSanitizer.

Analyse le stderr des binaires instrumentés par ASan et mappe chaque type d'erreur
vers une VulnClass + un Finding enrichi avec la pile d'appel en preuve.

Types d'erreurs ASan supportés
-------------------------------
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

# ── type d'erreur ASan → (VulnClass, sévérité_de_base) ─────────────────────

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
    # Segfault déclenché par %s / %n d'une format string — le crash EST le bug
    "segv":                     (VulnClass.UNKNOWN,         Severity.MEDIUM),
    "deadly signal":            (VulnClass.STACK_BOF,       Severity.HIGH),
}

# ── patterns regex ────────────────────────────────────────────────────────────

_RE_ERROR    = re.compile(r"ERROR: AddressSanitizer: ([\w-]+)", re.IGNORECASE)
_RE_ACCESS   = re.compile(r"(READ|WRITE) of size (\d+)", re.IGNORECASE)
_RE_FRAME    = re.compile(r"#(\d+)\s+0x[0-9a-f]+ in (\S+)\s+(.+)")
_RE_ADDR     = re.compile(r"on address (0x[0-9a-f]+)", re.IGNORECASE)
# Marqueurs de début de sections secondaires ASan (freed-by, alloc, shadow…)
_RE_SECONDARY = re.compile(
    r"\n\s*(?:freed by thread|previously allocated by|allocated by|"
    r"SUMMARY:|Shadow bytes|Address 0x)",
    re.IGNORECASE,
)


_RUNTIME_PREFIXES = (
    "__interceptor_", "__sanitizer_", "__sanitizer::", "__asan_", "_asan_", "asan_",
    "__libc_", "__GI_", "libc_",
)
_RUNTIME_EXACT = {"??", "<unknown>", "_start", "__start", "__libc_start_main",
                   "__libc_start_call_main"}


def _is_runtime_frame(func: str) -> bool:
    """Vrai si le frame appartient à un runtime interne (ASan, libc, CRT…)."""
    return func in _RUNTIME_EXACT or any(func.startswith(p) for p in _RUNTIME_PREFIXES)


class ASanReport:
    """Représentation structurée d'une erreur ASan extraite du rapport brut."""

    def __init__(self, raw: str) -> None:
        """Parse le bloc brut ASan dès la construction."""
        self.raw = raw
        self.error_type: str = ""
        self.access_op: str = ""      # "READ" | "WRITE" | ""
        self.access_size: int = 0
        self.address: str = ""        # adresse hexadécimale de l'accès fautif
        self.frames: list[dict] = []         # frames de la section primaire (l'accès qui a crashé)
        self.freed_frames: list[dict] = []   # frames de la section "freed by" (utile pour UAF)
        self._parse()

    @staticmethod
    def _extract_frames(text: str) -> list[dict]:
        """Extrait et trie par index les frames ASan présentes dans *text*.

        Supprime les codes couleur ANSI éventuels des localisations (fichier:ligne).
        """
        frames = []
        for m in _RE_FRAME.finditer(text):
            loc = m.group(3).strip()
            # Certaines versions d'ASan émettent des codes couleur même avec color=never
            loc = re.sub(r"\x1b\[[0-9;]*m", "", loc)
            frames.append({
                "idx":      int(m.group(1)),
                "func":     m.group(2),
                "location": loc,
            })
        # Tri par index : garantit l'ordre #0, #1, #2… même si la regex les trouve dans un autre ordre
        frames.sort(key=lambda f: f["idx"])
        return frames

    def _parse(self) -> None:
        m = _RE_ERROR.search(self.raw)
        if m:
            self.error_type = m.group(1).lower()
        # Gestion du "bug imbriqué" / DEADLYSIGNAL — reste un rapport d'erreur valide
        if not self.error_type and "DEADLYSIGNAL" in self.raw:
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

        # Découpe la sortie en sections pour éviter de mélanger les backtraces.
        # La section primaire va jusqu'au premier marqueur secondaire (freed by, etc.)
        sec_match = _RE_SECONDARY.search(self.raw)
        primary_text = self.raw[:sec_match.start()] if sec_match else self.raw

        self.frames = self._extract_frames(primary_text)

        # Capture optionnelle du premier frame "freed by" (utile pour UAF/double-free)
        if sec_match:
            freed_start = sec_match.start()
            next_sec = _RE_SECONDARY.search(self.raw, freed_start + 1)
            freed_text = self.raw[freed_start: next_sec.start() if next_sec else None]
            if "freed by" in freed_text.lower():
                self.freed_frames = self._extract_frames(freed_text)

    @property
    def is_valid(self) -> bool:
        """Retourne True si le rapport contient un type d'erreur reconnu (pas un bloc vide ou malformé)."""
        return bool(self.error_type)

    @property
    def first_user_frame(self) -> Optional[dict]:
        """Premier frame de pile hors des internals ASan/libc/runtime."""
        for f in self.frames:
            if not _is_runtime_frame(f["func"]):
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
        src_loc = frame["location"] if frame else ""

        op_desc = (f"{self.access_op} of {self.access_size}B" if self.access_op
                   else "access")
        lines = [f"ASan: {self.error_type}"]
        lines.append(f"operation : {op_desc}" + (f" at {self.address}" if self.address else ""))
        if frame:
            # Affiche la localisation source si disponible (DWARF embarqué dans le binaire)
            lines.append(f"in {func}()" + (f" — {src_loc}" if src_loc else ""))

        # Backtrace : uniquement les frames utilisateur de la section primaire (accès fautif),
        # triés et limités à 4 entrées pour ne pas noyer la preuve.
        user_frames = [f for f in self.frames if not _is_runtime_frame(f["func"])][:4]
        if user_frames:
            lines.append("backtrace :")
            for fr in user_frames:
                lines.append(f"  #{fr['idx']} {fr['func']} ({fr['location']})")

        # Pour UAF/double-free : indique où le free() a eu lieu (section secondaire)
        if self.freed_frames:
            first_user_freed = next(
                (f for f in self.freed_frames if not _is_runtime_frame(f["func"])), None
            )
            if first_user_freed:
                lines.append(f"free() en : {first_user_freed['func']} ({first_user_freed['location']})")

        evidence = "\n".join(lines)

        return Finding(
            vuln_class=vc,
            function=func,
            # Préfère l'adresse hexadécimale pour la colonne localisation ;
            # la référence source est déjà dans l'evidence.
            location=self.address or src_loc,
            severity=base_sev,
            confidence="dynamic",
            analysis="dynamic",
            evidence=evidence,
            cwe=_cwe(vc),
        )


def parse_output(text: str) -> list[ASanReport]:
    """Découpe la sortie ASan (potentiellement multi-erreurs) en objets ASanReport individuels.

    Chaque bloc d'erreur commence par "==PID==ERROR:" ; le split sur ce pattern
    permet de gérer les binaires qui produisent plusieurs erreurs ASan lors d'une même exécution.
    """
    # Le lookahead (?=…) conserve le délimiteur dans le bloc suivant
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
    """Exécute le binaire ASan de *binary_path* et retourne les Findings issus de sa sortie."""
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


# ── utilitaires ───────────────────────────────────────────────────────────────

def _cwe(vc: VulnClass) -> str:
    return {
        VulnClass.STACK_BOF:     "CWE-121",
        VulnClass.HEAP_BOF:      "CWE-122",
        VulnClass.USE_AFTER_FREE:"CWE-416",
        VulnClass.FORMAT_STRING: "CWE-134",
        VulnClass.OFF_BY_ONE:    "CWE-193",
    }.get(vc, "CWE-unknown")
