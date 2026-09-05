"""Triage de crash : analyse GDB en batch, classification d'exploitabilité, calcul d'offset.

Workflow
--------
1. Écrit l'entrée crashante dans un fichier temporaire.
2. Lance GDB en mode --batch avec un script qui :
     - Exécute le binaire avec stdin redirigé depuis le fichier temporaire
     - Capture les registres (rip, rbp, rsp) au moment du crash
     - Tente d'exécuter le plugin exploitable du CERT si disponible
     - Affiche une backtrace
3. Analyse la sortie GDB pour extraire :
     - La valeur de RIP au crash
     - Si cette valeur ressemble à un pattern cyclique (→ offset calculable)
     - Le verdict d'exploitabilité de `exploitable` (si présent)
4. Si RIP contient des octets de pattern cyclique, appelle `pwn.cyclic_find` pour
   calculer l'offset exact depuis le début de l'entrée jusqu'à l'adresse de retour sauvegardée.
5. Retourne un TriageResult consommé par le moteur de sévérité.

Repli (pas de GDB ni de plugin exploitable)
--------------------------------------------
Analyse le numéro de signal et l'adresse de crash depuis le RunResult. Si l'adresse
de crash ressemble à une valeur de pattern cyclique, on peut quand même calculer l'offset.
Classe en exploitabilité UNKNOWN.
"""

from __future__ import annotations

import dataclasses
import re
import struct
import tempfile
import os
from pathlib import Path
from typing import Optional

from vulnscan.utils.logging import get_logger
from vulnscan.utils.shell import run as shell_run

logger = get_logger(__name__)

# Niveaux d'exploitabilité (vocabulaire du plugin exploitable du CERT)
EXPLOITABLE           = "EXPLOITABLE"
PROBABLY_EXPLOITABLE  = "PROBABLY_EXPLOITABLE"
PROBABLY_NOT          = "PROBABLY_NOT_EXPLOITABLE"
UNKNOWN               = "UNKNOWN"

_RE_RIP     = re.compile(r"rip\s+(0x[0-9a-f]+)", re.IGNORECASE)
_RE_SIGSEGV = re.compile(r"Program received signal (SIG\w+)", re.IGNORECASE)
_RE_EXPLOIT = re.compile(
    r"(EXPLOITABLE|PROBABLY_EXPLOITABLE|PROBABLY_NOT_EXPLOITABLE|NOT_EXPLOITABLE|UNKNOWN)",
    re.IGNORECASE,
)
_RE_REASON  = re.compile(r"Exploitability Classification: (\w+)\s*\nDescription: (.+)")


@dataclasses.dataclass
class TriageResult:
    binary: str
    stdin_data: bytes
    argv_extra: list[str]
    signal_name: str
    rip_value: Optional[int]           # RIP au crash (None si inconnu)
    rip_hex: str                       # "0xdeadbeef" ou ""
    offset_to_rip: Optional[int]       # octets depuis le début de l'entrée jusqu'au RIP sauvegardé
    exploitability: str                # l'une des constantes ci-dessus
    exploitability_reason: str
    backtrace: str                     # 5 premiers frames en texte
    gdb_available: bool
    exploitable_plugin: bool


def triage(
    binary_path: Path,
    crash_input: bytes,
    *,
    argv_extra: list[str] | None = None,
    timeout: int = 20,
) -> TriageResult:
    """Triage d'un crash : lance GDB, extrait RIP, calcule l'offset, classifie."""
    gdb_ok = _gdb_available()

    if gdb_ok:
        return _triage_gdb(binary_path, crash_input, argv_extra or [], timeout)
    else:
        logger.warning("GDB introuvable — repli sur le triage par signal uniquement")
        return _triage_fallback(binary_path, crash_input, argv_extra or [])


# ── triage GDB ────────────────────────────────────────────────────────────────

def _triage_gdb(
    binary_path: Path,
    crash_input: bytes,
    argv_extra: list[str],
    timeout: int,
) -> TriageResult:
    with tempfile.NamedTemporaryFile(delete=False, suffix=".crash_input") as tf:
        tf.write(crash_input)
        input_file = tf.name

    try:
        gdb_script = _build_gdb_script(str(binary_path), input_file, argv_extra)
        with tempfile.NamedTemporaryFile(
            mode="w", delete=False, suffix=".gdb", encoding="utf-8"
        ) as sf:
            sf.write(gdb_script)
            script_file = sf.name

        result = shell_run(
            ["gdb", "--batch", "-x", script_file],
            timeout=timeout,
            limit_resources=False,
        )
        output = (result.stdout + result.stderr).decode(errors="replace")
        logger.debug("Sortie GDB (%d caractères) :\n%s", len(output), output[:800])
    except Exception as exc:
        logger.warning("Exécution GDB échouée : %s", exc)
        output = ""
    finally:
        for f in [input_file, script_file]:
            try:
                os.unlink(f)
            except OSError:
                pass

    return _parse_gdb_output(str(binary_path), crash_input, argv_extra, output)


def _build_gdb_script(binary: str, input_file: str, argv_extra: list[str]) -> str:
    argv_str = " ".join(argv_extra)
    has_exploitable = _exploitable_available()
    lines = [
        "set pagination off",
        "set disassembly-flavor intel",
        "set confirm off",
        f'file "{binary}"',
        f"set args {argv_str}",
        f'run < "{input_file}"',
        "echo ===REGISTERS===\\n",
        "info registers rip rbp rsp",
        "echo ===BACKTRACE===\\n",
        "backtrace 8",
    ]
    lines += [
        "echo ===STACK_TOP===\\n",
        # Lit les 8 octets à RSP — c'est l'adresse de retour (éventuellement corrompue)
        "x/2xg $rsp",
    ]
    if has_exploitable:
        lines += [
            "echo ===EXPLOITABLE===\\n",
            "exploitable -v",
        ]
    lines.append("quit")
    return "\n".join(lines) + "\n"


def _parse_gdb_output(
    binary: str,
    crash_input: bytes,
    argv_extra: list[str],
    output: str,
) -> TriageResult:
    # Signal
    m = _RE_SIGSEGV.search(output)
    signal_name = m.group(1) if m else ""

    # Valeur de RIP — préfère la valeur à RSP (adresse de retour corrompue) sur le RIP courant
    rip_value: Optional[int] = None
    rip_hex = ""
    _re_xg = re.compile(r"0x[0-9a-f]+\s*:\s*(0x[0-9a-f]+)")

    # Tente d'extraire la valeur dépilée par ret depuis la section stack_top
    if "===STACK_TOP===" in output:
        stack_section = output.split("===STACK_TOP===", 1)[1].split("===", 1)[0]
        m = _re_xg.search(stack_section)
        if m:
            rip_hex = m.group(1)
            try:
                rip_value = int(rip_hex, 16)
            except ValueError:
                pass

    # Repli sur la valeur du registre RIP
    if rip_value is None and "===REGISTERS===" in output:
        reg_section = output.split("===REGISTERS===", 1)[1].split("===", 1)[0]
        m = _RE_RIP.search(reg_section)
        if m:
            rip_hex = m.group(1)
            try:
                rip_value = int(rip_hex, 16)
            except ValueError:
                pass

    # Backtrace
    bt = ""
    if "===BACKTRACE===" in output:
        bt = output.split("===BACKTRACE===", 1)[1].split("===", 1)[0].strip()

    # Exploitabilité
    exploitability = UNKNOWN
    exploit_reason = ""
    has_plugin = _exploitable_available()
    if has_plugin and "===EXPLOITABLE===" in output:
        exp_section = output.split("===EXPLOITABLE===", 1)[1]
        m = _RE_EXPLOIT.search(exp_section)
        if m:
            exploitability = m.group(1).upper()
        m = _RE_REASON.search(exp_section)
        if m:
            exploit_reason = m.group(2).strip()
    else:
        # Heuristique : si RIP ressemble à un pattern cyclique → probablement exploitable
        exploitability, exploit_reason = _heuristic_exploitability(rip_value, signal_name)

    # Calcul d'offset via cyclic_find
    offset = _find_offset(rip_value, crash_input)

    return TriageResult(
        binary=binary,
        stdin_data=crash_input,
        argv_extra=argv_extra,
        signal_name=signal_name,
        rip_value=rip_value,
        rip_hex=rip_hex,
        offset_to_rip=offset,
        exploitability=exploitability,
        exploitability_reason=exploit_reason,
        backtrace=bt[:1000],
        gdb_available=True,
        exploitable_plugin=has_plugin,
    )


# ── repli (pas de GDB) ────────────────────────────────────────────────────────

def _triage_fallback(
    binary_path: Path,
    crash_input: bytes,
    argv_extra: list[str],
) -> TriageResult:
    offset = _find_offset(None, crash_input)
    exploitability, reason = _heuristic_exploitability(None, "")
    return TriageResult(
        binary=str(binary_path),
        stdin_data=crash_input,
        argv_extra=argv_extra,
        signal_name="",
        rip_value=None,
        rip_hex="",
        offset_to_rip=offset,
        exploitability=exploitability,
        exploitability_reason=reason,
        backtrace="",
        gdb_available=False,
        exploitable_plugin=False,
    )


# ── calcul d'offset ───────────────────────────────────────────────────────────

def _find_offset(rip_value: Optional[int], crash_input: bytes) -> Optional[int]:
    """Tente de calculer l'offset depuis le début de crash_input jusqu'au RIP sauvegardé.

    Utilise pwntools cyclic_find si la valeur de RIP ressemble à un pattern cyclique.
    Repli sur une recherche par force brute dans les octets bruts de l'entrée.
    """
    if not crash_input:
        return None

    try:
        import logging as _l
        _l.getLogger("pwnlib").setLevel(_l.ERROR)
        from pwn import cyclic_find, cyclic, context
        context.log_level = "error"

        # Essaie la valeur de RIP directement (lookup little-endian 4 octets dans l'alphabet cyclique)
        if rip_value is not None:
            try:
                # cyclic_find accepte un int (4 octets) ou bytes (sous-séquence de 4 octets)
                offset = cyclic_find(rip_value & 0xFFFFFFFF)
                if 0 <= offset <= len(crash_input):
                    logger.debug("cyclic_find(0x%x) → offset=%d", rip_value, offset)
                    return offset
            except Exception:
                pass

        # Cherche dans l'entrée une sous-séquence cyclique de 4 octets
        pattern_len = len(crash_input)
        try:
            pat = cyclic(pattern_len)
        except Exception:
            return None

        # Trouve où le premier caractère cyclique apparaît dans crash_input
        for i in range(len(crash_input) - 4):
            chunk = crash_input[i: i + 4]
            try:
                off = cyclic_find(chunk)
                if 0 <= off < pattern_len:
                    return off
            except Exception:
                continue

    except ImportError:
        pass

    return None


# ── heuristiques d'exploitabilité ─────────────────────────────────────────────

def _heuristic_exploitability(
    rip_value: Optional[int],
    signal_name: str,
) -> tuple[str, str]:
    """Classifie l'exploitabilité sans le plugin exploitable."""
    if rip_value is not None:
        # RIP dans la plage de l'alphabet cyclique → contrôlé par l'attaquant
        high_byte = (rip_value >> 24) & 0xFF
        if 0x40 <= high_byte <= 0x7A:  # plage ASCII imprimable
            return PROBABLY_EXPLOITABLE, "RIP contient des octets ASCII — probablement contrôlé par l'attaquant"
        if rip_value == 0 or rip_value > 0x7FFFFFFFFFFF:
            return PROBABLY_NOT, "RIP est null/espace noyau — probable déréférencement NULL"
        return PROBABLY_EXPLOITABLE, "RIP redirigé — détournement de flux de contrôle potentiel"
    if signal_name in ("SIGSEGV", "SIGBUS"):
        return UNKNOWN, "Crash sans données de registre — supposé potentiellement exploitable"
    if signal_name == "SIGABRT":
        return PROBABLY_NOT, "SIGABRT généralement issu d'une assertion/abort — non exploitable directement"
    return UNKNOWN, ""


# ── moteur de sévérité ────────────────────────────────────────────────────────

def estimate_severity(
    triage: TriageResult,
    vuln_class: "VulnClass",
    protections: "Protection",
) -> "Severity":
    """Combine triage + vuln_class + protections en un niveau de Severity.

    Échelle documentée dans docs/algorithmes.md.
    """
    from vulnscan.report.model import Severity, VulnClass

    exploit = triage.exploitability
    has_offset = triage.offset_to_rip is not None

    # Score de base par classe
    base = {
        VulnClass.STACK_BOF:      4,
        VulnClass.HEAP_BOF:       3,
        VulnClass.FORMAT_STRING:  3,
        VulnClass.USE_AFTER_FREE: 3,
        VulnClass.INTEGER_OVERFLOW: 2,
        VulnClass.OFF_BY_ONE:     2,
        VulnClass.UNKNOWN:        1,
    }.get(vuln_class, 1)

    # Ajustement selon l'exploitabilité
    if exploit == EXPLOITABLE:
        base += 2
    elif exploit == PROBABLY_EXPLOITABLE:
        base += 1
    elif exploit == PROBABLY_NOT:
        base -= 1

    # Offset connu → plus précis (plus dangereux)
    if has_offset:
        base += 1

    # Mitigations présentes → score réduit
    if protections.canary:
        base -= 1
    if protections.nx:
        base -= 1
    if protections.pie:
        base -= 1
    if protections.relro == "full":
        base -= 1

    # Borne à [1, 5] et mappage vers Severity
    base = max(1, min(5, base))
    return [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL][base - 1]


# ── utilitaires ───────────────────────────────────────────────────────────────

def _gdb_available() -> bool:
    import shutil
    return shutil.which("gdb") is not None


def _exploitable_available() -> bool:
    """Vérifie si le plugin GDB exploitable du CERT est installé."""
    if not _gdb_available():
        return False
    try:
        result = shell_run(
            ["gdb", "--batch", "-ex", "source /usr/share/exploitable/exploitable.py",
             "-ex", "quit"],
            timeout=5, limit_resources=False,
        )
        return result.returncode == 0
    except Exception:
        pass
    # Vérifie aussi les chemins alternatifs courants
    import os
    paths = [
        os.path.expanduser("~/.gdb/exploitable/exploitable.py"),
        "/usr/lib/debug/exploitable.py",
    ]
    return any(os.path.exists(p) for p in paths)
