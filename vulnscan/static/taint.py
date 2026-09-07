"""Propagation de teinte intra-procédurale : détection de flux source → sink.

Décisions de conception et limites
------------------------------------
- Parcours linéaire en une passe (pas de CFG) : chaque instruction est visitée une fois
  dans l'ordre. Cela sur-approxime (union de tous les chemins) → faux positifs possibles.
- TOUS les registres généraux sont suivis dans reg_state, permettant de résoudre
  correctement les patterns en deux étapes comme `lea rax,[rbp-X]; mov rdi,rax`.
- Les slots de pile sont suivis par offset RBP-relatif ; l'indexation RSP-base et
  l'arithmétique de pointeur via des registres non-rbp ne sont pas résolues.
- Pas d'analyse inter-procédurale : la teinte ne franchit pas les frontières de fonctions.
- angr n'est intentionnellement pas utilisé ; c'est le repli Python pur.

Sources : fonctions dont le tampon de sortie/destination contient des données utilisateur.
Sinks   : fonctions dont les arguments teintés constituent une vulnérabilité.
"""

from __future__ import annotations

import dataclasses
from pathlib import Path
from typing import Optional

import capstone
import capstone.x86
import lief

from vulnscan.report.model import Finding, Severity, VulnClass
from vulnscan.static.elf_info import ELFInfo, Symbol
from vulnscan.utils.logging import get_logger

logger = get_logger(__name__)

# Convention d'appel System V AMD64
_ARG_REGS = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]
# Registres caller-saved : leur valeur n'est pas préservée à travers un CALL
_CALLER_SAVED = {"rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11"}

# Source : index de l'argument dont la destination mémoire est teintée après l'appel.
# -1 signifie que c'est la valeur de retour (registre rax) qui est teintée.
_SOURCES: dict[str, int] = {
    "gets":    0,   # gets(buf)          → buf teinté (rdi)
    "read":    1,   # read(fd,buf,n)     → buf teinté (rsi)
    "recv":    1,   # recv(fd,buf,n,f)   → buf teinté (rsi)
    "fgets":   0,   # fgets(buf,n,fp)    → buf teinté (rdi)
    "scanf":   0,   # approximation : premier argument non-format
    "sscanf":  1,   # approximation
    "getenv":  -1,  # valeur de retour dans rax est un pointeur teinté
    "getline": 0,
}

# Sink : indices des arguments qui, s'ils sont teintés, constituent une vulnérabilité.
# Plusieurs indices = plusieurs arguments dangereux pour le même sink.
_SINKS: dict[str, list[int]] = {
    "strcpy":   [1],      # src est dangereux si teinté (arg1=rsi)
    "strcat":   [1],
    "sprintf":  [1],      # chaîne de format (arg1=rsi)
    "vsprintf": [1],
    "printf":   [0],      # chaîne de format (arg0=rdi)
    "fprintf":  [1],      # chaîne de format (arg1=rsi)
    "system":   [0],      # commande shell (arg0=rdi) — injection de commande
    "popen":    [0],
    "execve":   [0],
    "execl":    [0],
    "memcpy":   [1, 2],   # src et longueur peuvent tous deux être dangereux
    "memmove":  [1, 2],
}


@dataclasses.dataclass
class _State:
    """État courant du tracker de teinte pour une fonction."""
    # Noms des registres contenant actuellement une valeur issue d'une source utilisateur
    regs: set[str] = dataclasses.field(default_factory=set)
    # Offsets RBP-relatifs de la pile dont la valeur est teintée (ex. {-64} pour [rbp-0x40])
    stack: set[int] = dataclasses.field(default_factory=set)
    # Valeur symbolique de chaque registre : reg → ("imm"|"rbp_rel"|"unknown", valeur)
    regs_val: dict[str, tuple[str, int]] = dataclasses.field(default_factory=dict)


def analyze(binary_path: Path, elf_info: ELFInfo) -> list[Finding]:
    """Lance le tracking de teinte sur toutes les fonctions non-internes du binaire."""
    binary = lief.parse(str(binary_path))
    if binary is None:
        return []

    # Sections exécutables nécessaires pour extraire les octets de chaque fonction
    sections = _exec_sections(binary)
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True  # obligatoire pour accéder aux types d'opérandes

    findings: list[Finding] = []
    for fn in elf_info.functions:
        # Ignore les fonctions sans taille et les helpers internes du compilateur (__…)
        if fn.size == 0 or fn.name.startswith("__"):
            continue
        fn_bytes = _extract(fn, sections)
        if not fn_bytes:
            continue
        insns = list(md.disasm(fn_bytes, fn.address))
        if insns:
            findings += _track(fn.name, insns, elf_info.plt_map)

    return findings


# ── tracker par fonction ──────────────────────────────────────────────────────

def _track(fn_name: str, insns: list, plt_map: dict[int, str]) -> list[Finding]:
    """Propage la teinte instruction par instruction et signale les flux dangereux."""
    findings: list[Finding] = []
    st = _State()  # état vierge à l'entrée de chaque fonction

    for insn in insns:
        mnem = insn.mnemonic
        ops  = insn.operands

        # ── MOV : propage valeurs immédiates, copies de registres, et chargements mémoire ──
        if mnem == "mov" and len(ops) == 2:
            dst, src = ops

            # reg ← constante immédiate : valeur connue, jamais teintée
            if dst.type == capstone.x86.X86_OP_REG and src.type == capstone.x86.X86_OP_IMM:
                d = _r64(insn, dst)
                st.regs_val[d] = ("imm", int(src.imm))
                st.regs.discard(d)

            # reg ← reg : propage la teinte et la valeur symbolique
            elif dst.type == capstone.x86.X86_OP_REG and src.type == capstone.x86.X86_OP_REG:
                d = _r64(insn, dst)
                s = _r64(insn, src)
                st.regs_val[d] = st.regs_val.get(s, ("unknown", 0))
                if s in st.regs:
                    st.regs.add(d)
                else:
                    st.regs.discard(d)

            # reg ← [rbp+disp] : chargement d'un slot de pile
            elif dst.type == capstone.x86.X86_OP_REG and src.type == capstone.x86.X86_OP_MEM:
                d = _r64(insn, dst)
                breg = insn.reg_name(src.mem.base) if src.mem.base else ""
                if breg == "rbp":
                    st.regs_val[d] = ("rbp_rel", src.mem.disp)
                    # Si le slot de pile est teinté, le registre le devient aussi
                    if src.mem.disp in st.stack:
                        st.regs.add(d)
                    else:
                        st.regs.discard(d)
                else:
                    # Adresse non-RBP : valeur inconnue, on ne peut pas la tracer
                    st.regs_val[d] = ("unknown", 0)
                    st.regs.discard(d)

            # [rbp+disp] ← reg : stockage dans un slot de pile, propage la teinte
            elif dst.type == capstone.x86.X86_OP_MEM and src.type == capstone.x86.X86_OP_REG:
                breg = insn.reg_name(dst.mem.base) if dst.mem.base else ""
                s = _r64(insn, src)
                if breg == "rbp":
                    if s in st.regs:
                        st.stack.add(dst.mem.disp)
                    else:
                        st.stack.discard(dst.mem.disp)

        # ── LEA : résout les adresses RBP-relatives (pointeurs vers des buffers de pile) ──
        elif mnem == "lea" and len(ops) == 2:
            dst, src = ops
            if dst.type == capstone.x86.X86_OP_REG and src.type == capstone.x86.X86_OP_MEM:
                d = _r64(insn, dst)
                breg = insn.reg_name(src.mem.base) if src.mem.base else ""
                if breg == "rbp":
                    disp = src.mem.disp
                    st.regs_val[d] = ("rbp_rel", disp)
                    # Un pointeur vers un slot de pile teinté est lui-même teinté
                    if disp in st.stack:
                        st.regs.add(d)
                    else:
                        st.regs.discard(d)
                else:
                    st.regs_val[d] = ("unknown", 0)
                    st.regs.discard(d)

        # ── CALL : applique la source ou vérifie le sink, puis efface les caller-saved ──
        elif mnem in ("call", "callq") and ops and ops[0].type == capstone.x86.X86_OP_IMM:
            target = int(ops[0].imm)
            callee = plt_map.get(target)

            if callee in _SOURCES:
                # La source injecte de la teinte dans le tampon de destination
                _apply_source(callee, st, insn.address)
            elif callee in _SINKS:
                # Vérifie si un argument du sink est teinté
                f = _check_sink(fn_name, callee, insn.address, st)
                if f:
                    findings.append(f)

            # Après tout CALL, les caller-saved sont considérés écrasés (convention d'appel)
            for r in _CALLER_SAVED - {"rax"}:
                st.regs.discard(r)
                st.regs_val.pop(r, None)
            # rax est préservé uniquement si la source vient d'y placer une valeur teintée
            if callee not in _SOURCES or _SOURCES.get(callee) != -1:
                st.regs.discard("rax")
                st.regs_val.pop("rax", None)

    return findings


def _apply_source(callee: str, st: _State, call_addr: int) -> None:
    """Marque le tampon de destination de *callee* comme teinté après l'appel."""
    arg_idx = _SOURCES[callee]
    if arg_idx == -1:
        # getenv() : la valeur de retour (rax) pointe vers une chaîne contrôlée par l'environnement
        st.regs.add("rax")
        return

    arg_reg = _ARG_REGS[arg_idx]
    buf_type, buf_val = st.regs_val.get(arg_reg, ("unknown", 0))

    # Le registre pointant vers le tampon devient teinté (il contient maintenant des données user)
    st.regs.add(arg_reg)
    # Marque aussi le slot de pile pour que les rechargements LEA/MOV propagent la teinte
    if buf_type == "rbp_rel":
        st.stack.add(buf_val)
        logger.debug("source de teinte %s @ 0x%x : stack[rbp%+d] teinté", callee, call_addr, buf_val)
    else:
        logger.debug("source de teinte %s @ 0x%x : %s teinté (offset inconnu)", callee, call_addr, arg_reg)


def _check_sink(
    caller: str,
    callee: str,
    call_addr: int,
    st: _State,
) -> Optional[Finding]:
    """Vérifie si un argument teinté du sink constitue une vulnérabilité et crée un Finding."""
    # Cas spécial : printf/fprintf avec un tampon de pile comme chaîne de format
    # (détectable même sans propagation inter-procédurale grâce à l'heuristique rbp_rel)
    fmt_finding = _check_stack_format_string(caller, callee, call_addr, st)
    if fmt_finding:
        return fmt_finding

    # Vérifie chaque argument du sink listé dans _SINKS
    tainted_args: list[int] = []
    for arg_idx in _SINKS.get(callee, []):
        if arg_idx >= len(_ARG_REGS):
            continue
        arg_reg = _ARG_REGS[arg_idx]
        # Un argument est teinté si le registre est marqué, ou si le slot de pile pointé l'est
        tainted = arg_reg in st.regs
        if not tainted:
            rtype, rval = st.regs_val.get(arg_reg, ("unknown", 0))
            if rtype == "rbp_rel" and rval in st.stack:
                tainted = True
        if tainted:
            tainted_args.append(arg_idx)

    if not tainted_args:
        return None

    arg_desc = ", ".join(f"arg{i}({_ARG_REGS[i]})" for i in tainted_args)
    return Finding(
        vuln_class=_sink_vc(callee),
        function=caller,
        location=f"0x{call_addr:x}",
        severity=_sink_sev(callee),
        confidence="static",
        analysis="static",
        evidence=(
            f"entrée utilisateur teintée vers {callee}({arg_desc}) à 0x{call_addr:x}"
        ),
        cwe=_sink_cwe(callee),
    )


def _check_stack_format_string(
    caller: str,
    callee: str,
    call_addr: int,
    st: _State,
) -> Optional[Finding]:
    """Détecte printf/fprintf dont l'argument format est un tampon de pile (pas .rodata).

    Capture le pattern courant `printf(buf)` même sans propagation de teinte inter-procédurale,
    car tout tampon de pile comme chaîne de format est suspect.
    """
    # Seuls printf et fprintf ont un argument de format susceptible d'être sur la pile
    fmt_sinks = {
        "printf":  0,   # format = arg0 (rdi)
        "fprintf": 1,   # format = arg1 (rsi) — arg0 est le FILE*
    }
    if callee not in fmt_sinks:
        return None

    fmt_arg_idx = fmt_sinks[callee]
    fmt_reg = _ARG_REGS[fmt_arg_idx]
    rtype, rval = st.regs_val.get(fmt_reg, ("unknown", 0))

    # Si le registre de format contient une adresse RBP-relative, c'est un buffer local
    # et non une chaîne littérale depuis .rodata → vulnérabilité de chaîne de format
    if rtype != "rbp_rel":
        return None

    return Finding(
        vuln_class=VulnClass.FORMAT_STRING,
        function=caller,
        location=f"0x{call_addr:x}",
        severity=Severity.HIGH,
        confidence="static",
        analysis="static",
        evidence=(
            f"{callee}() appelé avec une chaîne de format allouée sur la pile "
            f"(arg{fmt_arg_idx}={fmt_reg} → [rbp{rval:+d}]) à 0x{call_addr:x} "
            f"— probablement contrôlée par l'utilisateur si buf rempli par fgets/read/gets"
        ),
        cwe="CWE-134",
    )


# ── utilitaires ───────────────────────────────────────────────────────────────

def _exec_sections(binary) -> list[tuple[int, int, bytes]]:
    """Retourne (adresse_base, adresse_fin, octets) pour toutes les sections exécutables (SHF_EXECINSTR=0x4)."""
    result = []
    for sec in binary.sections:
        if int(sec.flags) & 0x4:
            data = bytes(sec.content)
            if data:
                base = sec.virtual_address
                result.append((base, base + len(data), data))
    return result


def _extract(fn: Symbol, sections: list[tuple[int, int, bytes]]) -> bytes:
    """Extrait les octets de *fn* depuis les sections exécutables.

    Limite à 512 octets si la taille du symbole est nulle (binaire partiellement strippé).
    """
    for base, end, data in sections:
        if base <= fn.address < end:
            start = fn.address - base
            length = fn.size if fn.size > 0 else min(512, end - fn.address)
            return data[start: start + length]
    return b""


def _r64(insn, op) -> str:
    """Normalise le nom d'un registre vers son équivalent 64 bits (ex. eax → rax, dil → rdi).

    Capstone retourne le nom exact de la variante utilisée dans l'instruction (8, 16, 32 ou 64 bits),
    mais on veut un seul slot par registre logique pour simplifier le tracking.
    """
    name = insn.reg_name(op.reg)
    _sub = {
        "eax": "rax", "ax": "rax", "al": "rax", "ah": "rax",
        "ebx": "rbx", "bx": "rbx", "bl": "rbx", "bh": "rbx",
        "ecx": "rcx", "cx": "rcx", "cl": "rcx", "ch": "rcx",
        "edx": "rdx", "dx": "rdx", "dl": "rdx", "dh": "rdx",
        "esi": "rsi", "si": "rsi", "sil": "rsi",
        "edi": "rdi", "di": "rdi", "dil": "rdi",
        "r8d": "r8",  "r8w": "r8",  "r8b": "r8",
        "r9d": "r9",  "r9w": "r9",  "r9b": "r9",
    }
    return _sub.get(name, name)


def _sink_vc(callee: str) -> VulnClass:
    """Retourne la classe de vulnérabilité correspondant au sink (format-string, stack ou heap BOF)."""
    if callee in ("printf", "fprintf", "sprintf", "vsprintf"):
        return VulnClass.FORMAT_STRING
    if callee in ("system", "popen", "execve", "execl"):
        return VulnClass.STACK_BOF  # injection de commande → traité comme contrôle de flux
    return VulnClass.STACK_BOF


def _sink_sev(callee: str) -> Severity:
    """Attribue la sévérité de base selon le sink : CRITICAL pour les shells, HIGH sinon."""
    if callee in ("system", "popen", "execve", "execl"):
        return Severity.CRITICAL   # exécution de commande directe → impact maximal
    if callee in ("printf", "fprintf"):
        return Severity.HIGH
    return Severity.HIGH


def _sink_cwe(callee: str) -> str:
    """Retourne l'identifiant CWE le plus approprié pour le sink."""
    if callee in ("printf", "fprintf", "sprintf", "vsprintf"):
        return "CWE-134"   # chaîne de format non contrôlée
    if callee in ("system", "popen", "execve", "execl"):
        return "CWE-78"    # injection de commande OS
    return "CWE-121"       # dépassement de tampon de pile
