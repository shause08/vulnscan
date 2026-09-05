"""Analyse de taille de frame et détection d'incohérences tampon/longueur.

Pour chaque fonction :
  1. Localise l'allocation de frame (sub rsp, N) pour obtenir la taille totale.
  2. Suit LEA/MOV pour TOUS les registres (pas seulement les registres d'arguments)
     afin de résoudre les patterns en deux étapes comme `lea rax,[rbp-0x40]; mov rdi,rax`.
  3. Déduit la taille disponible du tampon depuis son offset RBP-relatif.
  4. Pour les appels avec un argument longueur visible (read/memcpy/fgets),
     compare avec la taille du tampon et signale les incohérences.
  5. Pour les appels non bornés (gets, strcpy), signale toujours.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import capstone
import capstone.x86
import lief

from vulnscan.report.model import Finding, Severity, VulnClass
from vulnscan.static.elf_info import ELFInfo, Symbol
from vulnscan.utils.logging import get_logger

logger = get_logger(__name__)

_ARG_REGS = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]

# callee → (idx_arg_buf, idx_arg_len) ; idx_arg_len=None signifie non borné
_SINK_ARGS: dict[str, tuple[int, Optional[int]]] = {
    "gets":     (0, None),
    "strcpy":   (0, None),
    "strcat":   (0, None),
    "sprintf":  (0, None),
    "vsprintf": (0, None),
    "read":     (1, 2),
    "fgets":    (0, 1),
    "memcpy":   (0, 2),
    "memmove":  (0, 2),
    "scanf":    (0, None),
}


def analyze(binary_path: Path, elf_info: ELFInfo) -> list[Finding]:
    binary = lief.parse(str(binary_path))
    if binary is None:
        return []

    sections = _exec_sections(binary)
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True

    findings: list[Finding] = []
    for fn in elf_info.functions:
        if fn.size == 0 or fn.name.startswith("__"):
            continue
        fn_bytes = _extract(fn, sections)
        if not fn_bytes:
            continue
        insns = list(md.disasm(fn_bytes, fn.address))
        if not insns:
            continue
        frame_size = _get_frame_size(insns)
        findings += _analyze_fn(fn.name, insns, frame_size, elf_info.plt_map)

    return findings


# ── fonctions utilitaires ─────────────────────────────────────────────────────

def _exec_sections(binary) -> list[tuple[int, int, bytes]]:
    result = []
    for sec in binary.sections:
        if int(sec.flags) & 0x4:
            data = bytes(sec.content)
            if data:
                base = sec.virtual_address
                result.append((base, base + len(data), data))
    return result


def _extract(fn: Symbol, sections: list[tuple[int, int, bytes]]) -> bytes:
    for base, end, data in sections:
        if base <= fn.address < end:
            start = fn.address - base
            length = fn.size if fn.size > 0 else min(512, end - fn.address)
            return data[start: start + length]
    return b""


def _get_frame_size(insns: list) -> int:
    for insn in insns[:12]:
        if insn.mnemonic == "sub" and insn.operands:
            ops = insn.operands
            if (len(ops) == 2
                    and ops[0].type == capstone.x86.X86_OP_REG
                    and insn.reg_name(ops[0].reg) == "rsp"
                    and ops[1].type == capstone.x86.X86_OP_IMM):
                return int(ops[1].imm)
    return 0


def _analyze_fn(
    fn_name: str,
    insns: list,
    frame_size: int,
    plt_map: dict[int, str],
) -> list[Finding]:
    findings: list[Finding] = []
    # reg_state : nom_reg → ("imm", valeur) | ("rbp_rel", dépl) | ("unknown", 0)
    reg_state: dict[str, tuple[str, int]] = {}

    for insn in insns:
        mnem = insn.mnemonic
        ops  = insn.operands

        if mnem == "mov" and len(ops) == 2:
            dst, src = ops
            if dst.type == capstone.x86.X86_OP_REG:
                d = _r64(insn, dst)
                if src.type == capstone.x86.X86_OP_IMM:
                    reg_state[d] = ("imm", int(src.imm))
                elif src.type == capstone.x86.X86_OP_REG:
                    reg_state[d] = reg_state.get(_r64(insn, src), ("unknown", 0))
                else:
                    reg_state[d] = ("unknown", 0)

        elif mnem == "lea" and len(ops) == 2:
            dst, src = ops
            if dst.type == capstone.x86.X86_OP_REG and src.type == capstone.x86.X86_OP_MEM:
                d = _r64(insn, dst)
                base_name = insn.reg_name(src.mem.base) if src.mem.base else ""
                if base_name == "rbp":
                    reg_state[d] = ("rbp_rel", src.mem.disp)
                else:
                    reg_state[d] = ("unknown", 0)

        elif mnem in ("call", "callq") and ops and ops[0].type == capstone.x86.X86_OP_IMM:
            target = int(ops[0].imm)
            callee = plt_map.get(target)
            if callee in _SINK_ARGS:
                f = _check_call(fn_name, callee, insn.address, reg_state, frame_size)
                if f:
                    findings.append(f)
            # Les registres caller-saved sont écrasés après tout appel
            for r in ("rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11"):
                reg_state.pop(r, None)

    return findings


def _check_call(
    caller: str,
    callee: str,
    call_addr: int,
    reg_state: dict[str, tuple[str, int]],
    frame_size: int,
) -> Optional[Finding]:
    buf_arg_idx, len_arg_idx = _SINK_ARGS[callee]
    buf_reg = _ARG_REGS[buf_arg_idx]

    buf_type, buf_val = reg_state.get(buf_reg, ("unknown", 0))
    buf_space: Optional[int] = None
    if buf_type == "rbp_rel" and buf_val < 0:
        buf_space = abs(buf_val)

    # ── Callee non borné ──────────────────────────────────────────────────────
    if len_arg_idx is None:
        if buf_space is not None:
            evidence = (
                f"{callee}() écrit des données non bornées dans "
                f"buf@[rbp{buf_val:+d}] ({buf_space} octets disponibles sur {frame_size} octets de frame)"
            )
        else:
            evidence = f"{callee}() écrit des données non bornées (adresse du tampon non résolue statiquement)"
        return Finding(
            vuln_class=VulnClass.STACK_BOF,
            function=caller,
            location=f"0x{call_addr:x}",
            severity=Severity.HIGH,
            confidence="static",
            analysis="static",
            evidence=evidence,
            cwe="CWE-121",
        )

    # ── Callee avec longueur explicite ────────────────────────────────────────
    len_reg = _ARG_REGS[len_arg_idx]
    len_type, len_val = reg_state.get(len_reg, ("unknown", 0))

    if len_type == "imm" and buf_space is not None and len_val > buf_space:
        evidence = (
            f"{callee}() longueur={len_val} > taille_buf={buf_space} "
            f"(buf@[rbp{buf_val:+d}], frame={frame_size} octets) à 0x{call_addr:x}"
        )
        return Finding(
            vuln_class=_vc(callee),
            function=caller,
            location=f"0x{call_addr:x}",
            severity=Severity.HIGH,
            confidence="static",
            analysis="static",
            evidence=evidence,
            cwe="CWE-121" if _vc(callee) == VulnClass.STACK_BOF else "CWE-122",
        )

    # Longueur non constante (depuis registre/variable de pile — probablement contrôlée par l'utilisateur)
    if len_type in ("unknown", "rbp_rel"):
        if buf_space is not None:
            evidence = (
                f"{callee}() appelé avec longueur non constante (reg={len_reg}, "
                f"type={len_type}) dans buf@[rbp{buf_val:+d}] ({buf_space} octets) — débordement possible"
            )
        else:
            # Tampon heap (retour malloc stocké sur pile puis chargé) — pas de taille statique
            evidence = (
                f"{callee}() appelé avec longueur non constante (reg={len_reg}, "
                f"type={len_type}) — taille du tampon inconnue (heap ?), longueur peut dépasser l'allocation"
            )
        return Finding(
            vuln_class=_vc(callee),
            function=caller,
            location=f"0x{call_addr:x}",
            severity=Severity.MEDIUM,
            confidence="static",
            analysis="static",
            evidence=evidence,
            cwe="CWE-122",
        )

    return None


def _vc(callee: str) -> VulnClass:
    return VulnClass.HEAP_BOF if callee in ("read", "recv", "memcpy", "memmove") \
        else VulnClass.STACK_BOF


def _r64(insn, op) -> str:
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
