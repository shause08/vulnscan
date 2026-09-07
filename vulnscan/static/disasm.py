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

# Convention d'appel System V AMD64 : les 6 premiers arguments entiers sont dans ces registres
_ARG_REGS = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]

# Pour chaque fonction sink : (index_arg_buffer, index_arg_longueur)
# index_arg_longueur=None signifie que la fonction est non bornée (pas de paramètre de taille)
_SINK_ARGS: dict[str, tuple[int, Optional[int]]] = {
    "gets":     (0, None),   # gets(buf) — lit jusqu'à '\n', jamais borné
    "strcpy":   (0, None),   # strcpy(dst, src) — copie jusqu'à '\0', sans limite
    "strcat":   (0, None),   # strcat(dst, src) — concatène sans limite
    "sprintf":  (0, None),   # sprintf(buf, fmt, ...) — formate sans limite de longueur
    "vsprintf": (0, None),
    "read":     (1, 2),      # read(fd, buf, count) — buf=arg1, count=arg2
    "fgets":    (0, 1),      # fgets(buf, size, stream) — buf=arg0, size=arg1
    "memcpy":   (0, 2),      # memcpy(dst, src, n) — dst=arg0, n=arg2
    "memmove":  (0, 2),
    "scanf":    (0, None),   # scanf(fmt, ...) — le %s sans largeur est non borné
}


def analyze(binary_path: Path, elf_info: ELFInfo) -> list[Finding]:
    """Analyse chaque fonction définie pour détecter les incohérences tampon/longueur."""
    binary = lief.parse(str(binary_path))
    if binary is None:
        return []

    # Collecte les sections exécutables pour l'extraction des octets de chaque fonction
    sections = _exec_sections(binary)
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True  # nécessaire pour accéder aux types d'opérandes et aux registres

    findings: list[Finding] = []
    for fn in elf_info.functions:
        # Ignore les fonctions sans taille connue et les helpers internes du compilateur
        if fn.size == 0 or fn.name.startswith("__"):
            continue
        fn_bytes = _extract(fn, sections)
        if not fn_bytes:
            continue
        insns = list(md.disasm(fn_bytes, fn.address))
        if not insns:
            continue
        # Taille de la frame = valeur immédiate de "sub rsp, N" en prologue
        frame_size = _get_frame_size(insns)
        findings += _analyze_fn(fn.name, insns, frame_size, elf_info.plt_map)

    return findings


# ── fonctions utilitaires ─────────────────────────────────────────────────────

def _exec_sections(binary) -> list[tuple[int, int, bytes]]:
    """Retourne la liste (adresse_base, adresse_fin, octets) des sections exécutables.

    Le flag ELF SHF_EXECINSTR vaut 0x4 ; seules les sections avec ce flag contiennent du code.
    """
    result = []
    for sec in binary.sections:
        if int(sec.flags) & 0x4:   # SHF_EXECINSTR
            data = bytes(sec.content)
            if data:
                base = sec.virtual_address
                result.append((base, base + len(data), data))
    return result


def _extract(fn: Symbol, sections: list[tuple[int, int, bytes]]) -> bytes:
    """Extrait les octets correspondant à la fonction *fn* depuis les sections exécutables.

    Si la taille du symbole est nulle (binaire partiellement strippé), limite à 512 octets.
    """
    for base, end, data in sections:
        if base <= fn.address < end:
            start = fn.address - base
            length = fn.size if fn.size > 0 else min(512, end - fn.address)
            return data[start: start + length]
    return b""


def _get_frame_size(insns: list) -> int:
    """Retourne la taille de la frame de pile allouée par le prologue de la fonction.

    Cherche "sub rsp, N" dans les 12 premières instructions (le prologue est toujours court).
    Retourne 0 si l'instruction n'est pas trouvée (fonction sans frame locale).
    """
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
    """Simule l'état des registres instruction par instruction et détecte les appels dangereux.

    Maintient reg_state : nom_reg → ("imm", valeur) | ("rbp_rel", dépl) | ("unknown", 0)
    pour résoudre les arguments de chaque CALL vers les sinks connus.
    """
    findings: list[Finding] = []
    reg_state: dict[str, tuple[str, int]] = {}

    for insn in insns:
        mnem = insn.mnemonic
        ops  = insn.operands

        # MOV : propage les valeurs immédiates, les copies de registres, et les chargements mémoire
        if mnem == "mov" and len(ops) == 2:
            dst, src = ops
            if dst.type == capstone.x86.X86_OP_REG:
                d = _r64(insn, dst)
                if src.type == capstone.x86.X86_OP_IMM:
                    # Constante immédiate : taille connue
                    reg_state[d] = ("imm", int(src.imm))
                elif src.type == capstone.x86.X86_OP_REG:
                    # Copie de registre : propage le type et la valeur
                    reg_state[d] = reg_state.get(_r64(insn, src), ("unknown", 0))
                else:
                    # Chargement depuis la mémoire : valeur inconnue au moment de l'analyse
                    reg_state[d] = ("unknown", 0)

        # LEA : résout les adresses RBP-relatives (buffers sur la pile)
        elif mnem == "lea" and len(ops) == 2:
            dst, src = ops
            if dst.type == capstone.x86.X86_OP_REG and src.type == capstone.x86.X86_OP_MEM:
                d = _r64(insn, dst)
                base_name = insn.reg_name(src.mem.base) if src.mem.base else ""
                if base_name == "rbp":
                    # Adresse d'un slot de pile : mémorise le déplacement RBP-relatif
                    reg_state[d] = ("rbp_rel", src.mem.disp)
                else:
                    reg_state[d] = ("unknown", 0)

        # CALL : vérifie si la cible est un sink connu, puis efface les caller-saved
        elif mnem in ("call", "callq") and ops and ops[0].type == capstone.x86.X86_OP_IMM:
            target = int(ops[0].imm)
            callee = plt_map.get(target)
            if callee in _SINK_ARGS:
                f = _check_call(fn_name, callee, insn.address, reg_state, frame_size)
                if f:
                    findings.append(f)
            # Convention d'appel : les registres caller-saved sont écrasés après tout CALL
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
    """Évalue si l'appel à *callee* constitue une vulnérabilité de dépassement de tampon.

    Trois cas possibles :
    - Callee non borné (gets, strcpy…) → finding immédiat quelle que soit la taille
    - Longueur immédiate > taille du tampon → dépassement certain (HIGH)
    - Longueur non constante → dépassement potentiel si contrôlée par l'utilisateur (MEDIUM)
    """
    buf_arg_idx, len_arg_idx = _SINK_ARGS[callee]
    buf_reg = _ARG_REGS[buf_arg_idx]

    buf_type, buf_val = reg_state.get(buf_reg, ("unknown", 0))
    buf_space: Optional[int] = None
    # L'espace disponible est la valeur absolue du déplacement RBP négatif (offset depuis la frame)
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

    # Longueur immédiate connue et supérieure à la taille du tampon : dépassement certain
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

    # Longueur non constante : probablement contrôlée par l'utilisateur → MEDIUM
    if len_type in ("unknown", "rbp_rel"):
        if buf_space is not None:
            evidence = (
                f"{callee}() appelé avec longueur non constante (reg={len_reg}, "
                f"type={len_type}) dans buf@[rbp{buf_val:+d}] ({buf_space} octets) — débordement possible"
            )
        else:
            # Tampon heap (retour malloc stocké sur pile puis rechargé) — pas de taille statique
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
    """Détermine la classe de vulnérabilité selon le callee : HEAP_BOF pour les fonctions mémoire, STACK_BOF sinon."""
    return VulnClass.HEAP_BOF if callee in ("read", "recv", "memcpy", "memmove") \
        else VulnClass.STACK_BOF


def _r64(insn, op) -> str:
    """Normalise le nom d'un registre vers son équivalent 64 bits (ex. eax → rax, al → rax).

    Nécessaire car Capstone retourne le nom exact (eax, al…) selon la taille de l'opérande,
    mais on veut traquer les valeurs dans un seul slot par registre logique.
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
