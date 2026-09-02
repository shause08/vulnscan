"""Frame-size analysis and buffer-vs-length inconsistency detection.

For each function:
  1. Locate the frame allocation (sub rsp, N) to get total frame size.
  2. Track LEA/MOV for ALL registers (not just arg regs) so that 2-step
     patterns like `lea rax,[rbp-0x40]; mov rdi,rax` are resolved.
  3. Derive the buffer's available size from its RBP-relative offset.
  4. For calls where a length argument is visible (read/memcpy/fgets),
     compare it against the buffer size and flag inconsistencies.
  5. For unbounded calls (gets, strcpy), always flag.
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

# callee → (buf_arg_idx, len_arg_idx); len_arg_idx=None means unbounded
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


# ── helpers ───────────────────────────────────────────────────────────────────

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
    # reg_state: reg_name → ("imm", value) | ("rbp_rel", disp) | ("unknown", 0)
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
            # Caller-saved regs are clobbered after any call
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

    # ── Unbounded callee ──────────────────────────────────────────────────────
    if len_arg_idx is None:
        if buf_space is not None:
            evidence = (
                f"{callee}() writes unbounded data into "
                f"buf@[rbp{buf_val:+d}] ({buf_space}B available in {frame_size}B frame)"
            )
        else:
            evidence = f"{callee}() writes unbounded data (buffer address not statically resolved)"
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

    # ── Callee with explicit length ───────────────────────────────────────────
    len_reg = _ARG_REGS[len_arg_idx]
    len_type, len_val = reg_state.get(len_reg, ("unknown", 0))

    if len_type == "imm" and buf_space is not None and len_val > buf_space:
        evidence = (
            f"{callee}() length={len_val} > buf_size={buf_space} "
            f"(buf@[rbp{buf_val:+d}], frame={frame_size}B) at 0x{call_addr:x}"
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

    # Length is non-constant (from register/stack variable — likely user-controlled)
    if len_type in ("unknown", "rbp_rel"):
        if buf_space is not None:
            evidence = (
                f"{callee}() called with non-constant length (reg={len_reg}, "
                f"type={len_type}) into buf@[rbp{buf_val:+d}] ({buf_space}B) — may overflow"
            )
        else:
            # Heap buffer (malloc return stored in stack then loaded) — no static size
            evidence = (
                f"{callee}() called with non-constant length (reg={len_reg}, "
                f"type={len_type}) — buffer size unknown (heap?), length may exceed allocation"
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
