"""Intra-procedural taint tracking: source → sink flow detection.

Design decisions and limits
----------------------------
- Single-pass linear scan (no CFG): each instruction visited once in order.
  This over-approximates (union of all paths) → possible false positives.
- ALL general-purpose registers are tracked in reg_state so 2-step patterns
  like `lea rax,[rbp-X]; mov rdi,rax` are correctly propagated.
- Stack slots are tracked by RBP-relative offset; RSP-based indexing and
  pointer arithmetic through non-rbp registers are not resolved.
- No inter-procedural analysis: taint does not cross function boundaries.
- angr is intentionally not used; this is the pure-Python fallback.

Sources: functions whose output/destination buffer contains user data.
Sinks  : functions where tainted arguments constitute a vulnerability.
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

_ARG_REGS = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]
# Caller-saved registers that are clobbered across calls
_CALLER_SAVED = {"rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11"}

# Source: arg index whose memory destination is tainted after the call,
#         or -1 to mean the return value (rax).
_SOURCES: dict[str, int] = {
    "gets":    0,   # gets(buf)          → buf tainted (rdi)
    "read":    1,   # read(fd,buf,n)     → buf tainted (rsi)
    "recv":    1,   # recv(fd,buf,n,f)   → buf tainted (rsi)
    "fgets":   0,   # fgets(buf,n,fp)    → buf tainted (rdi)
    "scanf":   0,   # approximate: first non-fmt arg
    "sscanf":  1,   # approximate
    "getenv":  -1,  # return value in rax is a tainted pointer
    "getline": 0,
}

# Sink: arg indices that — if tainted — constitute a finding.
_SINKS: dict[str, list[int]] = {
    "strcpy":   [1],      # src is dangerous (arg1=rsi)
    "strcat":   [1],
    "sprintf":  [1],      # format string (arg1=rsi)
    "vsprintf": [1],
    "printf":   [0],      # format string (arg0=rdi)
    "fprintf":  [1],      # format string (arg1=rsi)
    "system":   [0],      # command (arg0=rdi)
    "popen":    [0],
    "execve":   [0],
    "execl":    [0],
    "memcpy":   [1, 2],   # src and len
    "memmove":  [1, 2],
}


@dataclasses.dataclass
class _State:
    # Registers holding tainted values
    regs: set[str] = dataclasses.field(default_factory=set)
    # RBP-relative stack slots that are tainted
    stack: set[int] = dataclasses.field(default_factory=set)
    # Full register state: reg → ("imm"|"rbp_rel"|"unknown", value)
    regs_val: dict[str, tuple[str, int]] = dataclasses.field(default_factory=dict)


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
        if insns:
            findings += _track(fn.name, insns, elf_info.plt_map)

    return findings


# ── per-function tracker ──────────────────────────────────────────────────────

def _track(fn_name: str, insns: list, plt_map: dict[int, str]) -> list[Finding]:
    findings: list[Finding] = []
    st = _State()

    for insn in insns:
        mnem = insn.mnemonic
        ops  = insn.operands

        # ── MOV ──────────────────────────────────────────────────────────────
        if mnem == "mov" and len(ops) == 2:
            dst, src = ops

            # reg ← imm
            if dst.type == capstone.x86.X86_OP_REG and src.type == capstone.x86.X86_OP_IMM:
                d = _r64(insn, dst)
                st.regs_val[d] = ("imm", int(src.imm))
                st.regs.discard(d)

            # reg ← reg
            elif dst.type == capstone.x86.X86_OP_REG and src.type == capstone.x86.X86_OP_REG:
                d = _r64(insn, dst)
                s = _r64(insn, src)
                st.regs_val[d] = st.regs_val.get(s, ("unknown", 0))
                if s in st.regs:
                    st.regs.add(d)
                else:
                    st.regs.discard(d)

            # reg ← [rbp+disp]
            elif dst.type == capstone.x86.X86_OP_REG and src.type == capstone.x86.X86_OP_MEM:
                d = _r64(insn, dst)
                breg = insn.reg_name(src.mem.base) if src.mem.base else ""
                if breg == "rbp":
                    st.regs_val[d] = ("rbp_rel", src.mem.disp)
                    if src.mem.disp in st.stack:
                        st.regs.add(d)
                    else:
                        st.regs.discard(d)
                else:
                    st.regs_val[d] = ("unknown", 0)
                    st.regs.discard(d)

            # [rbp+disp] ← reg
            elif dst.type == capstone.x86.X86_OP_MEM and src.type == capstone.x86.X86_OP_REG:
                breg = insn.reg_name(dst.mem.base) if dst.mem.base else ""
                s = _r64(insn, src)
                if breg == "rbp":
                    if s in st.regs:
                        st.stack.add(dst.mem.disp)
                    else:
                        st.stack.discard(dst.mem.disp)

        # ── LEA ──────────────────────────────────────────────────────────────
        elif mnem == "lea" and len(ops) == 2:
            dst, src = ops
            if dst.type == capstone.x86.X86_OP_REG and src.type == capstone.x86.X86_OP_MEM:
                d = _r64(insn, dst)
                breg = insn.reg_name(src.mem.base) if src.mem.base else ""
                if breg == "rbp":
                    disp = src.mem.disp
                    st.regs_val[d] = ("rbp_rel", disp)
                    # Pointer to a tainted stack slot is itself tainted
                    if disp in st.stack:
                        st.regs.add(d)
                    else:
                        st.regs.discard(d)
                else:
                    st.regs_val[d] = ("unknown", 0)
                    st.regs.discard(d)

        # ── CALL ─────────────────────────────────────────────────────────────
        elif mnem in ("call", "callq") and ops and ops[0].type == capstone.x86.X86_OP_IMM:
            target = int(ops[0].imm)
            callee = plt_map.get(target)

            if callee in _SOURCES:
                _apply_source(callee, st, insn.address)
            elif callee in _SINKS:
                f = _check_sink(fn_name, callee, insn.address, st)
                if f:
                    findings.append(f)

            # Clobber caller-saved registers (except rax which sources may set)
            for r in _CALLER_SAVED - {"rax"}:
                st.regs.discard(r)
                st.regs_val.pop(r, None)
            # rax clobbered unless we just set it in _apply_source
            if callee not in _SOURCES or _SOURCES.get(callee) != -1:
                st.regs.discard("rax")
                st.regs_val.pop("rax", None)

    return findings


def _apply_source(callee: str, st: _State, call_addr: int) -> None:
    arg_idx = _SOURCES[callee]
    if arg_idx == -1:
        st.regs.add("rax")
        return

    arg_reg = _ARG_REGS[arg_idx]
    buf_type, buf_val = st.regs_val.get(arg_reg, ("unknown", 0))

    # Mark the arg register as tainted (it is the buffer that was filled)
    st.regs.add(arg_reg)
    # Mark the stack slot so LEA-based reloads propagate taint later
    if buf_type == "rbp_rel":
        st.stack.add(buf_val)
        logger.debug("taint source %s @ 0x%x: stack[rbp%+d] tainted", callee, call_addr, buf_val)
    else:
        logger.debug("taint source %s @ 0x%x: %s tainted (offset unknown)", callee, call_addr, arg_reg)


def _check_sink(
    caller: str,
    callee: str,
    call_addr: int,
    st: _State,
) -> Optional[Finding]:
    # Special case: printf/fprintf with a stack-allocated format string.
    # Even without inter-procedural taint, a stack buffer as format arg is
    # almost certainly a format string vulnerability (CWE-134).
    fmt_finding = _check_stack_format_string(caller, callee, call_addr, st)
    if fmt_finding:
        return fmt_finding

    tainted_args: list[int] = []
    for arg_idx in _SINKS.get(callee, []):
        if arg_idx >= len(_ARG_REGS):
            continue
        arg_reg = _ARG_REGS[arg_idx]
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
            f"tainted user-input flows into {callee}({arg_desc}) at 0x{call_addr:x}"
        ),
        cwe=_sink_cwe(callee),
    )


def _check_stack_format_string(
    caller: str,
    callee: str,
    call_addr: int,
    st: _State,
) -> Optional[Finding]:
    """Detect printf/fprintf where the format arg is a stack buffer (not .rodata).

    This catches the common `printf(buf)` pattern even without taint propagation
    across function calls, because any stack-allocated format string is suspicious.
    """
    fmt_sinks = {
        "printf":  0,   # format = arg0 (rdi)
        "fprintf": 1,   # format = arg1 (rsi)
    }
    if callee not in fmt_sinks:
        return None

    fmt_arg_idx = fmt_sinks[callee]
    fmt_reg = _ARG_REGS[fmt_arg_idx]
    rtype, rval = st.regs_val.get(fmt_reg, ("unknown", 0))

    # A stack-allocated format string: the register holds an RBP-relative address
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
            f"{callee}() called with stack-allocated format string "
            f"(arg{fmt_arg_idx}={fmt_reg} → [rbp{rval:+d}]) at 0x{call_addr:x} "
            f"— likely user-controlled if buf was filled by fgets/read/gets"
        ),
        cwe="CWE-134",
    )


# ── utilities ─────────────────────────────────────────────────────────────────

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


def _sink_vc(callee: str) -> VulnClass:
    if callee in ("printf", "fprintf", "sprintf", "vsprintf"):
        return VulnClass.FORMAT_STRING
    if callee in ("system", "popen", "execve", "execl"):
        return VulnClass.STACK_BOF
    return VulnClass.STACK_BOF


def _sink_sev(callee: str) -> Severity:
    if callee in ("system", "popen", "execve", "execl"):
        return Severity.CRITICAL
    if callee in ("printf", "fprintf"):
        return Severity.HIGH
    return Severity.HIGH


def _sink_cwe(callee: str) -> str:
    if callee in ("printf", "fprintf", "sprintf", "vsprintf"):
        return "CWE-134"
    if callee in ("system", "popen", "execve", "execl"):
        return "CWE-78"
    return "CWE-121"
