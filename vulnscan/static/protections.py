"""Binary protection detection (checksec).

Cross-checks pwntools ELF.checksec() with our own lief-based reading.
"""

from __future__ import annotations

from pathlib import Path

import lief
import lief.ELF as ELFT

from vulnscan.report.model import Protection
from vulnscan.utils.logging import get_logger

logger = get_logger(__name__)

import logging as _logging
_logging.getLogger("pwnlib").setLevel(_logging.ERROR)
from pwn import ELF, context  # noqa: E402
context.log_level = "error"


def detect(binary_path: Path) -> Protection:
    """Return a Protection dataclass for *binary_path*."""
    lief_result = _lief_checksec(binary_path)
    pwn_result  = _pwntools_checksec(binary_path)

    nx      = lief_result["nx"]      or pwn_result["nx"]
    canary  = lief_result["canary"]  or pwn_result["canary"]
    pie     = lief_result["pie"]     or pwn_result["pie"]
    fortify = lief_result["fortify"] or pwn_result["fortify"]
    rpath   = lief_result["rpath"]

    relro_rank = {"no": 0, "partial": 1, "full": 2}
    relro = max(
        lief_result["relro"],
        pwn_result["relro"],
        key=lambda r: relro_rank.get(r, 0),
    )

    prot = Protection(
        nx=nx, canary=canary, relro=relro, pie=pie,
        fortify=fortify, rpath=rpath,
        aslr=_detect_aslr(),
    )
    logger.debug("protections for %s: %s", binary_path.name, prot)
    return prot


def _lief_checksec(binary_path: Path) -> dict:
    binary = lief.parse(str(binary_path))
    result = dict(nx=False, canary=False, relro="no", pie=False, fortify=False, rpath=False)
    if binary is None:
        return result

    # NX: GNU_STACK without execute flag
    for seg in binary.segments:
        if seg.type == ELFT.Segment.TYPE.GNU_STACK:
            result["nx"] = not bool(int(seg.flags) & int(ELFT.Segment.FLAGS.X))
            break

    dyn_names = {s.name for s in binary.dynamic_symbols if s.name}
    result["canary"]  = "__stack_chk_fail" in dyn_names
    result["fortify"] = any(n.endswith("_chk") for n in dyn_names)
    result["pie"]     = binary.header.file_type == ELFT.Header.FILE_TYPE.DYN

    result["rpath"] = (
        binary.has(ELFT.DynamicEntry.TAG.RPATH) or
        binary.has(ELFT.DynamicEntry.TAG.RUNPATH)
    )

    has_relro_seg = any(
        s.type == ELFT.Segment.TYPE.GNU_RELRO for s in binary.segments
    )
    has_bind_now = (
        binary.has(ELFT.DynamicEntry.TAG.BIND_NOW) or
        _has_flag_now(binary)
    )

    if has_relro_seg and has_bind_now:
        result["relro"] = "full"
    elif has_relro_seg:
        result["relro"] = "partial"

    return result


def _has_flag_now(binary: lief.ELF.Binary) -> bool:
    for entry in binary.dynamic_entries:
        if entry.tag == ELFT.DynamicEntry.TAG.FLAGS:
            return bool(entry.value & 0x8)   # DF_BIND_NOW
        if entry.tag == ELFT.DynamicEntry.TAG.FLAGS_1:
            return bool(entry.value & 0x1)   # DF_1_NOW
    return False


def _detect_aslr() -> str:
    """Read system ASLR level from /proc/sys/kernel/randomize_va_space."""
    try:
        val = Path("/proc/sys/kernel/randomize_va_space").read_text().strip()
        return {"0": "disabled", "1": "partial", "2": "full"}.get(val, "unknown")
    except OSError:
        return "unknown"


def _pwntools_checksec(binary_path: Path) -> dict:
    result = dict(nx=False, canary=False, relro="no", pie=False, fortify=False)
    try:
        elf = ELF(str(binary_path), checksec=False)
        cs  = elf.checksec
        result["nx"]      = bool(cs.get("nx", False))
        result["canary"]  = bool(cs.get("canary", False))
        result["pie"]     = bool(cs.get("pie", False))
        result["fortify"] = bool(cs.get("fortify", False))
        relro_raw = cs.get("relro", "no")
        if isinstance(relro_raw, str):
            result["relro"] = relro_raw.lower()
        elif relro_raw is False:
            result["relro"] = "no"
        else:
            result["relro"] = "partial"
    except Exception as exc:
        logger.debug("pwntools checksec failed for %s: %s", binary_path.name, exc)
    return result
