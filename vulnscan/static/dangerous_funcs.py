"""Detect calls to dangerous/unsafe C functions.

Strategy:
  1. Check PLT imports for known dangerous function names.
  2. Use the plt_map built by elf_info (stub_addr → name) to locate call sites:
     disassemble every executable section with capstone and find CALL instructions
     whose target address is a known PLT stub.
  3. Emit one Finding per unique (calling_function, dangerous_callee) pair.
"""

from __future__ import annotations

import dataclasses
from pathlib import Path

import capstone
import lief
import lief.ELF as ELFT

from vulnscan.report.model import Finding, Severity, VulnClass
from vulnscan.static.elf_info import ELFInfo
from vulnscan.utils.logging import get_logger

logger = get_logger(__name__)


@dataclasses.dataclass(frozen=True)
class DangerousFunc:
    name: str
    vuln_class: VulnClass
    severity: Severity
    reason: str
    cwe: str


_CATALOGUE: list[DangerousFunc] = [
    DangerousFunc("gets",     VulnClass.STACK_BOF,     Severity.CRITICAL,
                  "reads unbounded input into stack buffer", "CWE-121"),
    DangerousFunc("strcpy",   VulnClass.STACK_BOF,     Severity.HIGH,
                  "copies string with no length check", "CWE-121"),
    DangerousFunc("strcat",   VulnClass.STACK_BOF,     Severity.HIGH,
                  "concatenates string with no length check", "CWE-121"),
    DangerousFunc("sprintf",  VulnClass.STACK_BOF,     Severity.HIGH,
                  "formats into fixed buffer with no length limit", "CWE-121"),
    DangerousFunc("vsprintf", VulnClass.STACK_BOF,     Severity.HIGH,
                  "formats into fixed buffer with no length limit", "CWE-121"),
    DangerousFunc("scanf",    VulnClass.STACK_BOF,     Severity.MEDIUM,
                  "may read unbounded string with %%s", "CWE-121"),
    DangerousFunc("sscanf",   VulnClass.STACK_BOF,     Severity.MEDIUM,
                  "may read unbounded string with %%s", "CWE-121"),
    DangerousFunc("memcpy",   VulnClass.HEAP_BOF,      Severity.MEDIUM,
                  "copies user-controlled length — no bounds guard", "CWE-122"),
    DangerousFunc("memmove",  VulnClass.HEAP_BOF,      Severity.MEDIUM,
                  "moves user-controlled length — no bounds guard", "CWE-122"),
    DangerousFunc("printf",   VulnClass.FORMAT_STRING, Severity.HIGH,
                  "direct call — first argument may be user-controlled", "CWE-134"),
    DangerousFunc("fprintf",  VulnClass.FORMAT_STRING, Severity.HIGH,
                  "direct call — format argument may be user-controlled", "CWE-134"),
    DangerousFunc("system",   VulnClass.STACK_BOF,     Severity.CRITICAL,
                  "executes shell command — dangerous if argument is tainted", "CWE-78"),
    DangerousFunc("popen",    VulnClass.STACK_BOF,     Severity.CRITICAL,
                  "opens a pipe to a shell command", "CWE-78"),
    DangerousFunc("alloca",   VulnClass.STACK_BOF,     Severity.MEDIUM,
                  "stack allocation with user-controlled size", "CWE-121"),
    DangerousFunc("read",     VulnClass.HEAP_BOF,      Severity.MEDIUM,
                  "reads user-controlled number of bytes — dangerous if len > buffer", "CWE-122"),
    DangerousFunc("recv",     VulnClass.HEAP_BOF,      Severity.MEDIUM,
                  "reads user-controlled number of bytes from socket", "CWE-122"),
]

_CATALOGUE_MAP: dict[str, DangerousFunc] = {d.name: d for d in _CATALOGUE}


def analyze(binary_path: Path, elf_info: ELFInfo) -> list[Finding]:
    """Return static Findings for dangerous function usage."""
    findings: list[Finding] = []

    imported_names = elf_info.import_names()
    dangerous_imported = {n for n in imported_names if n in _CATALOGUE_MAP}

    if not dangerous_imported:
        logger.debug("%s: no dangerous imports", binary_path.name)
        return findings

    logger.debug("%s: dangerous imports: %s", binary_path.name, ", ".join(sorted(dangerous_imported)))

    # Restrict plt_map to dangerous functions only
    dangerous_plt: dict[int, str] = {
        addr: name
        for addr, name in elf_info.plt_map.items()
        if name in dangerous_imported
    }

    call_sites = _find_call_sites(binary_path, elf_info, dangerous_plt)

    emitted: set[tuple[str, str]] = set()
    for callee_name in dangerous_imported:
        info = _CATALOGUE_MAP[callee_name]
        sites = call_sites.get(callee_name, [])

        if sites:
            by_caller: dict[str, list[int]] = {}
            for addr, caller in sites:
                by_caller.setdefault(caller, []).append(addr)

            for caller, addrs in by_caller.items():
                key = (callee_name, caller)
                if key in emitted:
                    continue
                emitted.add(key)
                addr_list = ", ".join(f"0x{a:x}" for a in sorted(addrs))
                findings.append(Finding(
                    vuln_class=info.vuln_class,
                    function=caller,
                    location=addr_list,
                    severity=info.severity,
                    confidence="static",
                    analysis="static",
                    evidence=f"calls {callee_name}() at [{addr_list}] — {info.reason}",
                    cwe=info.cwe,
                ))
        else:
            # Import visible but call site not resolved (stripped / indirect call)
            key = (callee_name, "<import>")
            if key not in emitted:
                emitted.add(key)
                findings.append(Finding(
                    vuln_class=info.vuln_class,
                    function="<import>",
                    location="PLT",
                    severity=info.severity,
                    confidence="static",
                    analysis="static",
                    evidence=(
                        f"{callee_name} in PLT imports (call site not resolved) "
                        f"— {info.reason}"
                    ),
                    cwe=info.cwe,
                ))

    return findings


def _find_call_sites(
    binary_path: Path,
    elf_info: ELFInfo,
    dangerous_plt: dict[int, str],
) -> dict[str, list[tuple[int, str]]]:
    """Disassemble executable sections; collect CALL sites targeting dangerous PLT stubs."""
    if not dangerous_plt:
        return {}

    binary = lief.parse(str(binary_path))
    if binary is None:
        return {}

    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = False

    results: dict[str, list[tuple[int, str]]] = {}

    for section in binary.sections:
        # SHF_EXECINSTR = 0x4
        if not (int(section.flags) & 0x4):
            continue
        data = bytes(section.content)
        if not data:
            continue
        base = section.virtual_address

        for insn in md.disasm(data, base):
            if insn.mnemonic not in ("call", "callq"):
                continue
            try:
                target = int(insn.op_str, 16)
            except ValueError:
                continue

            callee = dangerous_plt.get(target)
            if callee is None:
                continue

            call_site = insn.address
            caller = elf_info.function_at(call_site) or "<unknown>"
            results.setdefault(callee, []).append((call_site, caller))

    return results
