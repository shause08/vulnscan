"""ELF metadata extraction: arch, symbols, PLT imports, defined functions."""

from __future__ import annotations

import dataclasses
from pathlib import Path
from typing import Optional

import lief
import lief.ELF as ELFT

from vulnscan.utils.logging import get_logger

logger = get_logger(__name__)


@dataclasses.dataclass
class Symbol:
    name: str
    address: int
    size: int
    is_import: bool
    is_function: bool


@dataclasses.dataclass
class ELFInfo:
    path: str
    arch: str
    bits: int
    entry_point: int
    is_pie: bool
    imports: list[Symbol]
    functions: list[Symbol]
    sections: list[str]
    # PLT stub address → function name (resolved by dangerous_funcs via disasm)
    plt_map: dict[int, str]

    def import_names(self) -> set[str]:
        return {s.name for s in self.imports}

    def function_at(self, addr: int) -> Optional[str]:
        """Return the name of the function that contains *addr*, or None."""
        for fn in self.functions:
            if fn.size > 0 and fn.address <= addr < fn.address + fn.size:
                return fn.name
        # Fallback: closest function start that is <= addr
        best: Optional[Symbol] = None
        for fn in self.functions:
            if fn.address <= addr:
                if best is None or fn.address > best.address:
                    best = fn
        return best.name if best else None


def parse(binary_path: Path) -> ELFInfo:
    """Parse an ELF binary with lief and return an ELFInfo."""
    binary = lief.parse(str(binary_path))
    if binary is None:
        raise ValueError(f"lief could not parse {binary_path}")

    arch_map = {
        ELFT.ARCH.X86_64:  "x86-64",
        ELFT.ARCH.I386:    "x86",
        ELFT.ARCH.ARM:     "arm",
        ELFT.ARCH.AARCH64: "aarch64",
    }
    arch = arch_map.get(binary.header.machine_type, str(binary.header.machine_type))
    bits = 64 if binary.header.identity_class == ELFT.Header.CLASS.ELF64 else 32
    is_pie = binary.header.file_type == ELFT.Header.FILE_TYPE.DYN

    # PLT imports: dynamic symbols marked as imported
    imports: list[Symbol] = []
    for sym in binary.dynamic_symbols:
        if sym.imported and sym.name:
            imports.append(Symbol(
                name=sym.name,
                address=int(sym.value),
                size=int(sym.size),
                is_import=True,
                is_function=sym.type == ELFT.Symbol.TYPE.FUNC,
            ))

    # Locally defined functions (debug symbols)
    functions: list[Symbol] = []
    seen: set[str] = set()
    for sym in binary.symbols:
        if (sym.type == ELFT.Symbol.TYPE.FUNC
                and int(sym.value) != 0
                and sym.name
                and sym.name not in seen):
            seen.add(sym.name)
            functions.append(Symbol(
                name=sym.name,
                address=int(sym.value),
                size=int(sym.size),
                is_import=False,
                is_function=True,
            ))

    sections = [s.name for s in binary.sections if s.name]
    plt_map = _build_plt_map(binary)

    logger.debug(
        "ELF: %s  arch=%s  pie=%s  imports=%d  functions=%d  plt_entries=%d",
        binary_path.name, arch, is_pie, len(imports), len(functions), len(plt_map),
    )

    return ELFInfo(
        path=str(binary_path),
        arch=arch,
        bits=bits,
        entry_point=int(binary.header.entrypoint),
        is_pie=is_pie,
        imports=imports,
        functions=functions,
        sections=sections,
        plt_map=plt_map,
    )


def _build_plt_map(binary: lief.ELF.Binary) -> dict[int, str]:
    """Build {plt_stub_addr → func_name} by disassembling PLT sections.

    Handles both classic .plt and IBT/.plt.sec layouts (x86-64 with endbr64).
    """
    import capstone

    # GOT slot address → symbol name from PLTGOT relocations
    got_slot: dict[int, str] = {}
    for r in binary.pltgot_relocations:
        if r.symbol and r.symbol.name:
            got_slot[r.address] = r.symbol.name

    if not got_slot:
        return {}

    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True

    plt_map: dict[int, str] = {}

    # Sections that contain callable PLT stubs
    for sec_name in (".plt.sec", ".plt.got", ".plt"):
        sec = binary.get_section(sec_name)
        if sec is None:
            continue
        data = bytes(sec.content)
        base = sec.virtual_address

        # Walk instructions; a stub starts at a block boundary (every 16 bytes).
        # We record the start address of each block that contains a jmp-to-GOT.
        current_stub_start = base
        for insn in md.disasm(data, base):
            # A new 16-byte block
            if (insn.address - base) % 16 == 0:
                current_stub_start = insn.address

            if insn.mnemonic not in ("jmp", "bnd jmp"):
                continue
            if not insn.operands:
                continue
            op = insn.operands[0]
            if op.type != capstone.x86.X86_OP_MEM:
                continue

            # RIP-relative: target = next_insn_addr + disp
            rip = insn.address + insn.size
            got_addr = rip + op.mem.disp
            name = got_slot.get(got_addr)
            if name:
                plt_map[current_stub_start] = name

    return plt_map
