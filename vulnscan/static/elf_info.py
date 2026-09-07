"""Extraction de métadonnées ELF : architecture, symboles, imports PLT, fonctions définies."""

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
    """Représente un symbole ELF (fonction importée ou définie localement)."""
    name: str
    address: int
    size: int        # taille en octets ; 0 si non renseignée dans le fichier
    is_import: bool  # True si le symbole provient d'une bibliothèque externe (PLT)
    is_function: bool


@dataclasses.dataclass
class ELFInfo:
    """Métadonnées extraites d'un binaire ELF, partagées entre tous les analyseurs statiques."""
    path: str
    arch: str          # "x86-64" | "x86" | "arm" | "aarch64"
    bits: int          # 32 ou 64
    entry_point: int
    is_pie: bool       # True si le fichier est de type DYN (Position-Independent Executable)
    imports: list[Symbol]    # fonctions importées depuis des bibliothèques partagées
    functions: list[Symbol]  # fonctions définies dans le binaire (symboles locaux)
    sections: list[str]      # noms des sections ELF présentes
    # Table {adresse_stub_PLT → nom_de_fonction}, construite depuis .plt.sec / .plt
    plt_map: dict[int, str]

    def import_names(self) -> set[str]:
        """Retourne l'ensemble des noms de fonctions importées (ex. {"gets", "printf"})."""
        return {s.name for s in self.imports}

    def function_at(self, addr: int) -> Optional[str]:
        """Retourne le nom de la fonction qui contient *addr*, ou None.

        Cherche d'abord par plage exacte [address, address+size[,
        puis repli sur la fonction dont l'adresse de début est la plus proche par en-dessous.
        """
        for fn in self.functions:
            if fn.size > 0 and fn.address <= addr < fn.address + fn.size:
                return fn.name
        # Repli : fonction la plus proche dont l'adresse est <= addr
        best: Optional[Symbol] = None
        for fn in self.functions:
            if fn.address <= addr:
                if best is None or fn.address > best.address:
                    best = fn
        return best.name if best else None


def parse(binary_path: Path) -> ELFInfo:
    """Analyse un binaire ELF avec lief et retourne un ELFInfo peuplé."""
    binary = lief.parse(str(binary_path))
    if binary is None:
        raise ValueError(f"lief ne peut pas analyser {binary_path}")

    # Mappage des types d'architecture lief vers des chaînes lisibles
    arch_map = {
        ELFT.ARCH.X86_64:  "x86-64",
        ELFT.ARCH.I386:    "x86",
        ELFT.ARCH.ARM:     "arm",
        ELFT.ARCH.AARCH64: "aarch64",
    }
    arch = arch_map.get(binary.header.machine_type, str(binary.header.machine_type))
    bits = 64 if binary.header.identity_class == ELFT.Header.CLASS.ELF64 else 32
    # Un binaire PIE est de type DYN (bibliothèque partagée) pour permettre le chargement à adresse variable
    is_pie = binary.header.file_type == ELFT.Header.FILE_TYPE.DYN

    # Imports PLT : symboles dynamiques marqués comme importés (provenant de libc, etc.)
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

    # Fonctions définies localement — présentes uniquement si le binaire n'est pas strippé
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
    # Construction de la PLT map — nécessaire pour résoudre les CALL indirects vers des fonctions dangereuses
    plt_map = _build_plt_map(binary)

    logger.debug(
        "ELF : %s  arch=%s  pie=%s  imports=%d  fonctions=%d  entrées_plt=%d",
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
    """Construit {adresse_stub_plt → nom_fonction} en désassemblant les sections PLT.

    Gère les layouts .plt classiques et IBT/.plt.sec (x86-64 avec endbr64).
    """
    import capstone

    # Adresse slot GOT → nom du symbole depuis les relocations PLTGOT
    got_slot: dict[int, str] = {}
    for r in binary.pltgot_relocations:
        if r.symbol and r.symbol.name:
            got_slot[r.address] = r.symbol.name

    if not got_slot:
        return {}

    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True   # nécessaire pour accéder aux opérandes et aux registres

    plt_map: dict[int, str] = {}

    # Parcourt les sections PLT dans l'ordre de priorité : .plt.sec (IBT) > .plt.got > .plt
    for sec_name in (".plt.sec", ".plt.got", ".plt"):
        sec = binary.get_section(sec_name)
        if sec is None:
            continue
        data = bytes(sec.content)
        base = sec.virtual_address

        # Chaque stub occupe un bloc de 16 octets alignés ; on suit le début du bloc courant
        current_stub_start = base
        for insn in md.disasm(data, base):
            # Nouveau bloc de 16 octets → nouvelle entrée de stub potentielle
            if (insn.address - base) % 16 == 0:
                current_stub_start = insn.address

            # Seuls les JMP vers la GOT nous intéressent (jmp/bnd jmp à opérande mémoire)
            if insn.mnemonic not in ("jmp", "bnd jmp"):
                continue
            if not insn.operands:
                continue
            op = insn.operands[0]
            if op.type != capstone.x86.X86_OP_MEM:
                continue

            # Calcul de l'adresse GOT : RIP pointe sur l'instruction suivante au moment de l'exécution
            rip = insn.address + insn.size
            got_addr = rip + op.mem.disp
            name = got_slot.get(got_addr)
            if name:
                plt_map[current_stub_start] = name

    return plt_map
