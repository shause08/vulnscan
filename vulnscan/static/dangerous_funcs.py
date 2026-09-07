"""Détection des appels à des fonctions C dangereuses/non sécurisées.

Stratégie :
  1. Vérifie les imports PLT pour les noms de fonctions dangereuses connus.
  2. Utilise la plt_map construite par elf_info (adresse_stub → nom) pour localiser
     les sites d'appel : désassemble chaque section exécutable avec capstone et
     trouve les instructions CALL dont la cible est un stub PLT dangereux.
  3. Émet un Finding par paire unique (fonction_appelante, callee_dangereux).
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
                  "lit une entrée non bornée dans un tampon de pile", "CWE-121"),
    DangerousFunc("strcpy",   VulnClass.STACK_BOF,     Severity.HIGH,
                  "copie une chaîne sans vérification de longueur", "CWE-121"),
    DangerousFunc("strcat",   VulnClass.STACK_BOF,     Severity.HIGH,
                  "concatène une chaîne sans vérification de longueur", "CWE-121"),
    DangerousFunc("sprintf",  VulnClass.STACK_BOF,     Severity.HIGH,
                  "formate dans un tampon fixe sans limite de longueur", "CWE-121"),
    DangerousFunc("vsprintf", VulnClass.STACK_BOF,     Severity.HIGH,
                  "formate dans un tampon fixe sans limite de longueur", "CWE-121"),
    DangerousFunc("scanf",    VulnClass.STACK_BOF,     Severity.MEDIUM,
                  "peut lire une chaîne non bornée avec %%s", "CWE-121"),
    DangerousFunc("sscanf",   VulnClass.STACK_BOF,     Severity.MEDIUM,
                  "peut lire une chaîne non bornée avec %%s", "CWE-121"),
    DangerousFunc("memcpy",   VulnClass.HEAP_BOF,      Severity.MEDIUM,
                  "copie une longueur contrôlée par l'utilisateur — sans garde de borne", "CWE-122"),
    DangerousFunc("memmove",  VulnClass.HEAP_BOF,      Severity.MEDIUM,
                  "déplace une longueur contrôlée par l'utilisateur — sans garde de borne", "CWE-122"),
    # printf/fprintf : détection déléguée à l'analyse de teinte (taint.py)
    # qui vérifie réellement si l'argument de format est contrôlé par l'utilisateur.
    # Les inclure ici génère un faux positif sur tout binaire qui affiche du texte.
    DangerousFunc("system",   VulnClass.STACK_BOF,     Severity.CRITICAL,
                  "exécute une commande shell — dangereux si l'argument est contaminé", "CWE-78"),
    DangerousFunc("popen",    VulnClass.STACK_BOF,     Severity.CRITICAL,
                  "ouvre un tube vers une commande shell", "CWE-78"),
    DangerousFunc("alloca",   VulnClass.STACK_BOF,     Severity.MEDIUM,
                  "allocation de pile avec taille contrôlée par l'utilisateur", "CWE-121"),
    DangerousFunc("read",     VulnClass.HEAP_BOF,      Severity.MEDIUM,
                  "lit un nombre d'octets contrôlé par l'utilisateur — dangereux si len > tampon", "CWE-122"),
    DangerousFunc("recv",     VulnClass.HEAP_BOF,      Severity.MEDIUM,
                  "lit un nombre d'octets contrôlé par l'utilisateur depuis une socket", "CWE-122"),
]

_CATALOGUE_MAP: dict[str, DangerousFunc] = {d.name: d for d in _CATALOGUE}


def analyze(binary_path: Path, elf_info: ELFInfo) -> list[Finding]:
    """Retourne les Findings statiques pour l'utilisation de fonctions dangereuses.

    Flux :
    1. Intersecte les imports du binaire avec le catalogue pour obtenir les fonctions dangereuses présentes.
    2. Restreint la PLT map aux seuls stubs dangereux (optimisation : réduit le désassemblage).
    3. Pour chaque site d'appel trouvé, émet un Finding par paire unique (callee, caller).
    4. Si un import est visible mais sans site d'appel résolu (binaire strippé), émet quand même un finding.
    """
    findings: list[Finding] = []

    # Étape 1 : quelles fonctions dangereuses sont réellement importées par ce binaire ?
    imported_names = elf_info.import_names()
    dangerous_imported = {n for n in imported_names if n in _CATALOGUE_MAP}

    if not dangerous_imported:
        logger.debug("%s : aucun import dangereux", binary_path.name)
        return findings

    logger.debug("%s : imports dangereux : %s", binary_path.name, ", ".join(sorted(dangerous_imported)))

    # Étape 2 : filtre la PLT map pour ne désassembler que les CALL vers des fonctions dangereuses
    dangerous_plt: dict[int, str] = {
        addr: name
        for addr, name in elf_info.plt_map.items()
        if name in dangerous_imported
    }

    # Étape 3 : désassemble les sections exécutables et collecte les sites d'appel
    call_sites = _find_call_sites(binary_path, elf_info, dangerous_plt)

    emitted: set[tuple[str, str]] = set()  # évite les doublons (callee, caller)
    for callee_name in dangerous_imported:
        info = _CATALOGUE_MAP[callee_name]
        sites = call_sites.get(callee_name, [])

        if sites:
            # Regroupe les adresses d'appel par fonction appelante
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
                    evidence=f"appel à {callee_name}() en [{addr_list}] — {info.reason}",
                    cwe=info.cwe,
                ))
        else:
            # Étape 4 : import PLT visible sans site d'appel résolu (binaire strippé ou appel indirect)
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
                        f"{callee_name} dans les imports PLT (site d'appel non résolu) "
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
    """Désassemble les sections exécutables et collecte les sites CALL ciblant des stubs PLT dangereux.

    Retourne {nom_callee → [(adresse_call, nom_caller), …]}.
    md.detail=False suffit ici car on ne lit que l'opérande immédiate via op_str.
    """
    if not dangerous_plt:
        return {}

    binary = lief.parse(str(binary_path))
    if binary is None:
        return {}

    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = False  # pas besoin du détail des opérandes, on lit directement op_str

    results: dict[str, list[tuple[int, str]]] = {}

    for section in binary.sections:
        # SHF_EXECINSTR = 0x4 : seules les sections de code nous intéressent
        if not (int(section.flags) & 0x4):
            continue
        data = bytes(section.content)
        if not data:
            continue
        base = section.virtual_address

        for insn in md.disasm(data, base):
            # On ne s'intéresse qu'aux instructions CALL directes (opérande = adresse immédiate)
            if insn.mnemonic not in ("call", "callq"):
                continue
            try:
                target = int(insn.op_str, 16)
            except ValueError:
                continue  # CALL indirect (via registre) : non traçable statiquement

            callee = dangerous_plt.get(target)
            if callee is None:
                continue

            # Résout la fonction contenant ce CALL pour identifier le "caller"
            call_site = insn.address
            caller = elf_info.function_at(call_site) or "<unknown>"
            results.setdefault(callee, []).append((call_site, caller))

    return results
