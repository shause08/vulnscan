"""Modèle de données pour les résultats de scan."""

from __future__ import annotations

import dataclasses
from datetime import datetime
from enum import Enum
from typing import Optional


# Niveaux de gravité croissants — utilisés pour trier et filtrer les findings
class Severity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


# Classes de vulnérabilité reconnues par vulnscan
class VulnClass(str, Enum):
    STACK_BOF = "stack-buffer-overflow"
    HEAP_BOF = "heap-buffer-overflow"
    FORMAT_STRING = "format-string"
    INTEGER_OVERFLOW = "integer-overflow"
    USE_AFTER_FREE = "use-after-free"
    OFF_BY_ONE = "off-by-one"
    UNKNOWN = "unknown"


@dataclasses.dataclass
class Protection:
    """Protections binaires détectées sur le binaire analysé."""
    nx: bool = False
    canary: bool = False
    relro: str = "no"          # "no" | "partial" | "full"
    pie: bool = False
    fortify: bool = False
    rpath: bool = False
    aslr: str = "unknown"      # "full" | "partial" | "disabled" | "unknown"

    def as_dict(self) -> dict:
        # Convertit en dict sérialisable pour le rapport JSON/HTML
        return dataclasses.asdict(self)


@dataclasses.dataclass
class Finding:
    """Une vulnérabilité détectée dans le binaire, avec sa preuve et sa sévérité."""
    vuln_class: VulnClass
    function: str              # nom de la fonction où la vulnérabilité a été détectée
    location: str              # adresse hex, offset ou fichier:ligne (ASan)
    severity: Severity
    confidence: str            # "static" | "dynamic" | "both" (les deux analyses concordent)
    analysis: str              # "static" | "dynamic" — quelle phase a produit ce finding
    evidence: str              # texte libre expliquant la preuve
    offset: Optional[int] = None   # octets depuis le début de l'entrée jusqu'au RIP sauvegardé
    cwe: Optional[str] = None      # identifiant CWE associé (ex. "CWE-121")

    def as_dict(self) -> dict:
        # Sérialise le finding en dict JSON-compatible (enums → valeurs string)
        d = dataclasses.asdict(self)
        d["vuln_class"] = self.vuln_class.value
        d["severity"] = self.severity.value
        return d


@dataclasses.dataclass
class ScanResult:
    """Résultat complet d'un scan — agrège tous les findings et métadonnées."""
    binary_path: str
    arch: str
    protections: Protection
    findings: list[Finding]
    timestamp: str = dataclasses.field(
        # Horodatage UTC de début de scan, généré automatiquement
        default_factory=lambda: datetime.utcnow().isoformat()
    )
    duration_s: float = 0.0
    scan_mode: str = "static+dynamic"  # "static" | "dynamic" | "static+dynamic"

    def as_dict(self) -> dict:
        # Sérialise l'ensemble du résultat en dict plat pour JSON/HTML
        return {
            "binary_path": self.binary_path,
            "arch": self.arch,
            "timestamp": self.timestamp,
            "duration_s": self.duration_s,
            "scan_mode": self.scan_mode,
            "protections": self.protections.as_dict(),
            "findings": [f.as_dict() for f in self.findings],
            # Résumé du nombre de findings par niveau de sévérité
            "summary": {
                s.value: sum(1 for f in self.findings if f.severity == s)
                for s in Severity
            },
        }
