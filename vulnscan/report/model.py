"""Modèle de données pour les résultats de scan."""

from __future__ import annotations

import dataclasses
from datetime import datetime
from enum import Enum
from typing import Optional


class Severity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


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
    nx: bool = False
    canary: bool = False
    relro: str = "no"          # "no" | "partial" | "full"
    pie: bool = False
    fortify: bool = False
    rpath: bool = False
    aslr: str = "unknown"      # "full" | "partial" | "disabled" | "unknown"

    def as_dict(self) -> dict:
        return dataclasses.asdict(self)


@dataclasses.dataclass
class Finding:
    vuln_class: VulnClass
    function: str
    location: str                          # adresse / offset / fichier:ligne
    severity: Severity
    confidence: str                        # "static" | "dynamic" | "both"
    analysis: str                          # "static" | "dynamic"
    evidence: str
    offset: Optional[int] = None           # octets jusqu'au RIP sauvegardé, si connu
    cwe: Optional[str] = None

    def as_dict(self) -> dict:
        d = dataclasses.asdict(self)
        d["vuln_class"] = self.vuln_class.value
        d["severity"] = self.severity.value
        return d


@dataclasses.dataclass
class ScanResult:
    binary_path: str
    arch: str
    protections: Protection
    findings: list[Finding]
    timestamp: str = dataclasses.field(
        default_factory=lambda: datetime.utcnow().isoformat()
    )
    duration_s: float = 0.0
    scan_mode: str = "static+dynamic"

    def as_dict(self) -> dict:
        return {
            "binary_path": self.binary_path,
            "arch": self.arch,
            "timestamp": self.timestamp,
            "duration_s": self.duration_s,
            "scan_mode": self.scan_mode,
            "protections": self.protections.as_dict(),
            "findings": [f.as_dict() for f in self.findings],
            "summary": {
                s.value: sum(1 for f in self.findings if f.severity == s)
                for s in Severity
            },
        }
