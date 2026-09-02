"""Report generator: JSON serialisation + Jinja2 HTML rendering.

Entry points
------------
render_json(result)  → str   (pretty-printed JSON)
render_html(result)  → str   (self-contained HTML, no external assets)
save(result, path, *, html=False)  → saves JSON and optionally HTML
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from vulnscan.report.model import ScanResult

_TEMPLATES_DIR = Path(__file__).parent / "templates"

# ── JSON ──────────────────────────────────────────────────────────────────────

def render_json(result: "ScanResult") -> str:
    """Serialise *result* to a pretty-printed JSON string."""
    return json.dumps(result.as_dict(), indent=2, ensure_ascii=False)


# ── HTML ──────────────────────────────────────────────────────────────────────

def render_html(result: "ScanResult") -> str:
    """Render *result* to a self-contained HTML string via Jinja2."""
    try:
        import jinja2
    except ImportError as exc:
        raise ImportError("jinja2 is required for HTML reports: pip install jinja2") from exc

    loader = jinja2.FileSystemLoader(str(_TEMPLATES_DIR))
    env = jinja2.Environment(
        loader=loader,
        autoescape=jinja2.select_autoescape(["html", "j2"]),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    # Custom filters
    env.filters["severity_class"] = _severity_class
    env.filters["protection_label"] = _protection_label
    env.filters["vuln_explain"] = _vuln_explain

    tmpl = env.get_template("report.html.j2")

    from vulnscan.report.model import Severity, VulnClass
    findings_sorted = sorted(
        result.findings,
        key=lambda f: _severity_order(f.severity),
        reverse=True,
    )
    summary = result.as_dict()["summary"]

    return tmpl.render(
        result=result,
        findings=findings_sorted,
        summary=summary,
        Severity=Severity,
        VulnClass=VulnClass,
        binary_name=Path(result.binary_path).name,
        impact_items=_compute_impact(result),
    )


# ── save helper ───────────────────────────────────────────────────────────────

def save(result: "ScanResult", path: Path) -> None:
    """Write the HTML report to *path*."""
    Path(path).write_text(render_html(result), encoding="utf-8")


# ── template filters ──────────────────────────────────────────────────────────

def _severity_order(sev) -> int:
    from vulnscan.report.model import Severity
    return {
        Severity.INFO:     1,
        Severity.LOW:      2,
        Severity.MEDIUM:   3,
        Severity.HIGH:     4,
        Severity.CRITICAL: 5,
    }.get(sev, 0)


def _severity_class(sev_value: str) -> str:
    return {
        "CRITICAL": "sev-critical",
        "HIGH":     "sev-high",
        "MEDIUM":   "sev-medium",
        "LOW":      "sev-low",
        "INFO":     "sev-info",
    }.get(sev_value.upper(), "sev-info")


def _protection_label(value) -> str:
    """Return 'yes' / 'no' / the string itself for relro."""
    if isinstance(value, bool):
        return "yes" if value else "no"
    return str(value)


_VULN_EXPLAIN = {
    "stack-buffer-overflow": (
        "Écriture au-delà d'un tampon sur la pile — l'adresse de retour et les variables "
        "locales adjacentes peuvent être écrasées, redirigeant le flux d'exécution."
    ),
    "heap-buffer-overflow": (
        "Écriture au-delà d'un tampon alloué sur le tas — les métadonnées de l'allocateur "
        "ou les objets voisins sont corrompus, pouvant mener à une exécution de code."
    ),
    "format-string": (
        "Chaîne de format contrôlée par l'utilisateur transmise à printf/sprintf — "
        "permet une lecture/écriture arbitraire en mémoire via les spécificateurs %x/%n."
    ),
    "integer-overflow": (
        "Dépassement d'un entier produisant une valeur tronquée utilisée comme taille "
        "d'allocation ou indice — mène généralement à un buffer overflow secondaire."
    ),
    "use-after-free": (
        "Accès à une zone mémoire après sa libération — un attaquant contrôlant "
        "l'allocateur peut substituer un objet malveillant et provoquer une exécution de code."
    ),
    "off-by-one": (
        "Dépassement d'un seul octet au-delà d'un tampon — suffit pour corrompre "
        "l'octet de longueur d'un chunk voisin ou un pointeur de pile adjacent."
    ),
}


def _vuln_explain(vuln_class_value: str) -> str:
    return _VULN_EXPLAIN.get(str(vuln_class_value), "")


# ── impact analysis ───────────────────────────────────────────────────────────

def _compute_impact(result: "ScanResult") -> list[dict]:
    """Build a list of protection-impact items for the HTML report.

    Each item: {"level": "critical|high|medium|good", "title": str, "description": str}
    """
    from vulnscan.report.model import VulnClass

    p = result.protections
    classes = {f.vuln_class for f in result.findings}

    has_stack_bof = bool(classes & {VulnClass.STACK_BOF, VulnClass.OFF_BY_ONE})
    has_any_bof   = bool(classes & {VulnClass.STACK_BOF, VulnClass.HEAP_BOF,
                                    VulnClass.OFF_BY_ONE})
    has_fmt       = VulnClass.FORMAT_STRING in classes
    has_uaf       = VulnClass.USE_AFTER_FREE in classes
    aslr_weak     = p.aslr in ("disabled", "partial", "unknown")

    items: list[dict] = []

    # ── missing protections ──────────────────────────────────────────────────
    if not p.canary and has_stack_bof:
        items.append({
            "level": "critical",
            "title": "No stack canary — return address unprotected",
            "description": (
                "Stack buffer overflow and off-by-one vulnerabilities can directly overwrite "
                "the saved return address without triggering any runtime check. "
                "Exploitation is straightforward once the stack offset to RIP is known."
            ),
        })

    if not p.nx and has_any_bof:
        items.append({
            "level": "critical",
            "title": "NX disabled — stack and heap are executable",
            "description": (
                "Memory regions holding user data (stack, heap) are executable. "
                "Buffer overflow vulnerabilities allow injecting arbitrary shellcode "
                "and executing it directly, without requiring ROP chains."
            ),
        })

    if not p.pie and p.aslr == "disabled":
        items.append({
            "level": "critical",
            "title": "No PIE + ASLR disabled — all addresses are fixed",
            "description": (
                "The binary is loaded at a fixed base address and ASLR is disabled "
                "system-wide. Every code gadget, libc function and GOT entry is at a "
                "deterministic address. Exploitation requires no information leak."
            ),
        })
    elif not p.pie:
        items.append({
            "level": "high",
            "title": "No PIE — binary code at a fixed address",
            "description": (
                "The binary is not compiled as position-independent (no PIE). Its code "
                "segment, GOT and PLT are at fixed, predictable addresses. Even with ASLR "
                "active on the system, ROP gadgets from the binary itself are usable "
                "without any memory disclosure."
            ),
        })

    if p.aslr == "disabled":
        items.append({
            "level": "critical",
            "title": "ASLR disabled system-wide",
            "description": (
                "Address Space Layout Randomization is turned off at the kernel level "
                "(/proc/sys/kernel/randomize_va_space = 0). Stack, heap and all shared "
                "libraries load at the same addresses on every run, eliminating the need "
                "for an info-leak to build a reliable exploit."
            ),
        })
    elif p.aslr == "partial":
        items.append({
            "level": "medium",
            "title": "ASLR partial — stack and heap randomised, not the binary",
            "description": (
                "ASLR is active but only randomises the stack and heap "
                "(/proc/sys/kernel/randomize_va_space = 1). Without PIE the binary code "
                "segment remains at a fixed address. Shared libraries may still be "
                "partially predictable."
            ),
        })

    if p.relro != "full" and has_fmt:
        label = "No RELRO" if p.relro == "no" else "Partial RELRO"
        items.append({
            "level": "critical" if p.relro == "no" else "high",
            "title": f"{label} — GOT entries are writable",
            "description": (
                "The Global Offset Table (GOT) is not made read-only after startup. "
                "Format string vulnerabilities can use %n writes to overwrite GOT entries "
                "and redirect any subsequent library call (e.g. printf → system) to "
                "attacker-controlled code."
            ),
        })

    if not p.fortify and has_any_bof:
        items.append({
            "level": "medium",
            "title": "No Fortify Source — no runtime bounds checking",
            "description": (
                "The binary was not compiled with _FORTIFY_SOURCE. Safe variants of "
                "string/memory functions (__strcpy_chk, __sprintf_chk, etc.) are absent, "
                "so no runtime buffer size checks supplement the missing compile-time "
                "protections."
            ),
        })

    if has_uaf and not p.pie:
        items.append({
            "level": "high",
            "title": "Use-after-free with fixed addresses",
            "description": (
                "A use-after-free vulnerability was detected. Without PIE, heap allocator "
                "metadata and freed chunk addresses are more predictable, facilitating "
                "heap grooming and type confusion attacks."
            ),
        })

    # ── active protections ───────────────────────────────────────────────────
    if p.canary:
        items.append({
            "level": "good",
            "title": "Stack canary active",
            "description": (
                "A secret cookie is placed between local variables and the saved return "
                "address. Any stack overflow that reaches the return address corrupts the "
                "canary and triggers process termination before the overflow is exploited. "
                "Overflows that do not reach the return address (e.g. off-by-one into "
                "adjacent variables) may still be exploitable."
            ),
        })

    if p.nx:
        items.append({
            "level": "good",
            "title": "NX active — data regions are non-executable",
            "description": (
                "The stack and heap are marked non-executable. Direct shellcode injection "
                "is prevented; an attacker must use code-reuse techniques (ROP/ret2libc) "
                "to achieve arbitrary code execution."
            ),
        })

    if p.pie and p.aslr == "full":
        items.append({
            "level": "good",
            "title": "PIE + ASLR (full randomisation)",
            "description": (
                "The binary is compiled as position-independent and ASLR is fully active. "
                "Code, stack, heap and shared libraries are randomised on each execution. "
                "Reliable exploitation requires an information-leak vulnerability to "
                "discover runtime addresses before building an exploit."
            ),
        })
    elif p.pie:
        items.append({
            "level": "good",
            "title": "PIE enabled",
            "description": (
                "The binary is compiled as position-independent. When combined with ASLR, "
                "the code segment base is randomised, making ROP chain construction "
                "significantly harder without a separate info-leak."
            ),
        })

    if p.relro == "full":
        items.append({
            "level": "good",
            "title": "Full RELRO — GOT is read-only",
            "description": (
                "All dynamic symbols are resolved at startup and the GOT is remapped "
                "read-only. GOT-overwrite attacks via format string or buffer overflow "
                "will trigger a segfault rather than redirecting execution."
            ),
        })

    return items
