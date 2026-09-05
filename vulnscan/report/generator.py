"""Générateur de rapports : sérialisation JSON + rendu HTML via Jinja2.

Points d'entrée
---------------
render_json(result)  → str   (JSON indenté)
render_html(result)  → str   (HTML autonome, sans ressources externes)
save(result, path)   → écrit le rapport HTML sur le disque
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
    """Sérialise *result* en JSON indenté."""
    return json.dumps(result.as_dict(), indent=2, ensure_ascii=False)


# ── HTML ──────────────────────────────────────────────────────────────────────

def render_html(result: "ScanResult") -> str:
    """Génère le rapport HTML complet à partir de *result* via Jinja2."""
    try:
        import jinja2
    except ImportError as exc:
        raise ImportError("jinja2 est requis pour les rapports HTML : pip install jinja2") from exc

    loader = jinja2.FileSystemLoader(str(_TEMPLATES_DIR))
    env = jinja2.Environment(
        loader=loader,
        autoescape=jinja2.select_autoescape(["html", "j2"]),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    # Filtres personnalisés
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


# ── sauvegarde ────────────────────────────────────────────────────────────────

def save(result: "ScanResult", path: Path) -> None:
    """Écrit le rapport HTML dans *path*."""
    Path(path).write_text(render_html(result), encoding="utf-8")


# ── filtres de template ───────────────────────────────────────────────────────

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
    """Retourne 'yes' / 'no' pour les booléens, la valeur brute sinon."""
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


# ── analyse d'impact ──────────────────────────────────────────────────────────

def _compute_impact(result: "ScanResult") -> list[dict]:
    """Génère la liste des items d'impact pour la section exploitabilité du rapport HTML.

    Chaque item : {"level": "critical|high|medium|good", "title": str, "description": str}
    """
    from vulnscan.report.model import VulnClass

    p = result.protections
    classes = {f.vuln_class for f in result.findings}

    has_stack_bof = bool(classes & {VulnClass.STACK_BOF, VulnClass.OFF_BY_ONE})
    has_any_bof   = bool(classes & {VulnClass.STACK_BOF, VulnClass.HEAP_BOF,
                                    VulnClass.OFF_BY_ONE})
    has_fmt       = VulnClass.FORMAT_STRING in classes
    has_uaf       = VulnClass.USE_AFTER_FREE in classes

    items: list[dict] = []

    # ── protections absentes ──────────────────────────────────────────────────
    if not p.canary and has_stack_bof:
        items.append({
            "level": "critical",
            "title": "Pas de stack canary — adresse de retour non protégée",
            "description": (
                "Les dépassements de tampon sur la pile et les vulnérabilités off-by-one peuvent "
                "écraser directement l'adresse de retour sauvegardée sans déclencher aucune "
                "vérification. L'exploitation est directe une fois l'offset vers RIP connu."
            ),
        })

    if not p.nx and has_any_bof:
        items.append({
            "level": "critical",
            "title": "NX désactivé — pile et tas exécutables",
            "description": (
                "Les régions mémoire contenant des données utilisateur (pile, tas) sont exécutables. "
                "Les vulnérabilités de dépassement de tampon permettent d'injecter du shellcode "
                "arbitraire et de l'exécuter directement, sans recourir à des chaînes ROP."
            ),
        })

    if not p.pie and p.aslr == "disabled":
        items.append({
            "level": "critical",
            "title": "Pas de PIE + ASLR désactivé — toutes les adresses sont fixes",
            "description": (
                "Le binaire est chargé à une adresse de base fixe et l'ASLR est désactivé au "
                "niveau système. Chaque gadget de code, fonction libc et entrée GOT se trouve à "
                "une adresse déterministe. L'exploitation ne nécessite aucune fuite d'information."
            ),
        })
    elif not p.pie:
        items.append({
            "level": "high",
            "title": "Pas de PIE — code binaire à adresse fixe",
            "description": (
                "Le binaire n'est pas compilé comme indépendant de la position (pas de PIE). Son "
                "segment de code, sa GOT et sa PLT sont à des adresses fixes et prévisibles. "
                "Même avec l'ASLR actif, les gadgets ROP du binaire lui-même sont exploitables "
                "sans fuite mémoire."
            ),
        })

    if p.aslr == "disabled":
        items.append({
            "level": "critical",
            "title": "ASLR désactivé au niveau système",
            "description": (
                "La randomisation de l'espace d'adressage est désactivée au niveau noyau "
                "(/proc/sys/kernel/randomize_va_space = 0). La pile, le tas et toutes les "
                "bibliothèques partagées se chargent aux mêmes adresses à chaque exécution, "
                "éliminant le besoin d'une fuite d'information pour construire un exploit fiable."
            ),
        })
    elif p.aslr == "partial":
        items.append({
            "level": "medium",
            "title": "ASLR partiel — pile et tas aléatoires, pas le binaire",
            "description": (
                "L'ASLR est actif mais ne randomise que la pile et le tas "
                "(/proc/sys/kernel/randomize_va_space = 1). Sans PIE, le segment de code du "
                "binaire reste à adresse fixe. Les bibliothèques partagées peuvent rester "
                "partiellement prévisibles."
            ),
        })

    if p.relro != "full" and has_fmt:
        label = "Pas de RELRO" if p.relro == "no" else "RELRO partiel"
        items.append({
            "level": "critical" if p.relro == "no" else "high",
            "title": f"{label} — entrées GOT accessibles en écriture",
            "description": (
                "La table des adresses globales (GOT) n'est pas passée en lecture seule après "
                "le démarrage. Les vulnérabilités de chaîne de format peuvent utiliser des "
                "écritures %n pour écraser des entrées GOT et rediriger tout appel de bibliothèque "
                "ultérieur (ex. printf → system) vers du code contrôlé par l'attaquant."
            ),
        })

    if not p.fortify and has_any_bof:
        items.append({
            "level": "medium",
            "title": "Pas de Fortify Source — aucune vérification de bornes à l'exécution",
            "description": (
                "Le binaire n'a pas été compilé avec _FORTIFY_SOURCE. Les variantes sécurisées "
                "des fonctions de chaînes/mémoire (__strcpy_chk, __sprintf_chk, etc.) sont "
                "absentes, aucune vérification de taille de tampon à l'exécution ne complète "
                "les protections de compilation manquantes."
            ),
        })

    if has_uaf and not p.pie:
        items.append({
            "level": "high",
            "title": "Use-after-free avec adresses fixes",
            "description": (
                "Une vulnérabilité use-after-free a été détectée. Sans PIE, les métadonnées de "
                "l'allocateur de tas et les adresses de chunks libérés sont plus prévisibles, "
                "facilitant le heap grooming et les attaques par confusion de types."
            ),
        })

    # ── protections actives ───────────────────────────────────────────────────
    if p.canary:
        items.append({
            "level": "good",
            "title": "Stack canary actif",
            "description": (
                "Un cookie secret est placé entre les variables locales et l'adresse de retour "
                "sauvegardée. Tout dépassement de pile qui l'atteint corrompt le canary et "
                "déclenche l'arrêt du processus avant exploitation. Les dépassements n'atteignant "
                "pas l'adresse de retour (ex. off-by-one sur variables adjacentes) peuvent "
                "rester exploitables."
            ),
        })

    if p.nx:
        items.append({
            "level": "good",
            "title": "NX actif — régions de données non exécutables",
            "description": (
                "La pile et le tas sont marqués non exécutables. L'injection directe de shellcode "
                "est bloquée ; un attaquant doit recourir à des techniques de réutilisation de "
                "code (ROP/ret2libc) pour obtenir une exécution de code arbitraire."
            ),
        })

    if p.pie and p.aslr == "full":
        items.append({
            "level": "good",
            "title": "PIE + ASLR (randomisation complète)",
            "description": (
                "Le binaire est compilé comme indépendant de la position et l'ASLR est "
                "entièrement actif. Le code, la pile, le tas et les bibliothèques partagées sont "
                "aléatoires à chaque exécution. Un exploit fiable nécessite une fuite d'information "
                "pour découvrir les adresses à l'exécution."
            ),
        })
    elif p.pie:
        items.append({
            "level": "good",
            "title": "PIE activé",
            "description": (
                "Le binaire est compilé comme indépendant de la position. Combiné à l'ASLR, "
                "la base du segment de code est aléatoire, rendant la construction de chaînes "
                "ROP significativement plus difficile sans fuite mémoire séparée."
            ),
        })

    if p.relro == "full":
        items.append({
            "level": "good",
            "title": "RELRO complet — GOT en lecture seule",
            "description": (
                "Tous les symboles dynamiques sont résolus au démarrage et la GOT est remappée "
                "en lecture seule. Les attaques par écrasement de GOT via chaîne de format ou "
                "dépassement de tampon déclencheront un segfault plutôt que de rediriger "
                "l'exécution."
            ),
        })

    return items
