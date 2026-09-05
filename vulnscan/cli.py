"""Interface en ligne de commande pour vulnscan."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from vulnscan import __version__
from vulnscan.pipeline import scan
from vulnscan.utils.logging import configure_root, get_logger
from vulnscan.utils.shell import check_system_deps

logger = get_logger(__name__)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vulnscan",
        description="Automated low-level vulnerability scanner for ELF binaries.",
    )
    parser.add_argument("--version", action="version", version=f"vulnscan {__version__}")
    parser.add_argument("-v", "--verbose", action="store_true", help="Debug output")

    sub = parser.add_subparsers(dest="command", required=True)

    # ── vulnscan scan ──────────────────────────────────────────────────────────
    scan_p = sub.add_parser("scan", help="Scan an ELF binary for vulnerabilities.")
    scan_p.add_argument("binary", type=Path, help="Path to the ELF binary to analyse.")
    scan_p.add_argument(
        "--static", dest="do_static", action="store_true", default=True,
        help="Run static analysis (default: on).",
    )
    scan_p.add_argument(
        "--no-static", dest="do_static", action="store_false",
    )
    scan_p.add_argument(
        "--dynamic", dest="do_dynamic", action="store_true", default=True,
        help="Run dynamic analysis (default: on).",
    )
    scan_p.add_argument(
        "--no-dynamic", dest="do_dynamic", action="store_false",
    )
    scan_p.add_argument(
        "--out", default="report.html", metavar="FILE",
        help="HTML report output path (default: report.html).",
    )
    scan_p.add_argument(
        "--timeout", type=int, default=30, metavar="N",
        help="Per-execution timeout in seconds (default: 30).",
    )

    # ── vulnscan check-deps ────────────────────────────────────────────────────
    sub.add_parser("check-deps", help="Verify required system tools are installed.")

    return parser


def cmd_scan(args: argparse.Namespace) -> int:
    binary = args.binary
    if not binary.exists():
        logger.error("Binaire introuvable : %s", binary)
        return 1
    if not binary.is_file():
        logger.error("N'est pas un fichier : %s", binary)
        return 1

    result = scan(
        binary,
        do_static=args.do_static,
        do_dynamic=args.do_dynamic,
        timeout=args.timeout,
    )

    out_path = Path(args.out)
    try:
        from vulnscan.report.generator import render_html
        out_path.write_text(render_html(result), encoding="utf-8")
        logger.info("Rapport HTML écrit dans %s", out_path)
    except ImportError:
        logger.warning("jinja2 non installé — impossible de générer le rapport HTML.")

    _print_summary(result)
    return 0


def _print_summary(result) -> None:
    print(f"\n{'='*60}")
    print(f"  vulnscan — {Path(result.binary_path).name}")
    print(f"{'='*60}")
    print(f"  Arch             : {result.arch}")
    print(f"  Durée            : {result.duration_s}s")
    print(f"  Vulnérabilités   : {len(result.findings)}")
    from vulnscan.report.model import Severity
    for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
        count = sum(1 for f in result.findings if f.severity == sev)
        if count:
            print(f"    {sev.value:<10}: {count}")
    print(f"{'='*60}\n")


def cmd_check_deps(_args: argparse.Namespace) -> int:
    missing = check_system_deps()
    if missing:
        print("[MANQUANT] Les outils système suivants sont requis mais absents :")
        for m in missing:
            print(f"  - {m}")
        print("\nInstallez-les avec :  sudo apt install gcc gdb make")
        return 1
    print("[OK] Tous les outils système requis sont disponibles (gcc, gdb, make).")
    return 0


def main() -> None:
    parser = _build_parser()
    args = parser.parse_args()
    configure_root(verbose=getattr(args, "verbose", False))

    # Vérifie les dépendances au démarrage, sans bloquer si certaines manquent.
    missing = check_system_deps()
    if missing and getattr(args, "command", None) == "scan":
        logger.warning(
            "Outils système manquants : %s — l'analyse dynamique sera limitée.",
            ", ".join(missing),
        )

    dispatch = {"scan": cmd_scan, "check-deps": cmd_check_deps}
    rc = dispatch[args.command](args)
    sys.exit(rc)


if __name__ == "__main__":
    main()
