#!/usr/bin/env bash
# Demo run: build the corpus, scan all 6 vulnerable binaries, generate HTML reports.
#
# Usage:
#   ./run.sh                   # full static + dynamic scan
#   ./run.sh --no-dynamic      # static analysis only (fast, ~2 s per binary)
#   ./run.sh --timeout 60      # override per-execution timeout (default 30 s)
#   ./run.sh --static-only     # alias for --no-dynamic
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# ── colours ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

# ── argument parsing ──────────────────────────────────────────────────────────
TIMEOUT=30
EXTRA_FLAGS=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --no-dynamic|--static-only) EXTRA_FLAGS="$EXTRA_FLAGS --no-dynamic"; shift ;;
    --timeout) TIMEOUT="$2"; shift 2 ;;
    --timeout=*) TIMEOUT="${1#*=}"; shift ;;
    *) echo "Unknown option: $1" >&2; exit 1 ;;
  esac
done

# ── venv detection ────────────────────────────────────────────────────────────
if [[ -f ".venv/bin/vulnscan" ]]; then
  VULNSCAN=".venv/bin/vulnscan"
elif command -v vulnscan &>/dev/null; then
  VULNSCAN="vulnscan"
else
  echo -e "${RED}[ERROR]${RESET} vulnscan not found." >&2
  echo "  Install it with:  python3 -m virtualenv .venv && .venv/bin/pip install -e ." >&2
  exit 1
fi

REPORTS_DIR="reports"

# ── header ────────────────────────────────────────────────────────────────────
echo -e "${BOLD}${CYAN}"
echo "╔══════════════════════════════════════════════════════╗"
echo "║         vulnscan — automated ELF vulnerability scan  ║"
echo "╚══════════════════════════════════════════════════════╝"
echo -e "${RESET}"

# ── dependency check ─────────────────────────────────────────────────────────
echo -e "${BOLD}[1/3] Checking dependencies…${RESET}"
"$VULNSCAN" check-deps
echo ""

# ── corpus build ─────────────────────────────────────────────────────────────
echo -e "${BOLD}[2/3] Building corpus…${RESET}"
make -C corpus vuln asan --no-print-directory 2>&1 | grep -E "^(gcc|make|cc|warning|error)" || true
echo -e "  ${GREEN}✓${RESET} Corpus built in corpus/bin/"
echo ""

# ── scan loop ─────────────────────────────────────────────────────────────────
echo -e "${BOLD}[3/3] Scanning binaries…${RESET}"
mkdir -p "$REPORTS_DIR"

BINARIES=(
  stack_bof_vuln
  heap_bof_vuln
  format_string_vuln
  integer_overflow_vuln
  uaf_vuln
  off_by_one_vuln
)

PASS=0
FAIL=0

for name in "${BINARIES[@]}"; do
  bin="corpus/bin/$name"
  if [[ ! -f "$bin" ]]; then
    echo -e "  ${YELLOW}[SKIP]${RESET} $bin not found"
    continue
  fi

  echo -e "\n  ${BOLD}→ $name${RESET}"
  set +e
  "$VULNSCAN" scan "$bin" \
    --out "$REPORTS_DIR/${name}.html" \
    --timeout "$TIMEOUT" \
    $EXTRA_FLAGS
  RC=$?
  set -e

  if [[ $RC -eq 0 ]]; then
    PASS=$((PASS+1))
    echo -e "    ${GREEN}✓${RESET} ${REPORTS_DIR}/${name}.html"
  else
    FAIL=$((FAIL+1))
    echo -e "    ${RED}✗${RESET} scan failed (rc=$RC)"
  fi
done

# ── summary ───────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}${CYAN}══════════════════════════════════════════════════════${RESET}"
echo -e "${BOLD}  Results${RESET}"
echo -e "  Binaries scanned : $((PASS+FAIL))   Success: ${GREEN}${PASS}${RESET}   Failed: ${RED}${FAIL}${RESET}"
echo -e "  Reports written  : ${REPORTS_DIR}/"
echo ""
ls -1 "$REPORTS_DIR/"*.html 2>/dev/null | while read -r f; do
  echo -e "    ${f}"
done
echo -e "${CYAN}══════════════════════════════════════════════════════${RESET}"
