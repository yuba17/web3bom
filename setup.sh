#!/usr/bin/env bash
# ─── Web3 Bug Bounty Hunting System — Setup ──────────────────────────────────
# Clone from GitHub → run this script → start hunting.
#
# Usage:
#   chmod +x setup.sh && ./setup.sh
#
# What it does:
#   1. Checks/installs Python packages
#   2. Checks/installs external CLI tools (Foundry, Slither, Aderyn, etc.)
#   3. Creates required directories
#   4. Sets up .env from .env.example
#   5. Verifies everything works
# ──────────────────────────────────────────────────────────────────────────────

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

ok()   { echo -e "  ${GREEN}✓${NC} $1"; }
warn() { echo -e "  ${YELLOW}!${NC} $1"; }
fail() { echo -e "  ${RED}✗${NC} $1"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo ""
echo "═══════════════════════════════════════════════════════"
echo "  Web3 Bug Bounty Hunting System — Setup"
echo "═══════════════════════════════════════════════════════"
echo ""

ERRORS=0

# ─── 1. Python packages ──────────────────────────────────────────────────────
echo "▸ Python packages"
if command -v python3 &>/dev/null; then
    ok "python3 found: $(python3 --version 2>&1)"
else
    fail "python3 not found — install Python 3.10+"
    ERRORS=$((ERRORS + 1))
fi

if [ -f audit-agents/requirements.txt ]; then
    echo "  Installing Python dependencies..."
    pip install -r audit-agents/requirements.txt --quiet --break-system-packages 2>/dev/null \
        || pip install -r audit-agents/requirements.txt --quiet 2>/dev/null \
        || { fail "pip install failed"; ERRORS=$((ERRORS + 1)); }
    ok "Python packages installed"
else
    fail "audit-agents/requirements.txt not found"
    ERRORS=$((ERRORS + 1))
fi

# Quick import check
python3 -c "import yaml, rich, jinja2, requests, dotenv" 2>/dev/null \
    && ok "Core Python imports OK" \
    || { fail "Some Python packages missing"; ERRORS=$((ERRORS + 1)); }

# ─── 2. External tools ───────────────────────────────────────────────────────
echo ""
echo "▸ External CLI tools"

check_tool() {
    local name="$1"
    local install_cmd="$2"
    local required="${3:-true}"

    if command -v "$name" &>/dev/null; then
        local ver
        ver=$("$name" --version 2>&1 | head -1 | tr -d '\n')
        ok "$name: $ver"
        return 0
    else
        if [ "$required" = "true" ]; then
            fail "$name not found"
            echo "       Install: $install_cmd"
            ERRORS=$((ERRORS + 1))
        else
            warn "$name not found (optional)"
            echo "       Install: $install_cmd"
        fi
        return 1
    fi
}

# Required tools
check_tool "forge" "curl -L https://foundry.paradigm.xyz | bash && foundryup" true
check_tool "slither" "pip install slither-analyzer" true
check_tool "claude" "See https://docs.anthropic.com/en/docs/claude-code" true

# Recommended tools
check_tool "aderyn" "cargo install aderyn" false
check_tool "medusa" "See https://github.com/crytic/medusa/releases" false
check_tool "echidna" "See https://github.com/crytic/echidna/releases" false
check_tool "halmos" "pip install halmos" false
check_tool "semgrep" "pip install semgrep" false

# ─── 3. Directories ──────────────────────────────────────────────────────────
echo ""
echo "▸ Directory structure"

dirs=(
    "hunt_session/hypotheses"
    "hunt_session/fichas"
    "hunt_session/gate_status"
    "hunt_session/context"
    "hunt_session/results"
    "hunt_session/feedback"
    "reports"
    "logs"
    "benchmarks"
)

for d in "${dirs[@]}"; do
    mkdir -p "$d"
done
ok "All directories created"

# Claude memory dirs
mkdir -p ~/.claude/MEMORY/STATE/ 2>/dev/null && ok "Claude memory dirs OK" || true

# ─── 4. Environment file ─────────────────────────────────────────────────────
echo ""
echo "▸ Environment"

if [ -f .env ]; then
    ok ".env exists"
    # Check critical vars
    source .env 2>/dev/null || true
    [ -n "${ANTHROPIC_API_KEY:-}" ] && ok "ANTHROPIC_API_KEY set" || warn "ANTHROPIC_API_KEY not set in .env"
    [ -n "${ETH_RPC_URL:-}" ] && ok "ETH_RPC_URL set" || warn "ETH_RPC_URL not set (needed for fork tests)"
    [ -n "${BASE_RPC_URL:-}" ] && ok "BASE_RPC_URL set" || warn "BASE_RPC_URL not set (needed for fork tests)"
else
    if [ -f .env.example ]; then
        cp .env.example .env
        warn ".env created from .env.example — edit it with your API keys"
    else
        fail ".env.example not found"
        ERRORS=$((ERRORS + 1))
    fi
fi

# ─── 5. Verification ─────────────────────────────────────────────────────────
echo ""
echo "▸ Quick verification"

# Check benchmark exists
if [ -f benchmarks/yieldoor/benchmark.yaml ]; then
    ok "Yieldoor benchmark found"
else
    warn "No benchmark found (benchmarks/yieldoor/benchmark.yaml)"
fi

# Check skills exist
SKILLS_DIR="$HOME/.claude/skills"
if [ -d "$SKILLS_DIR" ] && ls "$SKILLS_DIR"/*.md &>/dev/null; then
    SKILL_COUNT=$(ls "$SKILLS_DIR"/*.md 2>/dev/null | wc -l)
    ok "Claude skills found: $SKILL_COUNT"
else
    warn "No Claude skills in ~/.claude/skills/ — copy from audit-agents/.claude/skills/"
fi

# Check audit-agents scripts
for script in run_benchmark.py run_hunt.py detection_engine.py pipeline_gate.py benchmark_score.py; do
    if [ -f "audit-agents/$script" ]; then
        ok "$script exists"
    else
        fail "$script missing"
        ERRORS=$((ERRORS + 1))
    fi
done

# ─── Summary ──────────────────────────────────────────────────────────────────
echo ""
echo "═══════════════════════════════════════════════════════"
if [ $ERRORS -eq 0 ]; then
    echo -e "  ${GREEN}Setup complete — 0 errors${NC}"
    echo ""
    echo "  Quick start:"
    echo "    # Run benchmark (Strategy component, fast mode):"
    echo "    python3 audit-agents/run_benchmark.py \\"
    echo "      --ground-truth benchmarks/yieldoor/benchmark.yaml \\"
    echo "      --repo benchmarks/yieldoor/repo/yieldoor \\"
    echo "      --protocol yieldoor --components Strategy --fast"
    echo ""
    echo "    # Run a hunt on a new protocol:"
    echo "    python3 audit-agents/run_hunt.py --component <Name>"
else
    echo -e "  ${RED}Setup finished with $ERRORS error(s)${NC}"
    echo "  Fix the errors above and re-run ./setup.sh"
fi
echo "═══════════════════════════════════════════════════════"
echo ""
