#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════
# HYBRID PIPELINE — Quick Runner
# ═══════════════════════════════════════════════════════════════════════════
#
# Usage:
#   ./run_hybrid.sh <target_dir> [domain] [platform]
#
# Examples:
#   ./run_hybrid.sh ./contracts/euler-vault-kit/src defi-lending immunefi
#   ./run_hybrid.sh ./contracts/morpho/src defi-lending code4rena
#   ./run_hybrid.sh ./contracts/uniswap-v4/src defi-dex cantina
#
# For differential analysis:
#   ./run_hybrid.sh --diff ./contracts/euler-vault-kit audit-v1 HEAD
#
# ═══════════════════════════════════════════════════════════════════════════

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

if [ "$1" == "--diff" ]; then
    # Differential analysis mode
    REPO="${2:?Usage: ./run_hybrid.sh --diff <repo> <from_tag> [to_tag]}"
    FROM_TAG="${3:?Usage: ./run_hybrid.sh --diff <repo> <from_tag> [to_tag]}"
    TO_TAG="${4:-HEAD}"

    echo "═══ DIFFERENTIAL ANALYSIS ═══"
    echo "  Repo: $REPO"
    echo "  From: $FROM_TAG"
    echo "  To:   $TO_TAG"

    python hybrid_pipeline.py \
        --diff \
        --repo "$REPO" \
        --from-tag "$FROM_TAG" \
        --to-tag "$TO_TAG"
else
    # Full pipeline mode
    TARGET="${1:?Usage: ./run_hybrid.sh <target_dir> [domain] [platform]}"
    DOMAIN="${2:-defi-lending}"
    PLATFORM="${3:-immunefi}"

    echo "═══ HYBRID LLM + FORMAL VERIFICATION PIPELINE ═══"
    echo "  Target:   $TARGET"
    echo "  Domain:   $DOMAIN"
    echo "  Platform: $PLATFORM"

    python hybrid_pipeline.py \
        --target "$TARGET" \
        --domain "$DOMAIN" \
        --platform "$PLATFORM" \
        --step all
fi
