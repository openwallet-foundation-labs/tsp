#!/bin/bash
set -e

# TSP SDK Validation Script
#
# This script runs all validation checks before committing:
# - Formatting check
# - Clippy linting
# - Tests
# - Documentation build

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default options
QUICK_MODE=false
FIX_MODE=false

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --quick)
            QUICK_MODE=true
            shift
            ;;
        --fix)
            FIX_MODE=true
            shift
            ;;
        --help|-h)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --quick     Skip integration tests and doc building"
            echo "  --fix       Automatically fix formatting and some clippy issues"
            echo "  --help, -h  Show this help message"
            exit 0
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            exit 1
            ;;
    esac
done

echo -e "${BLUE}════════════════════════════════════════${NC}"
echo -e "${BLUE}  TSP SDK Validation${NC}"
echo -e "${BLUE}════════════════════════════════════════${NC}"
echo ""

# Track overall success
FAILED=false

# Function to run a check
run_check() {
    local name="$1"
    local cmd="$2"

    echo -e "${YELLOW}▶ $name${NC}"
    if eval "$cmd"; then
        echo -e "${GREEN}✓ $name passed${NC}"
        echo ""
    else
        echo -e "${RED}✗ $name failed${NC}"
        echo ""
        FAILED=true
    fi
}

# 1. Format check
if [ "$FIX_MODE" = true ]; then
    run_check "Format (fixing)" "cargo fmt --all"
else
    run_check "Format check" "cargo fmt --all --check"
fi

# 2. Clippy
if [ "$FIX_MODE" = true ]; then
    run_check "Clippy (fixing)" "cargo clippy --workspace --tests --all-features --fix --allow-dirty --allow-staged"
else
    run_check "Clippy lint" "cargo clippy --workspace --tests --all-features -- --deny warnings"
fi

# 3. Tests
if [ "$QUICK_MODE" = true ]; then
    run_check "Unit tests" "cargo test --lib --all-features"
else
    run_check "All tests (default features)" "cargo test --features nacl"
    run_check "All tests (no default features)" "cargo test --features ''"
fi

# 4. Documentation
if [ "$QUICK_MODE" = false ]; then
    run_check "Documentation build" "cargo doc --workspace --no-deps --all-features"
fi

# Summary
echo -e "${BLUE}════════════════════════════════════════${NC}"
if [ "$FAILED" = true ]; then
    echo -e "${RED}✗ Some checks failed${NC}"
    echo ""
    echo "Run with --fix to automatically fix some issues:"
    echo "  ./scripts/validate.sh --fix"
    exit 1
else
    echo -e "${GREEN}✓ All checks passed!${NC}"
    echo ""
    echo "Your code is ready to commit."
    exit 0
fi
