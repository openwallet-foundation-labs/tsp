#!/bin/bash
set -e

# TSP SDK Code Coverage Script
#
# This script generates code coverage reports using cargo-llvm-cov.
# It can generate HTML reports for local viewing or lcov format for CI.

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Default values
OUTPUT_FORMAT="html"
OPEN_REPORT=false
PACKAGE=""
WORKSPACE=true

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --html)
            OUTPUT_FORMAT="html"
            shift
            ;;
        --lcov)
            OUTPUT_FORMAT="lcov"
            shift
            ;;
        --json)
            OUTPUT_FORMAT="json"
            shift
            ;;
        --open)
            OPEN_REPORT=true
            shift
            ;;
        --package|-p)
            PACKAGE="$2"
            WORKSPACE=false
            shift 2
            ;;
        --help|-h)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --html              Generate HTML report (default)"
            echo "  --lcov              Generate lcov format"
            echo "  --json              Generate JSON format"
            echo "  --open              Open HTML report in browser"
            echo "  --package, -p NAME  Run coverage for specific package"
            echo "  --help, -h          Show this help message"
            echo ""
            echo "Examples:"
            echo "  $0                    # Generate HTML report for workspace"
            echo "  $0 --open             # Generate and open HTML report"
            echo "  $0 --lcov             # Generate lcov format for CI"
            echo "  $0 -p tsp_sdk         # Run coverage for tsp_sdk only"
            exit 0
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

# Check if cargo-llvm-cov is installed
if ! command -v cargo-llvm-cov &> /dev/null; then
    echo -e "${YELLOW}cargo-llvm-cov is not installed${NC}"
    echo "Installing cargo-llvm-cov..."
    cargo install cargo-llvm-cov
fi

echo -e "${GREEN}Running code coverage analysis...${NC}"

# Build coverage command
CMD="cargo llvm-cov"

# Add workspace or package flag
if [ "$WORKSPACE" = true ]; then
    CMD="$CMD --workspace"
else
    CMD="$CMD --package $PACKAGE"
fi

# Add all features
CMD="$CMD --all-features"

# Add output format
case $OUTPUT_FORMAT in
    html)
        CMD="$CMD --html"
        if [ "$OPEN_REPORT" = true ]; then
            CMD="$CMD --open"
        fi
        ;;
    lcov)
        CMD="$CMD --lcov --output-path lcov.info"
        ;;
    json)
        CMD="$CMD --json --output-path coverage.json"
        ;;
esac

# Run coverage
echo "Running: $CMD"
eval $CMD

# Print results
echo ""
if [ "$OUTPUT_FORMAT" = "html" ]; then
    echo -e "${GREEN}✓ Coverage report generated${NC}"
    echo "  Location: target/llvm-cov/html/index.html"
    if [ "$OPEN_REPORT" = false ]; then
        echo "  View with: open target/llvm-cov/html/index.html"
    fi
elif [ "$OUTPUT_FORMAT" = "lcov" ]; then
    echo -e "${GREEN}✓ Coverage report generated${NC}"
    echo "  Location: lcov.info"

    # Try to parse and display summary if genhtml is available
    if command -v lcov &> /dev/null; then
        echo ""
        echo "Coverage Summary:"
        lcov --summary lcov.info 2>&1 | grep -E "lines\.\.\.\.\.\.|functions\.\.\.\.\.\."
    fi
elif [ "$OUTPUT_FORMAT" = "json" ]; then
    echo -e "${GREEN}✓ Coverage report generated${NC}"
    echo "  Location: coverage.json"
fi

echo ""
echo -e "${GREEN}Done!${NC}"
