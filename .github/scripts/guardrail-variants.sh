#!/usr/bin/env bash
set -euo pipefail

cat <<'EOF'
guardrail-default|guardrail|false|resolve,bench-callgrind|guardrail-default.txt
guardrail-hpke|guardrail_hpke|true|resolve,bench-callgrind|guardrail-hpke.txt
guardrail-pq|guardrail_pq|true|pq,resolve,bench-callgrind|guardrail-pq.txt
EOF
