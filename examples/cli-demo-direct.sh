#!/bin/bash
# Direct mode demo: Alice and Bob communicate via TCP without any relay or intermediary.
#
# This is the simplest TSP communication mode — two processes on the same
# machine (or LAN) talking directly via TCP.
#
# Usage:
#   ./examples/cli-demo-direct.sh
#
# Requirements:
#   - `tsp` CLI binary built (uses cargo run by default)

set -euo pipefail

TSP="${TSP:-cargo run --quiet --bin tsp --}"

# Use random ports to avoid conflicts
PORT_A=$((10000 + RANDOM % 50000))
PORT_B=$((10000 + RANDOM % 50000))

echo "=== TSP Direct Mode Demo ==="
echo "Alice on localhost:$PORT_A"
echo "Bob on localhost:$PORT_B"
echo ""

# Cleanup function
cleanup() {
    echo ""
    echo "Cleaning up..."
    kill $(jobs -p) 2>/dev/null || true
    wait 2>/dev/null || true
    rm -rf /tmp/tsp-direct-alice /tmp/tsp-direct-bob
    echo "Done."
}
trap cleanup EXIT

# --- Step 1: Create identities ---
echo "--- Step 1: Creating identities ---"

$TSP --wallet /tmp/tsp-direct-alice create --type peer --tcp localhost:$PORT_A alice --alias alice
DID_ALICE=$($TSP --wallet /tmp/tsp-direct-alice print alice)
echo "Alice DID: ${DID_ALICE:0:40}..."

$TSP --wallet /tmp/tsp-direct-bob create --type peer --tcp localhost:$PORT_B bob --alias bob
DID_BOB=$($TSP --wallet /tmp/tsp-direct-bob print bob)
echo "Bob DID: ${DID_BOB:0:40}..."

# --- Step 2: Exchange and verify DIDs (out-of-band) ---
echo ""
echo "--- Step 2: Verifying DIDs (simulates out-of-band exchange) ---"

$TSP --wallet /tmp/tsp-direct-alice verify --alias bob "$DID_BOB"
echo "Alice verified Bob"

$TSP --wallet /tmp/tsp-direct-bob verify --alias alice "$DID_ALICE"
echo "Bob verified Alice"

# --- Step 3: Establish relationship via direct TCP ---
echo ""
echo "--- Step 3: Establishing relationship ---"

# Alice listens to accept the relationship request
$TSP --wallet /tmp/tsp-direct-alice receive alice --one &
ALICE_RECV_PID=$!
sleep 1

# Bob sends relationship request directly to Alice
$TSP --wallet /tmp/tsp-direct-bob request -s bob -r alice
echo "Bob sent relationship request"

# Wait for Alice to receive and auto-accept
wait $ALICE_RECV_PID 2>/dev/null || true
echo "Alice accepted relationship"

# --- Step 4: Send a message via direct TCP ---
echo ""
echo "--- Step 4: Sending message (Bob -> Alice, direct TCP) ---"

# Alice listens for the actual message
$TSP --wallet /tmp/tsp-direct-alice receive alice --one &
ALICE_RECV_PID=$!
sleep 1

# Bob sends a direct message
echo -n "Hello Alice! This is a direct TSP message — no relay, no intermediary, just TCP." | \
    $TSP --wallet /tmp/tsp-direct-bob send -s bob -r alice

echo "Bob sent message"

# Wait for Alice to receive
wait $ALICE_RECV_PID 2>/dev/null || true

# --- Step 5: Send in reverse (Alice -> Bob) ---
echo ""
echo "--- Step 5: Sending message (Alice -> Bob, direct TCP) ---"

# Bob listens
$TSP --wallet /tmp/tsp-direct-bob receive bob --one &
BOB_RECV_PID=$!
sleep 1

# Alice sends
echo -n "Hi Bob! Got your message. Direct mode works both ways!" | \
    $TSP --wallet /tmp/tsp-direct-alice send -s alice -r bob

echo "Alice sent reply"

wait $BOB_RECV_PID 2>/dev/null || true

echo ""
echo "=== Direct mode demo complete ==="
echo "Both directions tested: Bob->Alice and Alice->Bob via direct TCP"
