#!/usr/bin/env bash
# c6l-modem soak test: hold a connection for N seconds, verify no
# validation failures or panics.
set -e
PORT="${1:-/dev/ttyACM1}"
DURATION="${2:-115}"
cd "$(dirname "$0")/../.."
LOG=$(mktemp)
echo "soak: ${DURATION}s on ${PORT}"
RUST_LOG=info timeout "$((DURATION + 15))" \
    cargo run --example rnode_listen --features "iface-rnode,iface-serial" -- \
    --port "$PORT" > "$LOG" 2>&1 || true
pkill -9 -f "target/debug/examples/rnode_listen" 2>/dev/null || true
ONLINE=$(grep -c "device online" "$LOG" || true)
FAILED=$(grep -c "validation failed" "$LOG" || true)
PANIC=$(grep -c "PANIC" "$LOG" || true)
echo "soak result: online=${ONLINE} failed=${FAILED} panic=${PANIC}"
rm -f "$LOG"
[ "$FAILED" -eq 0 ] && [ "$PANIC" -eq 0 ] && [ "$ONLINE" -ge 1 ]
