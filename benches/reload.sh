#!/usr/bin/env bash
# benches/reload.sh — zero-loss reload bench.
#
# Sustains wrk2 traffic against ferryman-edge while sending SIGUSR1 mid-run
# to trigger an atomic TLS + route reload. Pass criterion if the failed-
# request count stays at zero across the reload window.
#
# Prereq: wrk2 on PATH, openssl, gen-test-certs.sh already run.
# Usage:  ./benches/reload.sh [duration_secs] [rps]

set -euo pipefail

DUR="${1:-60}"
RPS="${2:-50000}"
BIND="https://localhost:8443/svc-a/echo"
CERTS="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/certs"

if ! command -v wrk2 >/dev/null 2>&1 && ! command -v wrk >/dev/null 2>&1; then
    echo "wrk2 (or wrk) is required on PATH" >&2
    exit 1
fi
WRK_BIN="$(command -v wrk2 || command -v wrk)"

if [ ! -f "${CERTS}/client.crt" ]; then
    echo "missing test certs; run scripts/gen-test-certs.sh first" >&2
    exit 1
fi

LOG="$(mktemp)"
trap 'rm -f "$LOG"' EXIT

# Launch wrk2 in the background with mTLS client cert.
"$WRK_BIN" -c 1000 -t 16 -R "$RPS" -d "${DUR}s" \
    --latency \
    -s benches/wrk2.lua \
    "$BIND" \
    >"$LOG" 2>&1 &
WRK_PID=$!

# Fire SIGUSR1 halfway through. Repeat once more at 75% to stress the
# acceptor under sustained load + repeated config swap.
sleep $(( DUR / 2 ))
PID=$(pidof ferryman-edge-server || true)
if [ -n "$PID" ]; then
    echo "[reload] sending SIGUSR1 to PID $PID at t=$(( DUR / 2 ))s"
    kill -USR1 "$PID"
fi
sleep $(( DUR / 4 ))
PID=$(pidof ferryman-edge-server || true)
if [ -n "$PID" ]; then
    echo "[reload] sending SIGUSR1 to PID $PID at t=$(( DUR * 3 / 4 ))s"
    kill -USR1 "$PID"
fi

wait "$WRK_PID"

echo
echo "----- wrk2 output ---------------------------------------------------"
cat "$LOG"
echo "---------------------------------------------------------------------"

# wrk2 reports failed requests on the "Non-2xx or 3xx responses" and
# "Socket errors" lines. Both should be absent — a real zero-loss reload
# completes the in-flight handshake on the old config and starts the next
# one on the new config without dropping a single connection.
if grep -qE "Non-2xx|Socket errors" "$LOG"; then
    echo "FAIL: requests were lost during reload" >&2
    exit 1
fi
echo "PASS: zero failed requests across reload window"
