#!/usr/bin/env bash
# benches/reload.sh — zero-loss reload check under mTLS + JWT.
#
# Sustains traffic against a running ferryman-edge-server while sending
# SIGUSR1 at 50% and 75% of the run to trigger the atomic TLS + route
# reload. PASS iff every request returned 2xx.
#
# wrk/wrk2 cannot present a client certificate, so the driver is a pool of
# curl loops (each request is a fresh mTLS handshake — a harder test of the
# reload than keep-alive traffic). Use it for correctness, not throughput.
#
# Prereq: scripts/gen-test-certs.sh has run, the server is up, and the
# route in URL answers 2xx.
# Usage:  ./benches/reload.sh [duration_secs] [workers]
# Env:    URL (default https://localhost:8443/svc-a/echo), FERRYMAN_JWT
#         (minted via scripts/mint-jwt.sh if unset), PID (else pgrep).

set -euo pipefail

DUR="${1:-60}"
WORKERS="${2:-8}"
URL="${URL:-https://localhost:8443/svc-a/echo}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CERTS="${ROOT}/certs"

for f in ca.crt client.crt client.key jwt-priv.pem; do
    [ -f "${CERTS}/${f}" ] || { echo "missing ${CERTS}/${f}; run scripts/gen-test-certs.sh" >&2; exit 1; }
done
FERRYMAN_JWT="${FERRYMAN_JWT:-$("${ROOT}/scripts/mint-jwt.sh")}"
PID="${PID:-$(pgrep -x ferryman-edge-server || true)}"
[ -n "$PID" ] || { echo "ferryman-edge-server not running (set PID=...)" >&2; exit 1; }

LOG_DIR="$(mktemp -d)"
trap 'rm -rf "$LOG_DIR"' EXIT

worker() {
    local end=$(( $(date +%s) + DUR ))
    while [ "$(date +%s)" -lt "$end" ]; do
        # curl prints 000 itself on transport failure; `|| true` keeps the loop alive.
        curl -s -o /dev/null -w '%{http_code}\n' --max-time 5 \
            --cacert "${CERTS}/ca.crt" \
            --cert "${CERTS}/client.crt" --key "${CERTS}/client.key" \
            -H "Authorization: Bearer ${FERRYMAN_JWT}" \
            "$URL" >> "${LOG_DIR}/$1" || true
    done
}

echo "[load] ${WORKERS} curl workers for ${DUR}s against ${URL}"
pids=()
for i in $(seq 1 "$WORKERS"); do
    worker "$i" &
    pids+=("$!")
done

sleep $(( DUR / 2 ))
echo "[reload] SIGUSR1 -> ${PID} at t=$(( DUR / 2 ))s"
kill -USR1 "$PID"
sleep $(( DUR / 4 ))
echo "[reload] SIGUSR1 -> ${PID} at t=$(( DUR * 3 / 4 ))s"
kill -USR1 "$PID"

wait "${pids[@]}"

total=$(cat "${LOG_DIR}"/* | wc -l)
failed=$(cat "${LOG_DIR}"/* | grep -cv '^2' || true)
echo "total=${total} failed=${failed}"
if [ "$failed" -ne 0 ]; then
    cat "${LOG_DIR}"/* | sort | uniq -c
fi
if [ "$total" -gt 0 ] && [ "$failed" -eq 0 ]; then
    echo "PASS: zero failed requests across reload window"
else
    echo "FAIL: requests were lost during reload" >&2
    exit 1
fi
