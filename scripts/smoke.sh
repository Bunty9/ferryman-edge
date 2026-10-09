#!/usr/bin/env bash
# End-to-end mTLS + JWT smoke test of a built proxy binary.
#
#   scripts/smoke.sh target/release/ferryman-edge-server
#
# Generates certs/ (gitignored), serves an upstream on 127.0.0.1:8001 with
# python3, boots the binary with the repo's config.toml on 127.0.0.1:8443
# (metrics :9090) and checks real requests with curl. Needs openssl, curl
# and python3; the three ports must be free. Used by ci.yml (static musl
# build) and release.yml (each Linux release binary, before packaging).
#
#   SMOKE_IMAGE=ferryman-edge:local scripts/smoke.sh
#
# With SMOKE_IMAGE set (and no binary argument) the proxy runs from that
# docker image instead, as `--read-only --user 65532:65532` on the host
# network, so the same checks prove the container's rootfs and uid work.
# Container mode needs a native Docker engine (`DOCKER_CONTEXT=default`):
# Docker Desktop's `--network host` is its VM's network, not the host's.
set -euo pipefail

IMAGE=${SMOKE_IMAGE:-}
[ -n "$IMAGE" ] || BIN=$(realpath "$1")
cd "$(dirname "$0")/.."
work=$(mktemp -d)
bash scripts/gen-test-certs.sh >/dev/null
mkdir -p "$work/up/svc-a"
echo ok > "$work/up/health"
echo hello > "$work/up/svc-a/hello"
(cd "$work/up" && exec python3 -m http.server 8001 --bind 127.0.0.1) >"$work/upstream.log" 2>&1 &
UP_PID=$!
SERVER_PID=""
CNAME="ferryman-smoke-$$"
passed=0
cleanup() {
  kill "$UP_PID" $SERVER_PID 2>/dev/null || true
  [ -z "$IMAGE" ] || { docker logs "$CNAME" >"$work/server.log" 2>&1 || true; docker rm -f "$CNAME" >/dev/null 2>&1 || true; }
  [ "$passed" = 1 ] || tail -n +1 "$work"/*.log
}
trap cleanup EXIT

# Upstream first, so the first health tick cannot open the breaker.
for _ in $(seq 1 40); do curl -sf -o /dev/null http://127.0.0.1:8001/health && break; sleep 0.25; done
curl -sf -o /dev/null http://127.0.0.1:8001/health || { echo "upstream did not start"; exit 1; }
if [ -n "$IMAGE" ]; then
  # Test keys only: the container's uid 65532 must be able to read them.
  chmod a+r certs/*.key
  docker run -d --name "$CNAME" --read-only --user 65532:65532 --network host \
    -v "$PWD/certs:/app/certs:ro" "$IMAGE" --config /app/config.toml \
    --bind 127.0.0.1:8443 --metrics-bind 127.0.0.1:9090 >/dev/null
else
  "$BIN" --config config.toml --bind 127.0.0.1:8443 --metrics-bind 127.0.0.1:9090 \
    >"$work/server.log" 2>&1 &
  SERVER_PID=$!
fi

C="--cacert certs/ca.crt --cert certs/client.crt --key certs/client.key"
TOKEN=$(bash scripts/mint-jwt.sh smoke-tenant 300)
code() { curl -s -o /dev/null -w '%{http_code}' --max-time 5 "$@" || true; }
check() { [ "$1" = "$2" ] || { echo "FAIL $3: got $1 want $2"; exit 1; }; echo "ok $3 ($1)"; }
# Ready = the route answers; allow up to two health intervals.
# shellcheck disable=SC2086 # $C is deliberately split into curl flags
for _ in $(seq 1 24); do
  [ "$(code $C -H "Authorization: Bearer $TOKEN" https://localhost:8443/svc-a/hello)" = 200 ] && break
  sleep 0.5
done
# shellcheck disable=SC2086
check "$(code $C -H "Authorization: Bearer $TOKEN" https://localhost:8443/svc-a/hello)" 200 "valid cert + JWT (h2)"
# shellcheck disable=SC2086
check "$(code --http1.1 $C -H "Authorization: Bearer $TOKEN" https://localhost:8443/svc-a/hello)" 200 "valid cert + JWT (h1.1)"
# shellcheck disable=SC2086
check "$(code $C https://localhost:8443/svc-a/hello)" 401 "missing JWT"
# shellcheck disable=SC2086
check "$(code $C -H 'Authorization: Bearer nope' https://localhost:8443/svc-a/hello)" 401 "bad JWT"
check "$(code --cacert certs/ca.crt https://localhost:8443/svc-a/hello)" 000 "no client cert"
# shellcheck disable=SC2086
check "$(code $C -H "Authorization: Bearer $TOKEN" https://localhost:8443/nope)" 404 "unknown route"
curl -sf 127.0.0.1:9090/metrics | grep -q ferryman_requests_total
echo "ok metrics"
if [ -n "$IMAGE" ]; then docker kill -s USR1 "$CNAME" >/dev/null; else kill -USR1 "$SERVER_PID"; fi
sleep 1
# shellcheck disable=SC2086
check "$(code $C -H "Authorization: Bearer $TOKEN" https://localhost:8443/svc-a/hello)" 200 "after SIGUSR1 reload"
passed=1
