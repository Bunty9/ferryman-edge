# edge-demo: the ferryman-edge proxy in action

A runnable reference for the **operator** path: the real `ferryman-edge-server`
binary in front of sample upstream services, with every feature exercised and
checked. Unix only (the proxy is controlled with SIGUSR1 / SIGTERM).

The example crate is `ferryman-edge-demo`, with two binaries:

- `backend`: a sample upstream. It shows how a service consumes the
  `x-ferryman-tenant` header the proxy stamps.
- `edge-demo`: a driver with three subcommands: `setup` (PKI + config),
  `token` (mint a JWT) and `run` (the narrated end-to-end walkthrough).

## What you will see

`edge-demo run` starts three backends and the proxy on free ports, then walks
through eleven scenarios, printing `✓` / `✗` per check and exiting non-zero if
any fails (about 5 seconds):

1. **mTLS**: valid cert over HTTP/2 and HTTP/1.1 works; no cert and a cert
   from another CA are refused.
2. **JWT**: missing, garbage, expired, wrong `aud`, wrong `iss`, future `nbf`
   and wrongly-signed tokens are all 401; a valid one is 200.
3. **Identity propagation**: the backend sees `x-ferryman-tenant` equal to the
   JWT `sub` (client-supplied values are discarded), the peer IP in
   `x-forwarded-for`, and `x-forwarded-proto: https`.
4. **Routing**: longest prefix on a path-segment boundary; `..` is rejected; a WebSocket upgrade is 501.
5. **Bodies**: 6 MiB passes intact, 9 MiB is 413.
6. **Rate limiting**: per tenant, 6th immediate request is 429 with `retry-after`.
7. **Circuit breaker + health checks**: kill a backend, watch 503 and the
   `ferryman_circuit_state` gauge, restart it, watch recovery.
8. **Hot reload (routes)**: add a route, `SIGUSR1`, it is live.
9. **Hot reload (certificate)**: rotate the server cert, `SIGUSR1`, new
   handshakes present it; existing clients keep working.
10. **Metrics**: Prometheus text on a separate port.
11. **Graceful shutdown**: `SIGTERM` lets an in-flight request finish.

## Run it

From the repository root:

```bash
examples/edge-demo/run.sh
```

which is `cargo build -p ferryman-edge -p ferryman-edge-demo` followed by
`target/debug/edge-demo run`. Note that both packages must be built:
`cargo run -p ferryman-edge-demo` alone builds neither the proxy nor `backend`
(and the demo says so if it cannot find them). `run.sh` passes its arguments to
`cargo build`, so `./run.sh --release` works.

`run` keeps its keys, config and logs in `examples/edge-demo/.demo/run/`
(gitignored, never commit it), separate from the `setup` material in
`.demo/`. Look at `.demo/run/proxy.log` for the proxy's JSON logs. `edge-demo run --keep` leaves the stack running until Ctrl-C.

## Do it by hand

Build, then generate the PKI and config for fixed local ports (proxy 8443,
metrics 9090, backends 9101 to 9103):

```bash
cargo build -p ferryman-edge -p ferryman-edge-demo
target/debug/edge-demo setup
```

Start the backends and the proxy (`setup` prints equivalent commands with your
absolute paths). Backends first; they must only be reachable from the proxy.
The commands keep the process IDs so nothing else on your machine is touched:

```bash
target/debug/backend --name orders    --bind 127.0.0.1:9101 & ORDERS=$!
target/debug/backend --name inventory --bind 127.0.0.1:9102 & INVENTORY=$!
target/debug/backend --name payments  --bind 127.0.0.1:9103 & PAYMENTS=$!
target/debug/ferryman-edge-server \
  --config examples/edge-demo/.demo/ferryman.toml \
  --bind 127.0.0.1:8443 --metrics-bind 127.0.0.1:9090 & PROXY=$!
```

Set up a shorthand for a mutual-TLS request, then one request per feature.
The rate limit is 5 requests per second per tenant, so run these at human speed:

```bash
D=examples/edge-demo/.demo
P=https://127.0.0.1:8443
TOKEN=$(target/debug/edge-demo token --sub acme)
AUTH="Authorization: Bearer $TOKEN"
edge() { curl -sS --cacert $D/ca.crt --cert $D/client.crt --key $D/client.key "$@"; }

# 1. mTLS: a client cert works (prints the backend's JSON echo) ...
edge -H "$AUTH" $P/orders/42
# ... no client cert fails in the TLS handshake
curl -sS --cacert $D/ca.crt -H "$AUTH" $P/orders/42

# 2. JWT: no token -> 401 with `www-authenticate: Bearer`; expired token -> 401
edge -i $P/orders/42 | head -3
edge -o /dev/null -w '%{http_code}\n' \
  -H "Authorization: Bearer $(target/debug/edge-demo token --sub acme --ttl -120)" $P/orders/42

# 3. identity: tenant is "acme" although we claim to be admin, and
#    forwarded_for is our real address although we claim 6.6.6.6
edge -H "$AUTH" -H 'x-ferryman-tenant: admin' -H 'x-forwarded-for: 6.6.6.6' $P/orders/42

# 4. routing: 404 off a segment boundary; 400 for a `..` segment; 501 for Upgrade
edge -o /dev/null -w '%{http_code}\n' -H "$AUTH" $P/ordersX
edge --path-as-is -o /dev/null -w '%{http_code}\n' -H "$AUTH" $P/orders/../inventory
edge -o /dev/null -w '%{http_code}\n' -H "$AUTH" -H 'Upgrade: websocket' -H 'Connection: Upgrade' $P/orders/ws

# 5. bodies: 9 MiB is refused with 413
head -c 9437184 /dev/zero | edge -o /dev/null -w '%{http_code}\n' -X POST --data-binary @- \
  -H "$AUTH" $P/orders/upload

# 6. rate limit: 8 concurrent requests from one tenant; the burst is 5
BURST="Authorization: Bearer $(target/debug/edge-demo token --sub burst)"
seq 8 | xargs -P8 -I{} curl -sS --cacert $D/ca.crt --cert $D/client.crt --key $D/client.key \
  -o /dev/null -w '%{http_code}\n' -H "$BURST" $P/orders/1 | sort | uniq -c
#   5 200
#   3 429      (typically; a token refills every 200 ms, so a slow run can show 6 x 200)

# 7. circuit breaker: kill inventory, wait two health intervals -> 503
kill $INVENTORY; sleep 2
edge -o /dev/null -w '%{http_code}\n' -H "$AUTH" $P/inventory/x
curl -s 127.0.0.1:9090/metrics | grep '^ferryman_circuit_state'   # ...} 1 = open
target/debug/backend --name inventory --bind 127.0.0.1:9102 & INVENTORY=$!
sleep 2
edge -o /dev/null -w '%{http_code}\n' -H "$AUTH" $P/inventory/x   # recovered

# 8. hot reload: rename the /payments route to /billing and signal the proxy
edge -o /dev/null -w '%{http_code}\n' -H "$AUTH" $P/payments/p1   # 200
sed -i 's|"/payments"|"/billing"|' $D/ferryman.toml
kill -USR1 $PROXY; sleep 1
edge -o /dev/null -w '%{http_code} ' -H "$AUTH" $P/payments/p1     # 404
edge -o /dev/null -w '%{http_code}\n' -H "$AUTH" $P/billing/p1     # 200

# 9. certificate hot reload is easiest to see in `edge-demo run`; by hand you
#    replace server.crt/server.key and send SIGUSR1 as above.

# 10. metrics
curl -s 127.0.0.1:9090/metrics | grep -E '^ferryman_(requests_total|ratelimited_total)'

# 11. graceful shutdown: SIGTERM lets in-flight requests finish, then stop the rest
kill -TERM $PROXY; kill $ORDERS $INVENTORY $PAYMENTS
```

## Run it with Docker Compose

[`compose/`](https://github.com/Bunty9/ferryman-edge/tree/main/examples/edge-demo/compose)
runs the same topology in containers: the proxy, three backends, and
Prometheus. From the repository root:

```bash
# PKI + tokens into examples/edge-demo/.demo/ (mounted read-only into the proxy)
cargo run -q -p ferryman-edge-demo --bin edge-demo -- setup

# First build compiles both images in release mode: expect several minutes.
docker compose -f examples/edge-demo/compose/docker-compose.yml up -d --build

TOKEN=$(cargo run -q -p ferryman-edge-demo --bin edge-demo -- token --sub acme)
MTLS="--cacert examples/edge-demo/.demo/ca.crt --cert examples/edge-demo/.demo/client.crt --key examples/edge-demo/.demo/client.key"

curl -s $MTLS -H "Authorization: Bearer $TOKEN" https://localhost:8443/orders/42
# {"service":"orders","tenant":"acme","path":"/orders/42",...}
# (503 for the first second or two: the proxy's health checker hasn't seen the backend yet)

curl -s -o /dev/null -w '%{http_code}\n' $MTLS https://localhost:8443/orders/42
# 401

docker compose -f examples/edge-demo/compose/docker-compose.yml kill -s SIGUSR1 edge
docker compose -f examples/edge-demo/compose/docker-compose.yml logs edge | grep reloaded
# "mTLS config reloaded" and "routing table reloaded"

curl -s localhost:9091/api/v1/targets | grep -o '"health":"[a-z]*"'
# "health":"up"   (Prometheus UI: http://localhost:9091)

docker compose -f examples/edge-demo/compose/docker-compose.yml down
```

Only `edge` publishes a port (`8443`). Metrics (`9090`) and the backends
stay on the compose network, so from the host the proxy is the only way in.
Inside that network any container can still reach a backend directly. In
production, enforce "only the proxy talks to backends" with network
policy, because the backends trust `x-ferryman-tenant`.

`compose/ferryman.toml` is the container version of the config: container
paths under `/app/certs`, service names as upstreams, and the same issuer
and audience as the demo tokens. Re-running `setup` regenerates the PKI, so
send `edge` a SIGUSR1 (or restart it) afterwards: SIGUSR1 reloads TLS
material, routes and the JWT key.

## Adapting this to your project

- **PKI**: replace the generated files with your own CA. `[mtls] client_ca_path`
  is the CA that signs *client* certificates; `cert_path`/`key_path` is the
  server leaf your clients will verify (its SANs must match how they connect).
  Renew by replacing the files and sending `SIGUSR1`.
- **JWT**: point `[jwt] jwks_path` at your identity provider's RSA public key
  (PEM, RS256) and **set `issuer` and `audience`**; without them any token
  signed by that key is accepted for any service. SIGUSR1 re-reads the key from the
  boot-time path and clears the token cache. There is no overlap window:
  tokens signed by the old key fail right after the reload, so rotate at the
  IdP accordingly.
- **Backends**: read `x-ferryman-tenant` as the caller identity and do not
  re-authenticate. That is only safe when the proxy is the only thing that can
  reach them (private network, no published ports). If clients can reach a backend directly they can forge the
  header.
- **Tuning**: `[limits] tenant_rps`, `health_interval_secs`, `default_cooldown_secs` and
  per-route `cooldown_secs` are in the config; the full reference is in
  [docs/operations.md](https://github.com/Bunty9/ferryman-edge/blob/main/docs/operations.md).

## Streaming mode

By default the proxy buffers request bodies (fast for typical JSON). Build it
with `--features ferryman-edge/boxed_body` for streaming forwarding; the demo
passes unchanged:

```bash
examples/edge-demo/run.sh --features ferryman-edge/boxed_body
```

The trade-offs are in the [main README](https://github.com/Bunty9/ferryman-edge/blob/main/README.md).
