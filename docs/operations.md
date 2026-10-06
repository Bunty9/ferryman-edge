# Operating ferryman-edge

How to configure, run, reload, observe and debug the proxy. For the
request pipeline and design rationale see the [README](https://github.com/Bunty9/ferryman-edge#readme).

## Configuration reference

`config.toml` (path via `--config` / `FERRYMAN_EDGE_CONFIG`). Relative paths
are resolved against the process working directory.

| Key | Default | Reloaded on SIGUSR1 | Meaning |
| --- | --- | --- | --- |
| `health_interval_secs` | `5` | no | Active health probe interval (`GET <upstream>/health`). |
| `default_cooldown_secs` | `30` | yes (routes) | Breaker cooldown for routes that don't set one. |
| `tenant_rps` | `1000` | no | Per-tenant GCRA limit keyed by JWT `sub`. `0` disables rate limiting. |
| `[tls] cert_path` | — | yes | Server certificate chain, PEM (leaf first, then intermediates). |
| `[tls] key_path` | — | yes | Server private key, PEM (PKCS#8, PKCS#1 or SEC1). |
| `[tls] client_ca_path` | — | yes | Client CA bundle, PEM. Every client cert must chain to one of these. |
| `[jwt] jwks_path` | — | no | RSA public key, PEM, used for RS256 verification. |
| `[jwt] issuer` | unset | no | Required `iss`. Unset = not checked. |
| `[jwt] audience` | unset | no | Required `aud`. Unset = not checked; tokens carrying any `aud` are then rejected. |
| `[[routes]] prefix` | — | yes | Path prefix, matched on a segment boundary. Longest prefix wins. |
| `[[routes]] upstream` | — | yes | `http://host:port` of the backend. Must have an authority. |
| `[[routes]] cooldown_secs` | `default_cooldown_secs` | yes | Per-route breaker cooldown, must be ≥ 1. |
| `[[routes]] health_path` | `/health` | yes | Path the health checker probes on this upstream. Must start with `/`, no `?` or `#`. |
| `[[routes]] health_disabled` | `false` | yes | `true` skips active probing for this route; only requests drive its breaker. |

Set `issuer` and `audience` in every non-local deployment. Without them the
proxy accepts any token signed by the issuer key, whichever service it was
minted for.

CLI / environment:

| Flag | Env | Default |
| --- | --- | --- |
| `--config` | `FERRYMAN_EDGE_CONFIG` | `config.toml` |
| `--bind` | `FERRYMAN_EDGE_BIND` | `0.0.0.0:8443` |
| `--metrics-bind` | `FERRYMAN_EDGE_METRICS_BIND` | `0.0.0.0:9090` |
| — | `RUST_LOG` | `info` (JSON logs to stdout) |

### `[limits]`

All keys are optional; the defaults are the values earlier releases
hard-coded. **Every `[limits]` key is read at boot only**: SIGUSR1 does not
change them, restart the process to apply a change. Invalid values (zero, or
above the maximum) abort startup.

| Key | Default | Range | Meaning |
| --- | --- | --- | --- |
| `max_request_body_bytes` | `8388608` (8 MiB) | 1 to 1073741824 | Largest client request body; larger gets 413. |
| `request_body_timeout_secs` | `30` | 1 to 86400 | Deadline for reading the client body; exceeded gets 408. |
| `upstream_timeout_secs` | `30` | 1 to 86400 | Upstream round trip, starting once the request body is ready; exceeded gets 504. |
| `tls_handshake_timeout_secs` | `10` | 1 to 86400 | mTLS handshake deadline. |
| `first_request_timeout_secs` | `10` | 1 to 86400 | Time a new connection has to send its first request; also the HTTP/1 header-read timeout. |
| `h2_max_concurrent_streams` | `64` | at least 1 | Concurrent h2 streams per connection. In collected mode, per-connection body memory is up to this times `max_request_body_bytes`. |
| `shutdown_drain_secs` | `25` | 1 to 86400 | How long in-flight connections get to finish after a shutdown signal. |

Slowloris trade-off: `first_request_timeout_secs` (and the HTTP/1 header
timeout it also sets) and `tls_handshake_timeout_secs` bound how long an
unauthenticated or silent client can hold a connection slot. Raising them
widens that window; raise them only for slow, trusted networks. Keep
`shutdown_drain_secs` below your orchestrator's kill timeout.

## Local run

```bash
./scripts/gen-test-certs.sh                       # certs/ (gitignored)
cargo run -p ferryman-edge -- --config config.toml

curl --cacert certs/ca.crt --cert certs/client.crt --key certs/client.key \
     -H "Authorization: Bearer $(scripts/mint-jwt.sh tenant-a 3600)" \
     https://localhost:8443/svc-a/hello
```

`scripts/mint-jwt.sh [sub] [ttl_secs] [scope]` signs with
`certs/jwt-priv.pem`; set `JWT_ISS` / `JWT_AUD` to add `iss` / `aud`.

The upstreams in `config.toml` (`localhost:8001`, `localhost:8002`) must
serve `GET /health` with a 2xx, or the health checker keeps their breaker
open and requests get `503` (set a route's `health_path`, or
`health_disabled = true`, if the upstream has no such endpoint). The proxy
forwards the full path, prefix included (`/svc-a/hello` reaches the
upstream as `/svc-a/hello`).

## Hot reload

```bash
kill -USR1 "$(pidof ferryman-edge-server)"
```

One signal reloads both the TLS material and the routing table. A reload
that fails to parse or load keeps the old config and logs
`mTLS reload failed; keeping old` or `route reload failed; keeping old
table` with the cause. Live connections keep the TLS config they
handshook with; new connections get the new one. Breaker state carries
over for routes whose prefix, upstream and cooldown did not change.

Not reloaded: the JWT key and claims settings, `tenant_rps`,
`health_interval_secs`, bind addresses. Restart for those.

Use `pidof`, not `pgrep -x`: the binary name is longer than the 15-char
kernel `comm`, so `pgrep -x ferryman-edge-server` never matches.

## Shutdown

SIGTERM or SIGINT stops accepting, lets in-flight connections finish for up
to 25 s, then exits. `fly.toml` sends SIGINT with a 30 s kill timeout.

## Metrics

Prometheus text on `--metrics-bind` at `/metrics`. Keep it off the public
network (`fly.toml` uses Fly's internal `[metrics]` scrape).

| Metric | Type | Labels |
| --- | --- | --- |
| `ferryman_requests_total` | counter | `status`, `upstream` (when one was chosen) |
| `ferryman_request_duration_seconds` | summary | `upstream` (successful round trips) |
| `ferryman_auth_failures_total` | counter | `reason` = `missing` \| `invalid` |
| `ferryman_ratelimited_total` | counter | — (never labelled by tenant) |
| `ferryman_tls_handshake_seconds` | summary | — |
| `ferryman_tls_handshake_failures_total` | counter | — |
| `ferryman_circuit_state` | gauge | `upstream`; 0 closed, 1 open, 2 half-open |
| `ferryman_upstream_alive` | gauge | `upstream`; last health probe result. Absent for `health_disabled` routes; a value set before a reload that disables probing persists until restart, so exclude disabled upstreams from alerts on it |

`upstream` is `host:port`.

## Troubleshooting

| Symptom | Likely cause |
| --- | --- |
| `503 upstream unavailable` right after boot | First health probe ran before the upstream was up; the breaker closes on the next successful probe (≤ `health_interval_secs`). |
| `503` persists | Upstream has no 2xx `/health`, or keeps failing; a failing probe keeps the breaker open. Check `ferryman_upstream_alive`, then set the route's `health_path` or `health_disabled = true`. A disabled upstream is not probed: after a trip it recovers only via the half-open request let through after `cooldown_secs`. |
| `404 no route` | No prefix matches on a segment boundary (`/svc-a` does not match `/svc-abc`). |
| `400 bad path` | Path has a `.` or `..` segment (also `%2e`). |
| `501 protocol upgrades are not supported` | The request has an `Upgrade` header (e.g. WebSocket) other than `h2c`, or uses `CONNECT`. The proxy can't splice connections. It is checked before route lookup, so an unrouted path also gets 501, not 404. |
| `401` with a token you believe is valid | Expired (60 s leeway), `nbf` in the future, wrong key, or `iss`/`aud` mismatch. `ferryman_auth_failures_total{reason="invalid"}` counts these. |
| curl exits 56 / handshake failure | No client cert, or it doesn't chain to `client_ca_path`. `ferryman_tls_handshake_failures_total` counts these. |
| Python client: `CA cert does not include key usage extension` | Root CA generated without extensions; regenerate with the current `gen-test-certs.sh`. |
| Container exits with `GLIBC_2.38 not found` | Builder and runtime images on different Debian releases; the Dockerfile pins both to bookworm. |

## Container

```bash
docker build -t ferryman-edge .
docker run -p 8443:8443 -v "$PWD/certs:/app/certs:ro" ferryman-edge
```

The image ships no key material and no certs; mount them at `/app/certs`
(the paths in the baked-in `/app/config.toml`) or the server exits at boot.
