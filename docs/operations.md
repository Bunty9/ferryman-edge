# Operating ferryman-edge

How to configure, run, reload, observe and debug the proxy. For the
request pipeline and design rationale see the [README](https://github.com/Bunty9/ferryman-edge#readme).

## Configuration reference

`config.toml` (path via `--config` / `FERRYMAN_EDGE_CONFIG`). Relative paths
are resolved against the process working directory.

| Key | Default | Reloaded on SIGUSR1 | Meaning |
| --- | --- | --- | --- |
| `health_interval_secs` | `5` | no | Active health probe interval (`GET <upstream>/health`); all upstreams are probed concurrently, and any status below 500 counts as up. |
| `default_cooldown_secs` | `30` | yes (routes) | Breaker cooldown for routes that don't set one. |
| `failure_threshold` | `3` | yes | Consecutive upstream failures that open a circuit; at least 1. (0.1.x opened on the first failure.) |
| `trusted_proxies` | `[]` | — | Not supported by ferryman-edge yet: a non-empty list is rejected at load and on reload. Edge always replaces `x-forwarded-for` with the TLS peer address. |
| `upstream_timeout_secs` | `30` | yes | From the end of the client's upload to the upstream's response head; exceeded gets 504. (0.1.x: `[limits] upstream_timeout_secs`, still loads with a warning.) |
| `keepalive_timeout_secs` | `10` | no | HTTP/1 keep-alive idle timeout; also bounds header reads of later requests, and the first request on HTTP/1 is cut off at the smaller of this and `first_request_timeout_secs`. Behind an ALB use ALB idle + 15 s. If you raised `first_request_timeout_secs` in 0.1.x, set this to the same value. |
| `request_body_idle_timeout_secs` | `30` | yes | Longest gap between request-body frames; exceeded gets 408. |
| `request_body_timeout_secs` | `300` | yes | Whole upload; exceeded gets 408. (0.1.x: `[limits] request_body_timeout_secs`, still loads with a warning.) |
| `[mtls] cert_path` (0.1.x name `[tls]` still loads, with a warning) | — | yes (contents) | Server certificate chain, PEM (leaf first, then intermediates). |
| `[mtls] key_path` | — | yes (contents) | Server private key, PEM (PKCS#8, PKCS#1 or SEC1). |
| `[mtls] client_ca_path` | — | yes (contents) | Client CA bundle, PEM. Every client cert must chain to one of these. |
| `[jwt] jwks_path` | — | yes (contents) | RSA public key, PEM, used for RS256 verification. The path itself is read at boot; SIGUSR1 re-reads the file at that path. |
| `[jwt] issuer` | unset | no | Required `iss`. Unset = not checked. |
| `[jwt] audience` | unset | no | Required `aud`. Unset = not checked; tokens carrying any `aud` are then rejected. |
| `[[routes]] prefix` | — | yes | Path prefix, matched on a segment boundary against a normalised path (`%XX` of unreserved characters decoded, other escapes' hex uppercased, `//` merged; case-sensitive); the upstream still gets the raw path. Longest prefix wins; duplicates are rejected. Must be written in normalised form (no `%61`, no `//`, uppercase hex, ASCII) and must not contain `;`, `\`, `%2F` or `%5C`. Prefixes are routing, not access control: every route shares the same mTLS + JWT + rate-limit policy. |
| `[[routes]] upstream` | — | yes | `http://host[:port]` only: no path, query or `https`. Routes that share a `host:port` share its breaker and health check, so they must agree on `cooldown_secs`, `health_path` and `health_disabled`. |
| `[[routes]] cooldown_secs` | `default_cooldown_secs` | yes | Per-route breaker cooldown, must be ≥ 1. |
| `[[routes]] health_path` | `/health` | yes | Path the health checker probes on this upstream. Must start with `/`, no `?` or `#`. Any answer below 500 means up. |
| `[[routes]] health_disabled` | `false` | yes | `true` skips active probing for this upstream; only requests drive its breaker. A client that abandons the half-open probe request hands the slot back, so the next request probes (at most once per cooldown). |
| `[[routes]] rewrite_host` | `false` | yes | `true` sends the upstream's `host:port` as `Host`; `false` keeps the client's `Host`. `x-forwarded-host` always carries the client's host. |

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
above the maximum) abort startup. On SIGUSR1 an invalid `[limits]` value, an unknown key, a missing
`[mtls]` / `[jwt]` table, a conflicting old+new pair or an out-of-range core
timeout (or `health_interval_secs = 0`) makes the whole route reload fail,
keeping the old table; a valid but changed `[limits]` value is silently ignored until
restart (no log line).

| Key | Default | Range | Meaning |
| --- | --- | --- | --- |
| `max_request_body_bytes` | unset (no cap) | at least 1 | Optional cap on the client request body; over-cap gets 413 (declared length before routing, chunked mid-stream). This is the knob that bounds upload volume: with it unset, uploads are bounded only by `request_body_timeout_secs`. |
| `tls_handshake_timeout_secs` | `10` | 1 to 86400 | mTLS handshake deadline. |
| `first_request_timeout_secs` | `10` | 1 to 86400 | Time a new connection has to send its first request; on HTTP/1 also capped by `keepalive_timeout_secs` (the smaller applies). |
| `tenant_rps` | `1000` | 0 to 2^32-1 | Per-tenant GCRA limit keyed by JWT sub; 0 disables. (0.1.x: top level, still loads with a warning.) |
| `h2_max_concurrent_streams` | `64` | at least 1 | Concurrent h2 streams per connection. |
| `shutdown_drain_secs` | `25` | 1 to 86400 | How long in-flight connections get to finish after a shutdown signal. |

Unknown keys in any table are rejected at load.

Slowloris trade-off: `first_request_timeout_secs`, `keepalive_timeout_secs`
(the HTTP/1 header-read timeout) and `tls_handshake_timeout_secs` bound how long an
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
answer `GET /health` with any status below 500 (a 404 is fine), or the
health checker opens their breaker and requests get `503`. The proxy
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
over per upstream `host:port`: an open circuit stays open even if the routes
pointing at it change, and in-flight requests report to the same breaker.

The JWT public key reloads too (`JWT key reloaded` / `JWT key reload
failed; keeping old key`). A reload that changes the key clears the
verification cache; if the PEM file is byte-for-byte unchanged (for example
a certificate-renewal reload) the key and cache are left alone. There is a single key and no overlap window: tokens signed by the
old key are rejected immediately after the reload, so rotate at the IdP
accordingly (switch signing, then replace the file and signal).

Not reloaded: the JWT `issuer` / `audience`, `keepalive_timeout_secs`,
`health_interval_secs`, every `[limits]` key (including `tenant_rps`), bind
addresses. Restart for
those. An invalid `[limits]` value, unknown key, missing `[mtls]` / `[jwt]`
table, conflicting old+new pair, out-of-range core timeout (or
`health_interval_secs = 0`), unsupported core key or route rejected by
ferryman-core (non-normalised prefix, upstream with a path, routes on one
upstream disagreeing on cooldown or health settings) fails the whole route
reload (old table kept). The `[mtls]` / `[jwt]` paths are fixed at boot; the file
contents are re-read on SIGUSR1. Deprecation warnings are logged on reload
too. A valid but changed `[limits]` value is ignored without a log line.

Use `pidof`, not `pgrep -x`: the binary name is longer than the 15-char
kernel `comm`, so `pgrep -x ferryman-edge-server` never matches.

## Shutdown

SIGTERM or SIGINT stops accepting, lets in-flight connections finish for up
to 25 s by default (`shutdown_drain_secs`), then exits. `fly.toml` sends SIGINT with a 30 s kill timeout.

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
| `ferryman_upstream_alive` | gauge | `upstream`; 1 while the circuit is closed, else 0 (refreshed every health tick, `health_disabled` upstreams included) |

`upstream` is `host:port`, lowercased, with the port filled in (`localhost`
becomes `localhost:80`).

## Breaker blame

What counts against an upstream's breaker: transport errors, 502–504, the
504 upstream timeout (which only runs after the upload finished), and an
error from the response body after a healthy head. The last one is a
deliberate difference from ferryman, which never blames after the head.

What never counts: client body errors (400), the body cap (413), slow or
stalled uploads (408), a client hanging up or resetting its h2 stream, and an
upstream failure (transport error, body error or forwarded 502–504) after
the client stalled its upload or response reads for at least
θ = min(1 s, `request_body_idle_timeout_secs` / 2), at least 100 ms. Such a
request hands its admission back: if it was the half-open probe, the next
request probes (at most once per cooldown). Known limits, where the upstream
is still blamed: its own read or write timeout is under θ, or it enforces a
total request or response deadline that a slow but steady client exceeds.

## Troubleshooting

| Symptom | Likely cause |
| --- | --- |
| `503 upstream unavailable` right after boot | Three health probes failed before the upstream was up; the breaker closes on the next successful probe (≤ `health_interval_secs`). |
| `503` persists | Upstream's health path answers 5xx or not at all, or requests keep failing. Check `ferryman_upstream_alive`, then fix the upstream or set the route's `health_path` (or `health_disabled = true`). A disabled upstream is not probed: after a trip it recovers only via the half-open request let through after `cooldown_secs`. |
| `404 no route` | No prefix matches on a segment boundary (`/svc-a` does not match `/svc-abc`). |
| `400 bad path` | Path has a `.` or `..` segment (also `%2e`), or is ambiguous: read with `%2F` / `%5C` / `\` as `/` or with `;params` dropped, it would match a different route (`/api%2Fsecret` with a `/` catch-all). Send plain `/` separators. |
| `501 protocol upgrades are not supported` | The request has an `Upgrade` header (e.g. WebSocket) other than `h2c`, or uses `CONNECT`. The proxy can't splice connections. It is checked before route lookup, so an unrouted path also gets 501, not 404. |
| `401` with a token you believe is valid | Expired (60 s leeway), `nbf` in the future, wrong key, or `iss`/`aud` mismatch. `ferryman_auth_failures_total{reason="invalid"}` counts these. |
| curl exits 56 / handshake failure | No client cert, or it doesn't chain to `client_ca_path`. `ferryman_tls_handshake_failures_total` counts these. |
| Python client: `CA cert does not include key usage extension` | Root CA generated without extensions; regenerate with the current `gen-test-certs.sh`. |
| Container exits: permission denied reading a key | The image runs as 65532; make mounted files readable by it (see Container). |

## Container

```bash
docker build -t ferryman-edge .
docker run --user "$(id -u):$(id -g)" -p 8443:8443 -v "$PWD/certs:/app/certs:ro" ferryman-edge
```

The image is `scratch` with a static musl binary and runs as `65532:65532`.
Mounted certs, keys and config must be readable by that uid (`chmod 0640` +
`chgrp 65532`, or `docker run --user $(id -u)`; the example above does
the latter because `gen-test-certs.sh` writes keys 0600). It also runs with
`--read-only`: the proxy writes nothing to disk.

The image ships no key material and no certs; mount them at `/app/certs`
(the paths in the baked-in `/app/config.toml`) or the server exits at boot.
