# ferryman-edge

An mTLS-terminating L7 reverse proxy in Rust. Every request passes a TLS
client-certificate check, an RS256 JWT check, and a per-tenant rate limit
before it is routed to an upstream behind a per-upstream circuit breaker.
TLS material and routes hot-reload on `SIGUSR1` without dropping
connections.

```bash
cargo install ferryman-edge      # installs the `ferryman-edge-server` binary
```

- **[Overview](overview.md)** — the problem, architecture, and stack.
- **[Request pipeline & design](design.md)** — gates, status codes,
  header handling, breaker semantics, design tradeoffs, benchmarks.
- **[Operations](operations.md)** — configuration reference, reload,
  shutdown, metrics, troubleshooting, container.
- **[API reference](api.md)** — the two crates on docs.rs.
- **[Releasing](publishing.md)** — how versions are cut and published.
- **[Changelog](changelog.md)**

Source: [github.com/Bunty9/ferryman-edge](https://github.com/Bunty9/ferryman-edge).
Licensed under MIT or Apache-2.0.
