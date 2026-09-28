# API reference

| Crate | Use it for | Docs |
| --- | --- | --- |
| [`ferryman-edge-core`](https://crates.io/crates/ferryman-edge-core) | The primitives: `ReloadingTls`, `JwtVerifier`, the per-tenant limiter, `RouteTable` with its circuit breaker, the health loop, the config schema. | [docs.rs/ferryman-edge-core](https://docs.rs/ferryman-edge-core) |
| [`ferryman-edge`](https://crates.io/crates/ferryman-edge) | The `ferryman-edge-server` binary. Its library API (`serve`, `AppState`, `proxy`, `reload`) exists for the binary and its tests and is not yet semver-stable. | [docs.rs/ferryman-edge](https://docs.rs/ferryman-edge) |

```toml
[dependencies]
ferryman-edge-core = "0.1"
```
