# embed-core: mTLS + JWT + rate limiting inside your own axum service

`ferryman-edge-core` is the set of primitives behind the
[ferryman-edge](https://github.com/Bunty9/ferryman-edge) proxy. This example
uses them directly in an axum 0.8 app, with no proxy in front:

- `src/lib.rs`: `router`, the `require_jwt` middleware, and `serve_tls`,
  an accept loop over a `ReloadingTls`.
- `src/main.rs`: env-configured binary.
- `tests/embed.rs`: real mTLS handshakes against the server, in-process.

## Embed the core, or run the proxy?

Embed when you have **one service** and want mTLS + JWT + per-tenant limits
without an extra network hop or a second deployable. Run the
[proxy](https://github.com/Bunty9/ferryman-edge) when you front **several
upstreams**.

What you give up by embedding:

- **Routing**: no prefix table; your router does that.
- **Circuit breaker and active health checks**: they protect a proxy's
  upstreams, and you have none.
- **A separate trust boundary**: a bug in your handlers now runs in the
  process that holds the TLS private key.
- **Hot route reload**: there is no route table in embed mode, so there
  are no routes to reload. The TLS certificate (`ReloadingTls`, via
  `SIGUSR1` or `ReloadingTls::reload()`) and the JWT key
  (`JwtVerifier::reload_key`, call it yourself) can be reloaded.

## The middleware, to copy

```rust
pub async fn require_jwt(State(st): State<AppState>, mut req: Request, next: Next) -> Response {
    let claims = match bearer(&req) {
        Some(token) => st.jwt.verify(token).await,
        None => None,
    };
    let Some(claims) = claims else {
        return (StatusCode::UNAUTHORIZED,
                [(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"))],
                "unauthorized").into_response();
    };
    if let Some(l) = &st.limiter {
        if !ferryman_edge_core::check(l, &claims.sub) {
            return (StatusCode::TOO_MANY_REQUESTS,
                    [(header::RETRY_AFTER, HeaderValue::from_static("1"))],
                    "rate limited").into_response();
        }
    }
    req.extensions_mut().insert(claims); // handlers: Extension<Claims>
    next.run(req).await
}

fn bearer(req: &Request) -> Option<&str> {
    let raw = req.headers().get(header::AUTHORIZATION)?.to_str().ok()?;
    let (scheme, token) = raw.split_once(' ')?;
    (scheme.eq_ignore_ascii_case("bearer") && !token.is_empty()).then_some(token)
}
```

Wire it with `middleware::from_fn_with_state(state, require_jwt)` on the
routes that need auth, and leave `/health` outside it.

## Run it

Configuration is by environment:

| Variable | Default | Meaning |
| --- | --- | --- |
| `EMBED_BIND` | `127.0.0.1:8444` | listen address |
| `EMBED_CERT`, `EMBED_KEY` | required | server certificate chain and key (PEM) |
| `EMBED_CLIENT_CA` | required | CA bundle that client certificates must chain to |
| `EMBED_JWT_PUB` | required | RSA public key (PEM) for RS256 tokens |
| `EMBED_ISSUER`, `EMBED_AUDIENCE` | required | the `iss` / `aud` every token must carry. Required so a token signed by the same key for another service is not accepted |
| `EMBED_TENANT_RPS` | `100` | per-`sub` rate limit, `0` disables |
| `EMBED_LOG_JSON` | unset | `1` for JSON logs |

The sibling [edge-demo](https://github.com/Bunty9/ferryman-edge/tree/main/examples/edge-demo)
example generates a matching set of certs and tokens (this depends on that
example being present). Build both first so `curl` doesn't race a compile:

```bash
cargo build -p ferryman-edge-embed-example -p ferryman-edge-demo
target/debug/edge-demo setup            # writes examples/edge-demo/.demo/
D=examples/edge-demo/.demo
EMBED_CERT=$D/server.crt EMBED_KEY=$D/server.key EMBED_CLIENT_CA=$D/ca.crt \
EMBED_JWT_PUB=$D/jwt-signing.pub \
EMBED_ISSUER=https://issuer.demo.local EMBED_AUDIENCE=ferryman-edge \
  target/debug/ferryman-edge-embed-example >embed.log 2>&1 &
PID=$!

TOKEN=$(target/debug/edge-demo token --sub acme)
curl --cacert $D/ca.crt --cert $D/client.crt --key $D/client.key \
     -H "authorization: Bearer $TOKEN" https://localhost:8444/whoami
# {"scope":"","sub":"acme"}    (the demo tokens carry no scope)
kill $PID
```

Rotate the certificate files and `kill -USR1 $(pidof ferryman-edge-embed-example)`;
new connections get the new certificate, existing ones are untouched.

## Before production

This is a reference, not a hardened service. At minimum:

- **Timeouts:** add a request/handler timeout, e.g. `tower_http::timeout::TimeoutLayer`. `serve_tls` bounds the handshake and the first request, not slow handlers or slow bodies.
- **Body limits:** axum's built-in extractors cap bodies at 2 MiB; anything reading the raw body (or with `DefaultBodyLimit::disable`) is unbounded. Set `DefaultBodyLimit` deliberately.
- **Metrics:** none are exported here; count auth failures, 429s and handshake failures (never label by tenant or path).
- **Key rotation:** call `JwtVerifier::reload_key(&pem)` from your own trigger (it parses first, keeps the old key on error, and clears the cache; a byte-identical PEM is a no-op and returns `Ok(false)`). There is no overlap window: tokens signed by the old key fail right after.
- **A real CA:** the demo CA is for demos. Use your own CA and rotate server and client certificates.
- **Issuer and audience** are required for a reason; keep them.

## Test

```bash
cargo test -p ferryman-edge-embed-example
```
