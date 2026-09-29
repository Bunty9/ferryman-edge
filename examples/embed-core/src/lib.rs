//! ferryman-edge-core inside your own axum service: mTLS + JWT + per-tenant
//! rate limiting with no proxy hop. `router` is the app, `require_jwt` the
//! middleware to copy, `serve_tls` the accept loop that turns a
//! `ReloadingTls` into connections.

use axum::extract::{Request, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Extension, Json, Router};
use ferryman_edge_core::{check, Claims, JwtVerifier, Limiter, ReloadingTls};
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto;
use hyper_util::server::graceful::GracefulShutdown;
use hyper_util::service::TowerToHyperService;
use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// Also the deadline for a connection's first request after the handshake.
pub const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(10);
const SHUTDOWN_DRAIN: Duration = Duration::from_secs(25);

#[derive(Clone)]
pub struct AppState {
    pub jwt: Arc<JwtVerifier>,
    /// `None` = rate limiting disabled (`build_limiter(0)`).
    pub limiter: Option<Arc<Limiter>>,
}

/// `/health` is outside the auth layer (probes have no token); everything
/// else goes through `require_jwt`.
pub fn router(state: AppState) -> Router {
    let protected = Router::new()
        .route("/whoami", get(whoami))
        .route_layer(middleware::from_fn_with_state(state, require_jwt));
    Router::new()
        .route("/health", get(|| async { "ok" }))
        .merge(protected)
}

async fn whoami(Extension(c): Extension<Claims>) -> Json<serde_json::Value> {
    Json(serde_json::json!({ "sub": c.sub, "scope": c.scope }))
}

/// Bearer JWT check, then per-tenant (`sub`) rate limit. Verified `Claims`
/// go into request extensions so handlers can extract them.
pub async fn require_jwt(State(st): State<AppState>, mut req: Request, next: Next) -> Response {
    let claims = match bearer(&req) {
        Some(token) => st.jwt.verify(token).await,
        None => None,
    };
    let Some(claims) = claims else {
        return (
            StatusCode::UNAUTHORIZED,
            [(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"))],
            "unauthorized",
        )
            .into_response();
    };
    // Limit after auth, keyed by the verified `sub`: an unauthenticated
    // caller can't spend a tenant's budget or grow the limiter's key set.
    if let Some(l) = &st.limiter {
        if !check(l, &claims.sub) {
            return (
                StatusCode::TOO_MANY_REQUESTS,
                [(header::RETRY_AFTER, HeaderValue::from_static("1"))],
                "rate limited",
            )
                .into_response();
        }
    }
    req.extensions_mut().insert(claims);
    next.run(req).await
}

fn bearer(req: &Request) -> Option<&str> {
    let raw = req.headers().get(header::AUTHORIZATION)?.to_str().ok()?;
    let (scheme, token) = raw.split_once(' ')?;
    (scheme.eq_ignore_ascii_case("bearer") && !token.is_empty()).then_some(token)
}

/// mTLS accept loop. Runs until `shutdown` resolves, then stops accepting
/// and drains in-flight connections for at most `SHUTDOWN_DRAIN`.
pub async fn serve_tls(
    listener: TcpListener,
    tls: Arc<ReloadingTls>,
    app: Router,
    shutdown: impl Future<Output = ()>,
) {
    let graceful = GracefulShutdown::new();
    let mut http = auto::Builder::new(TokioExecutor::new());
    // Timers are required for header_read_timeout to do anything.
    http.http1()
        .timer(TokioTimer::new())
        .header_read_timeout(HEADER_READ_TIMEOUT);
    http.http2()
        .timer(TokioTimer::new())
        .keep_alive_interval(Duration::from_secs(30))
        // Bounds per-connection concurrency (and memory) for one client.
        .max_concurrent_streams(64);

    tokio::pin!(shutdown);
    loop {
        let (stream, peer) = tokio::select! {
            _ = &mut shutdown => break,
            r = listener.accept() => match r {
                Ok(v) => v,
                Err(e) => {
                    // EMFILE etc.: back off instead of spinning or dying.
                    tracing::warn!(?e, "accept error");
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                }
            },
        };
        // `current()` per connection is what makes a cert reload apply to
        // new connections only; live ones keep the config they handshook with.
        let acceptor = TlsAcceptor::from(tls.current());
        let http = http.clone();
        let app = app.clone();
        let watcher = graceful.watcher();
        tokio::spawn(async move {
            // Bound the handshake so a silent peer can't hold a task forever.
            let tls_stream =
                match tokio::time::timeout(TLS_HANDSHAKE_TIMEOUT, acceptor.accept(stream)).await {
                    Ok(Ok(s)) => s,
                    // Includes "no client certificate": build_mtls_config requires one.
                    Ok(Err(e)) => return tracing::debug!(?peer, ?e, "tls handshake failed"),
                    Err(_) => return tracing::debug!(?peer, "tls handshake timed out"),
                };
            // ALPN already picked the protocol; pinning it skips the auto
            // builder's version sniff, which has no timeout of its own.
            let http = if tls_stream.get_ref().1.alpn_protocol() == Some(b"h2") {
                http.http2_only()
            } else {
                http.http1_only()
            };
            let seen_request = Arc::new(AtomicBool::new(false));
            let seen = seen_request.clone();
            let svc = TowerToHyperService::new(app);
            let svc = hyper::service::service_fn(move |req| {
                seen.store(true, Ordering::Release);
                hyper::service::Service::call(&svc, req)
            });
            let conn = watcher.watch(
                http.serve_connection(TokioIo::new(tls_stream), svc)
                    .into_owned(),
            );
            // hyper's h2 handshake and keep-alive pings have no timer of
            // their own, so a client that finishes TLS and goes silent would
            // hold the connection forever. Drop it if no request arrives.
            let first_request = tokio::time::sleep(HEADER_READ_TIMEOUT);
            tokio::pin!(conn, first_request);
            let result = tokio::select! {
                r = &mut conn => r,
                _ = &mut first_request => {
                    // Check inside the branch: select! guards are evaluated
                    // once on entry, so a request may have arrived since.
                    if !seen_request.load(Ordering::Acquire) {
                        return tracing::debug!(?peer, "no request before timeout; closing");
                    }
                    conn.await
                }
            };
            if let Err(e) = result {
                tracing::debug!(?peer, ?e, "connection error");
            }
        });
    }

    drop(listener);
    tokio::select! {
        _ = graceful.shutdown() => tracing::info!("connections drained"),
        _ = tokio::time::sleep(SHUTDOWN_DRAIN) => tracing::warn!("drain timed out; dropping connections"),
    }
}
