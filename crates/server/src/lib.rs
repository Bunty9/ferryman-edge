//! ferryman-edge — programmable mTLS L7 reverse proxy pipeline.
//!
//!   inbound TCP
//!     -> `TlsAcceptor::accept` using the *current* `ReloadingTls` config
//!     -> hyper `serve_connection` over the TLS stream
//!     -> per-request: JWT verify, rate-limit by `Claims::sub`, route, proxy
//!
//! `main.rs` is arg parsing + boot; this crate root owns the accept loop
//! (`serve`) and the auth middleware in front of `proxy::handle`, so both
//! can be driven directly from an integration test without a real process.
//!
//! Most users want the `ferryman-edge-server` binary (`cargo install
//! ferryman-edge`). This library API exists for that binary and its tests
//! and is not yet semver-stable; the reusable primitives live in
//! `ferryman-edge-core`.

pub mod proxy;
pub mod reload;

use ferryman_edge_core::ferryman_core::SharedTable;
use ferryman_edge_core::{check, Claims, JwtVerifier, Limiter, Limits, ReloadingTls};
use http::{HeaderValue, Request, Response};
use hyper::body::{Bytes, Incoming};
use hyper::service::service_fn;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto;
use hyper_util::server::graceful::{GracefulShutdown, Watcher};
use std::convert::Infallible;
use std::future::Future;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;

/// Shared upstream client. One instance for the whole process; its pool
/// keeps idle HTTP/1.1 connections to each upstream (outbound is always
/// HTTP/1.1).
pub type UpstreamClient = Client<HttpConnector, proxy::RequestBody>;

/// Everything a connection/request needs, built once at boot.
pub struct AppState {
    pub tls: Arc<ReloadingTls>,
    pub table: SharedTable,
    pub jwt: Arc<JwtVerifier>,
    pub limiter: Option<Arc<Limiter>>,
    pub client: UpstreamClient,
}

const ACCEPT_ERROR_BACKOFF: Duration = Duration::from_millis(50);
const H2_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(30);

/// [`serve_with`] using [`Limits::default`].
pub async fn serve(
    listener: TcpListener,
    state: Arc<AppState>,
    shutdown: impl Future<Output = ()>,
) {
    serve_with(listener, state, Limits::default(), shutdown).await
}

/// Limits should come from `EdgeConfig::parse` (or satisfy its ranges): a 0
/// timeout makes every request or connection time out immediately.
///
/// Accept loop. Runs until `shutdown` resolves, then stops accepting new
/// connections, lets in-flight ones finish (bounded by
/// `limits.shutdown_drain_secs`), and returns.
pub async fn serve_with(
    listener: TcpListener,
    state: Arc<AppState>,
    limits: Limits,
    shutdown: impl Future<Output = ()>,
) {
    let limits = Arc::new(limits);
    let graceful = GracefulShutdown::new();
    let mut http = auto::Builder::new(TokioExecutor::new());
    http.http1()
        .timer(TokioTimer::new())
        // Keep-alive idle timeout; hyper re-arms it whenever a connection goes
        // idle (ROADMAP F1/E9). hyper adds it to `now()` unchecked, so cap it.
        .header_read_timeout(
            state
                .table
                .load()
                .keepalive_timeout()
                .min(Duration::from_secs(86_400)),
        );
    http.http2()
        .timer(TokioTimer::new())
        .keep_alive_interval(H2_KEEPALIVE_INTERVAL)
        .max_concurrent_streams(limits.h2_max_concurrent_streams);

    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            _ = &mut shutdown => break,
            accepted = listener.accept() => {
                match accepted {
                    Ok((stream, peer)) => {
                        let state = state.clone();
                        let http = http.clone();
                        let watcher = graceful.watcher();
                        let limits = limits.clone();
                        tokio::spawn(async move {
                            handle_conn(stream, peer, state, http, watcher, limits).await;
                        });
                    }
                    Err(e) => {
                        // EMFILE and friends: log and keep the server alive.
                        tracing::warn!(?e, "accept error");
                        tokio::time::sleep(ACCEPT_ERROR_BACKOFF).await;
                    }
                }
            }
        }
    }

    drop(listener);
    tracing::info!("shutdown signal received; draining connections");
    tokio::select! {
        _ = graceful.shutdown() => tracing::info!("all connections drained"),
        _ = tokio::time::sleep(Duration::from_secs(limits.shutdown_drain_secs)) => {
            tracing::warn!("graceful shutdown timed out; dropping remaining connections");
        }
    }
}

async fn handle_conn(
    stream: TcpStream,
    peer: SocketAddr,
    state: Arc<AppState>,
    http: auto::Builder<TokioExecutor>,
    watcher: Watcher,
    limits: Arc<Limits>,
) {
    let acceptor = TlsAcceptor::from(state.tls.current());
    let started = Instant::now();
    let handshake_timeout = Duration::from_secs(limits.tls_handshake_timeout_secs);
    let tls_stream = match tokio::time::timeout(handshake_timeout, acceptor.accept(stream)).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            metrics::counter!("ferryman_tls_handshake_failures_total").increment(1);
            tracing::debug!(?peer, ?e, "tls handshake failed");
            return;
        }
        Err(_) => {
            metrics::counter!("ferryman_tls_handshake_failures_total").increment(1);
            tracing::debug!(?peer, "tls handshake timed out");
            return;
        }
    };
    metrics::histogram!("ferryman_tls_handshake_seconds").record(started.elapsed().as_secs_f64());

    // ALPN already decided the protocol. Pinning it skips the auto
    // builder's version sniff, which has no timeout of its own and would
    // let a silent client hold the connection open forever.
    let http = if tls_stream.get_ref().1.alpn_protocol() == Some(b"h2") {
        http.http2_only()
    } else {
        http.http1_only()
    };
    let io = TokioIo::new(tls_stream);
    let seen_request = Arc::new(AtomicBool::new(false));
    let seen = seen_request.clone();
    let first_request_timeout = Duration::from_secs(limits.first_request_timeout_secs);
    let svc = service_fn(move |req| {
        seen.store(true, Ordering::Release);
        let state = state.clone();
        let limits = limits.clone();
        async move { Ok::<_, Infallible>(route_request(state, req, peer, &limits).await) }
    });

    let conn = watcher.watch(http.serve_connection(io, svc).into_owned());
    // Neither hyper's h2 handshake (waiting for the client preface) nor its
    // keep-alive pings, which only start after it, have a timer; a client
    // that completes TLS and then goes silent would hold the connection
    // forever. Drop it if no request arrives in time.
    let first_request = tokio::time::sleep(first_request_timeout);
    tokio::pin!(conn, first_request);
    let result = tokio::select! {
        r = &mut conn => r,
        _ = &mut first_request => {
            if !seen_request.load(Ordering::Acquire) {
                tracing::debug!(?peer, "no request before timeout; closing");
                return;
            }
            conn.await
        }
    };
    if let Err(e) = result {
        tracing::debug!(?peer, ?e, "connection error");
    }
}

/// Auth + rate-limit middleware in front of `proxy::handle`.
async fn route_request(
    state: Arc<AppState>,
    mut req: Request<Incoming>,
    peer: SocketAddr,
    limits: &Limits,
) -> Response<proxy::Body> {
    let claims = match authenticate(&state.jwt, &req).await {
        Ok(c) => c,
        Err(reason) => {
            metrics::counter!("ferryman_requests_total", "status" => "401").increment(1);
            metrics::counter!("ferryman_auth_failures_total", "reason" => reason.as_str())
                .increment(1);
            return unauthorized_response();
        }
    };

    if let Some(limiter) = &state.limiter {
        if !check(limiter, &claims.sub) {
            metrics::counter!("ferryman_requests_total", "status" => "429").increment(1);
            // Not labelled by tenant — unbounded cardinality.
            metrics::counter!("ferryman_ratelimited_total").increment(1);
            return rate_limited_response();
        }
    }

    // Strip hop-by-hop headers *before* stamping: a client could otherwise
    // send `Connection: x-ferryman-tenant` and have the strip delete the
    // stamped value.
    let upgrade = proxy::wants_upgrade(&req);
    proxy::strip_hop_by_hop(req.headers_mut());
    proxy::strip_noncanonical_asserted(req.headers_mut());
    // Stamp the tenant for the upstream; discard whatever the client sent
    // to close the obvious spoofing hole.
    req.headers_mut().remove("x-ferryman-tenant");
    if let Ok(v) = HeaderValue::from_str(&claims.sub) {
        req.headers_mut().insert("x-ferryman-tenant", v);
    }

    match proxy::handle_checked(
        state.table.clone(),
        state.client.clone(),
        req,
        peer.ip(),
        upgrade,
        limits,
    )
    .await
    {
        Ok(resp) => resp,
        Err(e) => {
            tracing::error!(?e, "unhandled proxy error");
            metrics::counter!("ferryman_requests_total", "status" => "500").increment(1);
            internal_error_response()
        }
    }
}

enum AuthFailure {
    Missing,
    Invalid,
}

impl AuthFailure {
    fn as_str(&self) -> &'static str {
        match self {
            AuthFailure::Missing => "missing",
            AuthFailure::Invalid => "invalid",
        }
    }
}

async fn authenticate(jwt: &JwtVerifier, req: &Request<Incoming>) -> Result<Claims, AuthFailure> {
    let raw = req
        .headers()
        .get(http::header::AUTHORIZATION)
        .ok_or(AuthFailure::Missing)?;
    let raw = raw.to_str().map_err(|_| AuthFailure::Invalid)?;
    let (scheme, token) = raw.split_once(' ').ok_or(AuthFailure::Invalid)?;
    if !scheme.eq_ignore_ascii_case("bearer") || token.is_empty() {
        return Err(AuthFailure::Invalid);
    }
    jwt.verify(token).await.ok_or(AuthFailure::Invalid)
}

fn unauthorized_response() -> Response<proxy::Body> {
    Response::builder()
        .status(401)
        .header(http::header::WWW_AUTHENTICATE, "Bearer")
        .body(proxy::text_body(Bytes::from_static(b"unauthorized")))
        .expect("static response builds")
}

fn rate_limited_response() -> Response<proxy::Body> {
    Response::builder()
        .status(429)
        .header("retry-after", "1")
        .body(proxy::text_body(Bytes::from_static(b"rate limited")))
        .expect("static response builds")
}

fn internal_error_response() -> Response<proxy::Body> {
    Response::builder()
        .status(500)
        .body(proxy::text_body(Bytes::from_static(b"internal error")))
        .expect("static response builds")
}
