//! ferryman-edge-server — programmable mTLS L7 reverse proxy pipeline.
//!
//!   inbound TCP
//!     -> `TlsAcceptor::accept` using the *current* `ReloadingTls` config
//!     -> hyper `serve_connection` over the TLS stream
//!     -> per-request: JWT verify, rate-limit by `Claims::sub`, route, proxy
//!
//! `main.rs` is arg parsing + boot; this crate root owns the accept loop
//! (`serve`) and the auth middleware in front of `proxy::handle`, so both
//! can be driven directly from an integration test without a real process.

pub mod proxy;
pub mod reload;

use ferryman_edge_core::{check, Claims, JwtVerifier, Limiter, ReloadingTls, SharedTable};
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
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;

/// Shared upstream client. One instance for the whole process — its
/// internal pool multiplexes HTTP/2 streams to each upstream.
pub type UpstreamClient = Client<HttpConnector, proxy::Body>;

/// Everything a connection/request needs, built once at boot.
pub struct AppState {
    pub tls: Arc<ReloadingTls>,
    pub table: SharedTable,
    pub jwt: Arc<JwtVerifier>,
    pub limiter: Option<Arc<Limiter>>,
    pub client: UpstreamClient,
}

const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(10);
const SHUTDOWN_DRAIN: Duration = Duration::from_secs(25);
const ACCEPT_ERROR_BACKOFF: Duration = Duration::from_millis(50);

/// Accept loop. Runs until `shutdown` resolves, then stops accepting new
/// connections, lets in-flight ones finish (bounded by `SHUTDOWN_DRAIN`),
/// and returns.
pub async fn serve(
    listener: TcpListener,
    state: Arc<AppState>,
    shutdown: impl Future<Output = ()>,
) {
    let graceful = GracefulShutdown::new();
    let mut http = auto::Builder::new(TokioExecutor::new());
    http.http1()
        .timer(TokioTimer::new())
        .header_read_timeout(HEADER_READ_TIMEOUT);

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
                        tokio::spawn(async move {
                            handle_conn(stream, peer, state, http, watcher).await;
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
        _ = tokio::time::sleep(SHUTDOWN_DRAIN) => {
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
) {
    let acceptor = TlsAcceptor::from(state.tls.current());
    let started = Instant::now();
    let tls_stream =
        match tokio::time::timeout(TLS_HANDSHAKE_TIMEOUT, acceptor.accept(stream)).await {
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

    let io = TokioIo::new(tls_stream);
    let svc = service_fn(move |req| {
        let state = state.clone();
        async move { Ok::<_, Infallible>(route_request(state, req, peer).await) }
    });

    let conn = http.serve_connection(io, svc);
    if let Err(e) = watcher.watch(conn.into_owned()).await {
        tracing::debug!(?peer, ?e, "connection error");
    }
}

/// Auth + rate-limit middleware in front of `proxy::handle`.
async fn route_request(
    state: Arc<AppState>,
    mut req: Request<Incoming>,
    peer: SocketAddr,
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

    // Stamp the tenant for the upstream; discard whatever the client sent
    // to close the obvious spoofing hole.
    req.headers_mut().remove("x-ferryman-tenant");
    if let Ok(v) = HeaderValue::from_str(&claims.sub) {
        req.headers_mut().insert("x-ferryman-tenant", v);
    }

    match proxy::handle(state.table.clone(), state.client.clone(), req, peer.ip()).await {
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
