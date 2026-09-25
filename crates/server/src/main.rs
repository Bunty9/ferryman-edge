//! ferryman-edge-server — programmable mTLS L7 reverse proxy.
//!
//! Wires `ferryman-edge-core` behind a `tokio-rustls` acceptor:
//!
//!   inbound TCP
//!     -> `TlsAcceptor::accept` using the *current* `ReloadingTls` config
//!     -> hyper `serve_connection` over the TLS stream
//!     -> per-request: JWT verify, rate-limit by `Claims::sub`, route, proxy.
//!
//! Phase 1: the full acceptor wire-up is gated behind a `todo!()` for the
//! request-level auth path (see `tls_serve`); `cargo check --workspace`
//! passes and the binary builds. Phase 2 fills in the auth middleware and
//! takes wrk2 numbers.

mod proxy;
mod reload;

use arc_swap::ArcSwap;
use clap::Parser;
use ferryman_edge_core::{
    build_limiter, build_table, health_loop, ratelimit::Limiter, ConfigToml, JwtVerifier,
    ReloadingTls, SharedTable,
};
use http_body_util::Full;
use hyper::body::Bytes;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use metrics_exporter_prometheus::PrometheusBuilder;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(name = "ferryman-edge-server", about = "programmable mTLS L7 proxy")]
struct Args {
    /// Path to the TOML config (TLS paths, JWKS path, routes, rps cap).
    #[arg(long, env = "FERRYMAN_EDGE_CONFIG", default_value = "config.toml")]
    config: PathBuf,

    /// Bind address for the mTLS listener (HTTPS).
    #[arg(long, env = "FERRYMAN_EDGE_BIND", default_value = "0.0.0.0:8443")]
    bind: SocketAddr,

    /// Bind address for the Prometheus `/metrics` listener.
    #[arg(
        long,
        env = "FERRYMAN_EDGE_METRICS_BIND",
        default_value = "0.0.0.0:9090"
    )]
    metrics_bind: SocketAddr,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Install the aws-lc-rs default crypto provider for rustls before any
    // ServerConfig is built. Required because we disabled `rustls`'s default
    // features (no ring) at the workspace level.
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .map_err(|_| anyhow::anyhow!("failed to install aws-lc-rs crypto provider"))?;

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .json()
        .init();

    let args = Args::parse();

    // Load + parse the initial config. Fail fast on first-boot misconfiguration.
    let raw = std::fs::read_to_string(&args.config)?;
    let cfg: ConfigToml = toml::from_str(&raw)?;
    let interval = Duration::from_secs(cfg.health_interval_secs);

    // Routing table (atomic hot-swap).
    let table = build_table(&cfg)?;
    let shared: SharedTable = Arc::new(ArcSwap::from_pointee(table));

    // mTLS material + reloading wrapper. SIGUSR1 swaps cert/key/ca atomically.
    let tls = ReloadingTls::new(
        &cfg.tls.cert_path,
        &cfg.tls.key_path,
        &cfg.tls.client_ca_path,
    )?;

    // JWT verifier reads the RSA pub key once at boot. Cache TTL == 5 min,
    // capacity == 10k. Stable across reloads — re-init on Phase 2 if the
    // issuer key rotates.
    let jwks_pem = std::fs::read(&cfg.jwt.jwks_path)?;
    let jwt: Arc<JwtVerifier> = Arc::new(JwtVerifier::new(&jwks_pem)?);

    // Per-tenant rate limiter, keyed by `Claims::sub`. `None` when
    // `tenant_rps == 0` — rate limiting is disabled outright rather than
    // silently clamped to 1 rps.
    let limiter: Option<Arc<Limiter>> = build_limiter(cfg.tenant_rps);

    // Prometheus exporter binds its own listener so the proxy is unaffected
    // by /metrics scrape traffic.
    PrometheusBuilder::new()
        .with_http_listener(args.metrics_bind)
        .install()?;
    tracing::info!(addr = %args.metrics_bind, "metrics listener bound");

    // Background tasks: active health checker + SIGUSR1-driven route reload.
    tokio::spawn(health_loop(shared.clone(), interval));
    reload::spawn_reload(args.config.clone(), shared.clone());

    // Shared hyper upstream client. Single instance across the process — its
    // internal pool multiplexes HTTP/2 streams to each upstream.
    let _client: Client<HttpConnector, Full<Bytes>> =
        Client::builder(TokioExecutor::new()).build(HttpConnector::new());

    let listener = tokio::net::TcpListener::bind(args.bind).await?;
    tracing::info!(addr = %args.bind, "ferryman-edge-server listening (mTLS)");

    loop {
        let (stream, peer) = listener.accept().await?;
        let _tls = tls.clone();
        let _shared = shared.clone();
        let _jwt = jwt.clone();
        let _limiter = limiter.clone();
        let _client = _client.clone();
        tokio::spawn(async move {
            if let Err(e) = tls_serve(stream, peer, _tls, _shared, _jwt, _limiter, _client).await {
                tracing::debug!(?peer, ?e, "connection closed with error");
            }
        });
    }
}

/// Per-connection task. Phase 2 fills in the auth + rate-limit middleware
/// between the TLS handshake and `proxy::handle`; for now the
/// `todo!()` keeps the workspace honest about what's missing while still
/// type-checking the full call graph.
#[allow(clippy::too_many_arguments)]
async fn tls_serve(
    _stream: tokio::net::TcpStream,
    _peer: SocketAddr,
    _tls: Arc<ReloadingTls>,
    _shared: SharedTable,
    _jwt: Arc<JwtVerifier>,
    _limiter: Option<Arc<Limiter>>,
    _client: Client<HttpConnector, Full<Bytes>>,
) -> anyhow::Result<()> {
    // Phase 2: tokio_rustls::TlsAcceptor::from(_tls.current()).accept(_stream)
    // -> hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
    //    .serve_connection(TokioIo::new(tls_stream), service_fn(|req| async {
    //        let token = req.headers().get("authorization") ...;
    //        let claims = _jwt.verify(token).await ...;
    //        ferryman_edge_core::ratelimit::check(&_limiter, &claims.sub) ...;
    //        proxy::handle(_shared.clone(), _client.clone(), req).await
    //    }))
    todo!("Phase 2: wire tokio-rustls acceptor + JWT/ratelimit middleware around proxy::handle")
}

/// Placeholder for a future `/metrics` router served via tower (e.g. when
/// scrape filtering or auth on the metrics surface is needed). The
/// Prometheus exporter currently owns the listener directly — see `main()`.
#[allow(dead_code)]
fn metrics_router() {
    todo!("Phase 2: optional tower router for /metrics with auth + scrape filters");
}
