//! ferryman-edge-server — programmable mTLS L7 reverse proxy.
//!
//! This binary is arg parsing + boot: load config, build the mTLS/JWT/route
//! primitives, spin up background tasks (health checker, SIGUSR1 reload,
//! rate-limiter GC), then hand off to `ferryman_edge::serve_with` for the
//! accept loop and per-request pipeline.

use arc_swap::ArcSwap;
use clap::Parser;
use ferryman_edge::{reload, serve_with, AppState, UpstreamClient};
use ferryman_edge_core::{
    build_limiter, build_table, health_loop, spawn_gc, EdgeConfig, JwtVerifier, Limiter,
    ReloadingTls, SharedTable,
};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use metrics_exporter_prometheus::PrometheusBuilder;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tracing_subscriber::EnvFilter;

/// Rate-limiter GC interval — evicts per-tenant state that hasn't been
/// touched recently so the keyed store doesn't grow unbounded.
const LIMITER_GC_INTERVAL: Duration = Duration::from_secs(60);

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
    // ring is the only rustls provider compiled in (deny.toml bans aws-lc),
    // so rustls could pick it on its own; installing it explicitly keeps the
    // choice visible and fails loudly if a second provider ever sneaks in.
    rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|_| anyhow::anyhow!("failed to install the ring crypto provider"))?;

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .json()
        .init();

    let args = Args::parse();

    // Load + parse the initial config. Fail fast on first-boot misconfiguration.
    let raw = std::fs::read_to_string(&args.config)?;
    let cfg = EdgeConfig::parse(&raw)?;
    for d in &cfg.deprecations {
        tracing::warn!(config = %args.config.display(), "{d}");
    }
    let interval = Duration::from_secs(cfg.core.health_interval_secs);

    // Routing table (atomic hot-swap).
    let table = build_table(&cfg.core)?;
    let shared: SharedTable = Arc::new(ArcSwap::from_pointee(table));

    // mTLS material + reloading wrapper. SIGUSR1 swaps cert/key/ca atomically.
    let tls = ReloadingTls::new(
        &cfg.mtls.cert_path,
        &cfg.mtls.key_path,
        &cfg.mtls.client_ca_path,
    )?;

    // JWT verifier: RSA pub key read at boot and re-read from the same path
    // on SIGUSR1. Cache TTL == 5 min, capacity == 10k (cleared on key reload).
    let jwks_pem = std::fs::read(&cfg.jwt.jwks_path)?;
    let mut verifier = JwtVerifier::new(&jwks_pem)?;
    if let Some(iss) = &cfg.jwt.issuer {
        verifier = verifier.with_issuer(iss);
    }
    if let Some(aud) = &cfg.jwt.audience {
        verifier = verifier.with_audience(aud);
    }
    let jwt: Arc<JwtVerifier> = Arc::new(verifier);
    reload::spawn_jwt_reload(cfg.jwt.jwks_path.clone().into(), jwt.clone());

    // Per-tenant rate limiter, keyed by `Claims::sub`. `None` when
    // `tenant_rps == 0` — rate limiting is disabled outright rather than
    // silently clamped to 1 rps.
    let limiter: Option<Arc<Limiter>> = build_limiter(cfg.limits.tenant_rps);
    if let Some(l) = &limiter {
        spawn_gc(l.clone(), LIMITER_GC_INTERVAL);
    }

    // Prometheus exporter binds its own listener so the proxy is unaffected
    // by /metrics scrape traffic.
    PrometheusBuilder::new()
        .with_http_listener(args.metrics_bind)
        .install()?;
    tracing::info!(addr = %args.metrics_bind, "metrics listener bound");

    // Background tasks: active health checker + SIGUSR1-driven route reload.
    tokio::spawn(health_loop(shared.clone(), interval));
    reload::spawn_reload(args.config.clone(), shared.clone());

    // Shared hyper upstream client. Single instance across the process; its
    // pool keeps idle HTTP/1.1 connections to each upstream (outbound is
    // always HTTP/1.1, whatever the client spoke).
    let client: UpstreamClient = Client::builder(TokioExecutor::new()).build(HttpConnector::new());

    let state = Arc::new(AppState {
        tls,
        table: shared,
        jwt,
        limiter,
        client,
    });

    let listener = tokio::net::TcpListener::bind(args.bind).await?;
    tracing::info!(addr = %args.bind, "ferryman-edge-server listening (mTLS)");

    serve_with(listener, state, cfg.limits.clone(), shutdown_signal()).await;
    Ok(())
}

/// Resolves on SIGTERM or SIGINT (fly.toml uses `kill_signal = "SIGINT"`,
/// `kill_timeout = 30`) so `serve_with` can start its own bounded drain.
async fn shutdown_signal() {
    let mut sigterm = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
    {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(?e, "failed to install SIGTERM handler");
            return;
        }
    };
    tokio::select! {
        _ = sigterm.recv() => tracing::info!("SIGTERM received"),
        _ = tokio::signal::ctrl_c() => tracing::info!("SIGINT received"),
    }
}
