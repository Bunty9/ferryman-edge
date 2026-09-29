//! Configured entirely by environment variables; see README.md.

use ferryman_edge_core::{build_limiter, spawn_gc, JwtVerifier, ReloadingTls};
use ferryman_edge_embed_example::{router, serve_tls, AppState};
use std::sync::Arc;
use std::time::Duration;

fn required(name: &str) -> anyhow::Result<String> {
    std::env::var(name).map_err(|_| anyhow::anyhow!("{name} must be set"))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    if std::env::var("EMBED_LOG_JSON").is_ok_and(|v| v == "1") {
        tracing_subscriber::fmt().json().init();
    } else {
        tracing_subscriber::fmt().init();
    }
    // rustls needs a process-wide provider before any config is built.
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .map_err(|_| anyhow::anyhow!("crypto provider already installed"))?;

    let bind = std::env::var("EMBED_BIND").unwrap_or_else(|_| "127.0.0.1:8444".into());
    let rps: u32 = std::env::var("EMBED_TENANT_RPS")
        .ok()
        .map(|v| v.parse())
        .transpose()?
        .unwrap_or(100);

    let jwt = JwtVerifier::new(&std::fs::read(required("EMBED_JWT_PUB")?)?)?;
    // Required: without iss/aud checks, any token signed by this key is accepted.
    let jwt = jwt
        .with_issuer(&required("EMBED_ISSUER")?)
        .with_audience(&required("EMBED_AUDIENCE")?);
    let limiter = build_limiter(rps);
    if let Some(l) = &limiter {
        spawn_gc(l.clone(), Duration::from_secs(60));
    }

    // Also registers the SIGUSR1 reload handler.
    let tls = ReloadingTls::new(
        &required("EMBED_CERT")?,
        &required("EMBED_KEY")?,
        &required("EMBED_CLIENT_CA")?,
    )?;
    let app = router(AppState {
        jwt: Arc::new(jwt),
        limiter,
    });

    let listener = tokio::net::TcpListener::bind(&bind).await?;
    tracing::info!(%bind, rps, "embed-core listening (mTLS)");
    serve_tls(listener, tls, app, shutdown_signal()).await;
    Ok(())
}

async fn shutdown_signal() {
    use tokio::signal::unix::{signal, SignalKind};
    let mut term = signal(SignalKind::terminate()).expect("SIGTERM handler");
    tokio::select! {
        _ = term.recv() => {}
        _ = tokio::signal::ctrl_c() => {}
    }
}
