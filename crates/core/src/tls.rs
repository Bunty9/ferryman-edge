//! mTLS server config + hot-reloading wrapper.
//!
//! Uses `rustls` 0.23 with the `aws-lc-rs` cryptographic provider — FIPS
//! path is via the same `aws-lc-fips-sys` crate (interview talking point).
//! The cert chain is loaded via `rustls-pemfile` 2 from disk; we deliberately
//! avoid `webpki-roots` for the *client* CA store because we want only the
//! tenant's CA chain to validate inbound peers.
//!
//! Hot-reload is `SIGUSR1`-driven (see `ReloadingTls::watch`). This is the
//! defensible choice over `notify` filesystem events: k8s ConfigMap
//! mounts use symlink-swap, which `notify` reports as a chain of remove +
//! create on the *symlink target* rather than the watched path — easy to
//! miss without per-platform special-casing. `SIGUSR1` is one POSIX call
//! with predictable semantics across every deploy target.

use arc_swap::ArcSwap;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ServerConfig, WebPkiClientVerifier};
use std::io::BufReader;
use std::sync::Arc;

/// Build a fully-configured mTLS [`ServerConfig`]. Loads:
/// * the server certificate chain from `cert_path` (PEM bundle).
/// * the matching private key from `key_path` (PKCS#8 / RSA).
/// * the trusted client-CA bundle from `client_ca_path` — any inbound peer
///   cert must chain to one of these roots.
///
/// ALPN advertises `h2` then `http/1.1`. The provider is `aws-lc-rs`
/// (selected at workspace level via `rustls`'s `aws-lc-rs` feature with
/// `default-features = false`).
pub fn build_mtls_config(
    cert_path: &str,
    key_path: &str,
    client_ca_path: &str,
) -> anyhow::Result<Arc<ServerConfig>> {
    let certs: Vec<CertificateDer<'static>> =
        rustls_pemfile::certs(&mut BufReader::new(std::fs::File::open(cert_path)?))
            .collect::<Result<_, _>>()?;
    let key: PrivateKeyDer<'static> =
        rustls_pemfile::private_key(&mut BufReader::new(std::fs::File::open(key_path)?))?
            .ok_or_else(|| anyhow::anyhow!("no private key in {}", key_path))?;

    let mut roots = rustls::RootCertStore::empty();
    for c in rustls_pemfile::certs(&mut BufReader::new(std::fs::File::open(client_ca_path)?)) {
        roots.add(c?)?;
    }
    let verifier = WebPkiClientVerifier::builder(Arc::new(roots)).build()?;

    let mut cfg = ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(certs, key)?;
    cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(Arc::new(cfg))
}

/// Hot-reloading wrapper. The acceptor loop calls [`Self::current`] on each
/// inbound connection and gets the *latest* `Arc<ServerConfig>`. A swap
/// affects only future handshakes; live connections keep their pinned
/// config. Trigger a reload with `kill -USR1 $(pidof ferryman-edge-server)`.
pub struct ReloadingTls {
    inner: Arc<ArcSwap<ServerConfig>>,
    paths: (String, String, String),
}

impl ReloadingTls {
    pub fn new(cert: &str, key: &str, ca: &str) -> anyhow::Result<Arc<Self>> {
        let cfg = build_mtls_config(cert, key, ca)?;
        let s = Arc::new(Self {
            inner: Arc::new(ArcSwap::new(cfg)),
            paths: (cert.into(), key.into(), ca.into()),
        });
        Self::watch(s.clone());
        Ok(s)
    }

    pub fn current(&self) -> Arc<ServerConfig> {
        self.inner.load_full()
    }

    fn watch(s: Arc<Self>) {
        let paths = s.paths.clone();
        tokio::spawn(async move {
            let mut sig = match tokio::signal::unix::signal(
                tokio::signal::unix::SignalKind::user_defined1(),
            ) {
                Ok(s) => s,
                Err(e) => {
                    tracing::error!(?e, "failed to register SIGUSR1 handler");
                    return;
                }
            };
            // SIGUSR1 triggers reload — simpler and more reliable than notify on k8s ConfigMap mounts.
            while sig.recv().await.is_some() {
                match build_mtls_config(&paths.0, &paths.1, &paths.2) {
                    Ok(cfg) => {
                        s.inner.store(cfg);
                        tracing::info!("mTLS config reloaded");
                    }
                    Err(e) => tracing::error!(?e, "mTLS reload failed; keeping old"),
                }
            }
        });
    }
}
