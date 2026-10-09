//! Clients that talk to the proxy the way real callers do.
//!
//! reqwest covers normal requests. `raw_http1` and `peer_cert_sha256` drop
//! to tokio-rustls for the two things reqwest cannot show: bytes exactly as
//! written (no URL normalisation) and the certificate the server presented.

use crate::pki::Pki;
use anyhow::Context;
use ring::digest;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::TlsConnector;

const TIMEOUT: Duration = Duration::from_secs(30);

fn builder(pki: &Pki) -> anyhow::Result<reqwest::ClientBuilder> {
    let ca = reqwest::Certificate::from_pem(&std::fs::read(pki.path("ca.crt"))?)?;
    Ok(reqwest::Client::builder()
        // Trust only the demo CA, never the system roots, and never plain http.
        .tls_built_in_root_certs(false)
        .add_root_certificate(ca)
        .https_only(true)
        .timeout(TIMEOUT))
}

fn with_identity(
    pki: &Pki,
    b: reqwest::ClientBuilder,
    prefix: &str,
) -> anyhow::Result<reqwest::ClientBuilder> {
    // reqwest wants certificate and key concatenated in one PEM buffer.
    let mut pem = std::fs::read(pki.path(&format!("{prefix}.crt")))?;
    pem.extend(std::fs::read(pki.path(&format!("{prefix}.key")))?);
    Ok(b.identity(reqwest::Identity::from_pem(&pem)?))
}

/// Client that trusts the demo CA and presents the valid client certificate.
/// Negotiates HTTP/2 via ALPN unless `http1_only`.
pub fn mtls_client(pki: &Pki, http1_only: bool) -> anyhow::Result<reqwest::Client> {
    let mut b = with_identity(pki, builder(pki)?, "client")?;
    if http1_only {
        b = b.http1_only();
    }
    Ok(b.build()?)
}

/// Trusts the proxy but presents no client certificate: the handshake must fail.
pub fn client_without_cert(pki: &Pki) -> anyhow::Result<reqwest::Client> {
    Ok(builder(pki)?.build()?)
}

/// Presents a certificate from a CA the proxy does not trust.
pub fn rogue_client(pki: &Pki) -> anyhow::Result<reqwest::Client> {
    Ok(with_identity(pki, builder(pki)?, "rogue-client")?.build()?)
}

fn tls_config(pki: &Pki, alpn: &[&[u8]]) -> anyhow::Result<Arc<rustls::ClientConfig>> {
    let mut roots = rustls::RootCertStore::empty();
    for c in CertificateDer::pem_file_iter(pki.path("ca.crt"))? {
        roots.add(c?)?;
    }
    let chain: Vec<CertificateDer<'static>> =
        CertificateDer::pem_file_iter(pki.path("client.crt"))?.collect::<Result<_, _>>()?;
    let key = PrivateKeyDer::from_pem_file(pki.path("client.key"))?;
    let mut cfg = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_client_auth_cert(chain, key)?;
    cfg.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    Ok(Arc::new(cfg))
}

async fn connect(
    pki: &Pki,
    addr: SocketAddr,
    alpn: &[&[u8]],
) -> anyhow::Result<tokio_rustls::client::TlsStream<tokio::net::TcpStream>> {
    let tcp = tokio::net::TcpStream::connect(addr).await?;
    let name = ServerName::try_from("localhost")?;
    Ok(TlsConnector::from(tls_config(pki, alpn)?)
        .connect(name, tcp)
        .await?)
}

/// Hex SHA-256 of the leaf certificate the server presents. Used to observe
/// a certificate rotation from the outside.
pub async fn peer_cert_sha256(pki: &Pki, addr: SocketAddr) -> anyhow::Result<String> {
    let tls = connect(pki, addr, &[b"http/1.1"]).await?;
    let leaf = tls
        .get_ref()
        .1
        .peer_certificates()
        .and_then(|c| c.first())
        .context("server presented no certificate")?;
    Ok(digest::digest(&digest::SHA256, leaf.as_ref())
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect())
}

/// Send `request` verbatim over mTLS (HTTP/1.1) and return the status line.
/// The caller supplies the whole request, so paths like `/a/../b` reach the
/// proxy unmodified; reqwest's `url` crate would normalise them away.
pub async fn raw_http1(pki: &Pki, addr: SocketAddr, request: &[u8]) -> anyhow::Result<String> {
    let mut tls = connect(pki, addr, &[b"http/1.1"]).await?;
    tls.write_all(request).await?;
    tls.flush().await?;
    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];
    // Only the status line is needed; stop as soon as it is complete.
    while !buf.windows(2).any(|w| w == b"\r\n") {
        let n = tokio::time::timeout(TIMEOUT, tls.read(&mut chunk)).await??;
        anyhow::ensure!(n > 0, "connection closed before a status line");
        buf.extend_from_slice(&chunk[..n]);
    }
    let text = String::from_utf8_lossy(&buf);
    Ok(text.lines().next().unwrap_or_default().to_string())
}
