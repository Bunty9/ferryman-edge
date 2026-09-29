//! In-process tests: real mTLS handshakes against `serve_tls`, certs from
//! rcgen written to a tempdir so `ReloadingTls` loads them from disk.
//! Uses the committed RSA JWT fixtures from `ferryman-edge-core`.

use ferryman_edge_core::{build_limiter, JwtVerifier, ReloadingTls};
use ferryman_edge_embed_example::{router, serve_tls, AppState, HEADER_READ_TIMEOUT};
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose,
};
use rustls::pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer, ServerName};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;

const ISS: &str = "https://issuer.test";
const AUD: &str = "embed-test";
const JWT_PRIV: &[u8] = include_bytes!("fixtures/test-only-jwt-priv.pem");
const JWT_PUB: &[u8] = include_bytes!("fixtures/test-only-jwt-pub.pem");

fn leaf(cn: &str, sans: &[&str], ca: &Certificate, ca_key: &KeyPair) -> (Certificate, KeyPair) {
    let key = KeyPair::generate().unwrap();
    let mut p =
        CertificateParams::new(sans.iter().map(|s| s.to_string()).collect::<Vec<_>>()).unwrap();
    p.distinguished_name.push(DnType::CommonName, cn);
    (p.signed_by(&key, ca, ca_key).unwrap(), key)
}

fn write_server_leaf(dir: &std::path::Path, ca: &Certificate, ca_key: &KeyPair) {
    let (c, k) = leaf("localhost", &["localhost", "127.0.0.1"], ca, ca_key);
    std::fs::write(dir.join("server.crt"), c.pem()).unwrap();
    std::fs::write(dir.join("server.key"), k.serialize_pem()).unwrap();
}

struct Harness {
    dir: tempfile::TempDir,
    ca: Certificate,
    ca_key: KeyPair,
    client_cert: String,
    client_key: String,
    tls: Arc<ReloadingTls>,
    addr: SocketAddr,
    _shutdown: tokio::sync::oneshot::Sender<()>,
}

impl Harness {
    async fn new(rps: u32) -> Self {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let dir = tempfile::tempdir().unwrap();
        let ca_key = KeyPair::generate().unwrap();
        let mut p = CertificateParams::new(Vec::<String>::new()).unwrap();
        p.distinguished_name
            .push(DnType::CommonName, "embed test CA");
        p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        p.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        let ca = p.self_signed(&ca_key).unwrap();
        let (client, client_key) = leaf("test-client", &[], &ca, &ca_key);
        let d = dir.path();
        std::fs::write(d.join("ca.crt"), ca.pem()).unwrap();
        write_server_leaf(d, &ca, &ca_key);
        let p = |n: &str| d.join(n).to_str().unwrap().to_string();
        let tls = ReloadingTls::new(&p("server.crt"), &p("server.key"), &p("ca.crt")).unwrap();
        let app = router(AppState {
            jwt: Arc::new(
                JwtVerifier::new(JWT_PUB)
                    .unwrap()
                    .with_issuer(ISS)
                    .with_audience(AUD),
            ),
            limiter: build_limiter(rps),
        });
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        tokio::spawn(serve_tls(listener, tls.clone(), app, async {
            let _ = rx.await;
        }));
        Self {
            client_cert: client.pem(),
            client_key: client_key.serialize_pem(),
            dir,
            ca,
            ca_key,
            tls,
            addr,
            _shutdown: tx,
        }
    }

    /// Overwrite the on-disk server leaf with a fresh one from the same CA.
    fn rotate_server_leaf(&self) {
        write_server_leaf(self.dir.path(), &self.ca, &self.ca_key);
    }

    fn client(&self, with_cert: bool) -> reqwest::Client {
        let mut b = reqwest::Client::builder()
            .use_rustls_tls()
            .add_root_certificate(
                reqwest::Certificate::from_pem(self.ca.pem().as_bytes()).unwrap(),
            );
        if with_cert {
            let pem = format!("{}{}", self.client_cert, self.client_key);
            b = b.identity(reqwest::Identity::from_pem(pem.as_bytes()).unwrap());
        }
        b.build().unwrap()
    }

    fn url(&self, p: &str) -> String {
        format!("https://127.0.0.1:{}{p}", self.addr.port())
    }

    fn client_config(&self) -> rustls::ClientConfig {
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(CertificateDer::from_pem_slice(self.ca.pem().as_bytes()).unwrap())
            .unwrap();
        rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_client_auth_cert(
                vec![CertificateDer::from_pem_slice(self.client_cert.as_bytes()).unwrap()],
                PrivateKeyDer::from_pem_slice(self.client_key.as_bytes()).unwrap(),
            )
            .unwrap()
    }

    /// Server leaf DER as seen by a fresh mTLS client (reqwest hides it).
    async fn peer_leaf(&self) -> Vec<u8> {
        let cfg = self.client_config();
        let tcp = tokio::net::TcpStream::connect(self.addr).await.unwrap();
        let s = tokio_rustls::TlsConnector::from(Arc::new(cfg))
            .connect(ServerName::try_from("localhost").unwrap(), tcp)
            .await
            .unwrap();
        s.get_ref().1.peer_certificates().unwrap()[0].to_vec()
    }
}

fn token(sub: &str) -> String {
    token_for(sub, AUD)
}

fn token_for(sub: &str, aud: &str) -> String {
    let exp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as usize
        + 3600;
    jsonwebtoken::encode(
        &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256),
        &serde_json::json!({ "sub": sub, "exp": exp, "scope": "read", "iss": ISS, "aud": aud }),
        &jsonwebtoken::EncodingKey::from_rsa_pem(JWT_PRIV).unwrap(),
    )
    .unwrap()
}

#[tokio::test]
async fn valid_token_returns_sub() {
    let h = Harness::new(0).await;
    let r = h
        .client(true)
        .get(h.url("/whoami"))
        .bearer_auth(token("acme"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let v: serde_json::Value = r.json().await.unwrap();
    assert_eq!(v["sub"], "acme");
    assert_eq!(v["scope"], "read");
}

#[tokio::test]
async fn missing_token_is_401() {
    let h = Harness::new(0).await;
    let r = h.client(true).get(h.url("/whoami")).send().await.unwrap();
    assert_eq!(r.status(), 401);
    assert_eq!(r.headers()["www-authenticate"], "Bearer");
}

#[tokio::test]
async fn third_request_over_two_rps_is_429() {
    let h = Harness::new(2).await;
    let c = h.client(true);
    let t = token("acme");
    let mut codes = vec![];
    for _ in 0..3 {
        let r = c
            .get(h.url("/whoami"))
            .bearer_auth(&t)
            .send()
            .await
            .unwrap();
        codes.push(r.status().as_u16());
        if r.status() == 429 {
            assert_eq!(r.headers()["retry-after"], "1");
        }
    }
    assert_eq!(codes, [200, 200, 429]);
}

#[tokio::test]
async fn no_client_cert_is_rejected() {
    let h = Harness::new(0).await;
    assert!(h.client(false).get(h.url("/health")).send().await.is_err());
}

#[tokio::test]
async fn health_needs_no_token() {
    let h = Harness::new(0).await;
    let r = h.client(true).get(h.url("/health")).send().await.unwrap();
    assert_eq!(r.status(), 200);
}

#[tokio::test]
async fn reload_swaps_server_cert() {
    let h = Harness::new(0).await;
    let before = h.peer_leaf().await;
    h.rotate_server_leaf();
    h.tls.reload().unwrap();
    assert_ne!(before, h.peer_leaf().await);
}

#[tokio::test]
async fn wrong_audience_is_401() {
    let h = Harness::new(0).await;
    let t = token_for("acme", "someone-else");
    let r = h
        .client(true)
        .get(h.url("/whoami"))
        .bearer_auth(t)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 401);
}

/// Completes mTLS with ALPN h2, then sends nothing: the server must hang up
/// after HEADER_READ_TIMEOUT instead of holding the connection forever.
#[tokio::test]
async fn silent_h2_client_is_dropped() {
    use tokio::io::AsyncReadExt;
    let h = Harness::new(0).await;
    let mut cfg = h.client_config();
    cfg.alpn_protocols = vec![b"h2".to_vec()];
    let tcp = tokio::net::TcpStream::connect(h.addr).await.unwrap();
    let mut s = tokio_rustls::TlsConnector::from(Arc::new(cfg))
        .connect(ServerName::try_from("localhost").unwrap(), tcp)
        .await
        .unwrap();
    let mut buf = [0u8; 1024];
    let wait = HEADER_READ_TIMEOUT + std::time::Duration::from_secs(1);
    // The server may send its h2 SETTINGS first; read until EOF/error.
    let end = tokio::time::timeout(wait, async {
        while matches!(s.read(&mut buf).await, Ok(n) if n > 0) {}
    })
    .await;
    assert!(end.is_ok(), "connection still open after {wait:?}");
}
