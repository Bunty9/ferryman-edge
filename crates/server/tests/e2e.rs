//! End-to-end test: real TLS handshake, real mTLS + JWT + rate-limit
//! middleware, real upstream over HTTP/1 and HTTP/2. Runs once under the
//! default (`collected`) body path and once under `--features boxed_body`.
//!
//! Certs are generated in-process with `rcgen` (CA -> server leaf, CA ->
//! trusted client leaf, a second untrusted CA -> client leaf) and written to
//! a tempdir so `ReloadingTls` can load them from disk like it would in
//! production. JWTs are signed with the same RSA fixture keypair
//! `ferryman-edge-core`'s own tests use.

use ferryman_edge::{reload, serve, AppState, UpstreamClient};
use ferryman_edge_core::{build_limiter, Claims, JwtVerifier, ReloadingTls, RouteTable, Upstream};
use http::{Request, Response};
use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::service::service_fn;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};
use rcgen::{BasicConstraints, Certificate, CertificateParams, DnType, IsCa, KeyPair};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use std::convert::Infallible;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tempfile::TempDir;
use tokio::net::TcpListener;
use tokio_rustls::TlsConnector;

const JWT_PRIV_PEM: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../core/tests/fixtures/jwt-test-priv.pem"
));
const JWT_PUB_PEM: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../core/tests/fixtures/jwt-test-pub.pem"
));

fn install_crypto_provider() {
    // rustls needs a process-wide default provider; installing more than
    // once is a no-op error we don't care about.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}

// ----- cert generation -------------------------------------------------

struct TestCerts {
    _dir: TempDir,
    server_cert_path: PathBuf,
    server_key_path: PathBuf,
    ca_bundle_path: PathBuf,
    ca_cert: Certificate,
    ca_key: KeyPair,
    ca_pem: Vec<u8>,
    client_cert_pem: Vec<u8>,
    client_key_pem: Vec<u8>,
    untrusted_client_cert_pem: Vec<u8>,
    untrusted_client_key_pem: Vec<u8>,
}

fn gen_ca(cn: &str) -> (Certificate, KeyPair) {
    let key = KeyPair::generate().expect("keypair");
    let mut params = CertificateParams::new(Vec::<String>::new()).expect("params");
    params.distinguished_name.push(DnType::CommonName, cn);
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let cert = params.self_signed(&key).expect("self-signed CA");
    (cert, key)
}

fn gen_leaf(
    cn: &str,
    sans: Vec<String>,
    ca: &Certificate,
    ca_key: &KeyPair,
) -> (Certificate, KeyPair) {
    let key = KeyPair::generate().expect("keypair");
    let mut params = CertificateParams::new(sans).expect("params");
    params.distinguished_name.push(DnType::CommonName, cn);
    let cert = params.signed_by(&key, ca, ca_key).expect("signed leaf");
    (cert, key)
}

impl TestCerts {
    fn generate() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let (ca_cert, ca_key) = gen_ca("ferryman-edge test CA");
        let (server_cert, server_key) = gen_leaf(
            "localhost",
            vec!["localhost".to_string(), "127.0.0.1".to_string()],
            &ca_cert,
            &ca_key,
        );
        let (client_cert, client_key) = gen_leaf("test-client", vec![], &ca_cert, &ca_key);
        let (other_ca_cert, other_ca_key) = gen_ca("untrusted test CA");
        let (bad_client_cert, bad_client_key) =
            gen_leaf("untrusted-client", vec![], &other_ca_cert, &other_ca_key);

        let server_cert_path = dir.path().join("server.crt");
        let server_key_path = dir.path().join("server.key");
        let ca_bundle_path = dir.path().join("ca-bundle.crt");
        std::fs::write(&server_cert_path, server_cert.pem()).expect("write server.crt");
        std::fs::write(&server_key_path, server_key.serialize_pem()).expect("write server.key");
        std::fs::write(&ca_bundle_path, ca_cert.pem()).expect("write ca-bundle.crt");

        Self {
            _dir: dir,
            server_cert_path,
            server_key_path,
            ca_bundle_path,
            ca_pem: ca_cert.pem().into_bytes(),
            ca_cert,
            ca_key,
            client_cert_pem: client_cert.pem().into_bytes(),
            client_key_pem: client_key.serialize_pem().into_bytes(),
            untrusted_client_cert_pem: bad_client_cert.pem().into_bytes(),
            untrusted_client_key_pem: bad_client_key.serialize_pem().into_bytes(),
        }
    }

    /// Rotate the on-disk server leaf to a fresh cert signed by the same
    /// CA, so a reload has something new to pick up.
    fn rotate_server_leaf(&self) {
        let (cert, key) = gen_leaf(
            "localhost",
            vec!["localhost".to_string(), "127.0.0.1".to_string()],
            &self.ca_cert,
            &self.ca_key,
        );
        std::fs::write(&self.server_cert_path, cert.pem()).expect("rewrite server.crt");
        std::fs::write(&self.server_key_path, key.serialize_pem()).expect("rewrite server.key");
    }
}

// ----- JWT ---------------------------------------------------------------

fn mint_jwt(sub: &str, ttl_secs: i64, scope: &str) -> String {
    use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let claims = Claims {
        sub: sub.to_string(),
        exp: (now + ttl_secs) as usize,
        scope: scope.to_string(),
    };
    encode(
        &Header::new(Algorithm::RS256),
        &claims,
        &EncodingKey::from_rsa_pem(JWT_PRIV_PEM).unwrap(),
    )
    .unwrap()
}

// ----- tiny upstream: echoes method/path/tenant/host/body ----------------

async fn echo_handler(req: Request<Incoming>) -> Result<Response<Full<Bytes>>, Infallible> {
    if req.uri().path() == "/health" {
        return Ok(Response::builder()
            .status(200)
            .body(Full::new(Bytes::new()))
            .unwrap());
    }
    let method = req.method().to_string();
    let path = req
        .uri()
        .path_and_query()
        .map(|p| p.to_string())
        .unwrap_or_default();
    let tenant = req
        .headers()
        .get("x-ferryman-tenant")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let host = req
        .headers()
        .get(http::header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let xff = req
        .headers()
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let body = req.into_body().collect().await.unwrap().to_bytes();
    Ok(Response::builder()
        .header("x-echo-xff", xff)
        .status(200)
        .header("x-upstream", "yes")
        .header("x-echo-method", method)
        .header("x-echo-path", path)
        .header("x-echo-tenant", tenant)
        .header("x-echo-host", host)
        .body(Full::new(body))
        .unwrap())
}

async fn spawn_upstream() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(v) => v,
                Err(_) => continue,
            };
            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(io, service_fn(echo_handler))
                    .await;
            });
        }
    });
    addr
}

/// A port nobody is listening on, for the upstream-down test.
fn closed_port() -> SocketAddr {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    addr
}

// ----- proxy harness -------------------------------------------------------

struct Harness {
    certs: TestCerts,
    upstream_addr: SocketAddr,
    proxy_addr: SocketAddr,
    tls: Arc<ReloadingTls>,
}

impl Harness {
    async fn new(tenant_rps: u32) -> Self {
        install_crypto_provider();
        let certs = TestCerts::generate();
        let upstream_addr = spawn_upstream().await;
        let down_addr = closed_port();

        let tls = ReloadingTls::new(
            certs.server_cert_path.to_str().unwrap(),
            certs.server_key_path.to_str().unwrap(),
            certs.ca_bundle_path.to_str().unwrap(),
        )
        .unwrap();
        let jwt = Arc::new(JwtVerifier::new(JWT_PUB_PEM).unwrap());
        let limiter = build_limiter(tenant_rps);

        let table = RouteTable::new(vec![
            (
                "/svc-a".to_string(),
                Upstream::new(format!("http://{upstream_addr}").parse().unwrap(), 30),
            ),
            (
                "/down".to_string(),
                Upstream::new(format!("http://{down_addr}").parse().unwrap(), 30),
            ),
        ]);
        let table = reload::new_shared(table);

        let client: UpstreamClient =
            Client::builder(TokioExecutor::new()).build(HttpConnector::new());

        let state = Arc::new(AppState {
            tls: tls.clone(),
            table,
            jwt,
            limiter,
            client,
        });

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = listener.local_addr().unwrap();
        tokio::spawn(serve(listener, state, std::future::pending()));

        Self {
            certs,
            upstream_addr,
            proxy_addr,
            tls,
        }
    }

    fn url(&self, path: &str) -> String {
        format!("https://127.0.0.1:{}{}", self.proxy_addr.port(), path)
    }

    fn client(&self) -> reqwest::Client {
        build_reqwest_client(
            &self.certs.ca_pem,
            Some((&self.certs.client_cert_pem, &self.certs.client_key_pem)),
            false,
        )
    }

    fn client_http1_only(&self) -> reqwest::Client {
        build_reqwest_client(
            &self.certs.ca_pem,
            Some((&self.certs.client_cert_pem, &self.certs.client_key_pem)),
            true,
        )
    }

    fn client_untrusted_cert(&self) -> reqwest::Client {
        build_reqwest_client(
            &self.certs.ca_pem,
            Some((
                &self.certs.untrusted_client_cert_pem,
                &self.certs.untrusted_client_key_pem,
            )),
            false,
        )
    }

    fn client_no_cert(&self) -> reqwest::Client {
        build_reqwest_client(&self.certs.ca_pem, None, false)
    }
}

fn build_reqwest_client(
    ca_pem: &[u8],
    identity: Option<(&[u8], &[u8])>,
    http1_only: bool,
) -> reqwest::Client {
    let mut builder = reqwest::Client::builder()
        .add_root_certificate(reqwest::Certificate::from_pem(ca_pem).unwrap())
        .use_rustls_tls();
    if let Some((cert, key)) = identity {
        let mut pem = Vec::with_capacity(cert.len() + key.len());
        pem.extend_from_slice(cert);
        pem.extend_from_slice(key);
        builder = builder.identity(reqwest::Identity::from_pem(&pem).unwrap());
    }
    if http1_only {
        builder = builder.http1_only();
    }
    builder.build().unwrap()
}

// ----- raw tokio-rustls client, for the hot-reload test --------------------
//
// reqwest doesn't expose the negotiated peer certificate, so the reload
// test connects directly with tokio-rustls and reads it off the
// connection. The verifier below accepts anything — we're not testing
// trust here, just "did the leaf change" — so it doesn't need to know
// which CA signed the (rotated) server cert.

#[derive(Debug)]
struct AcceptAnyServerCert;

impl ServerCertVerifier for AcceptAnyServerCert {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::aws_lc_rs::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

async fn tls_connect(
    proxy_addr: SocketAddr,
    certs: &TestCerts,
) -> tokio_rustls::client::TlsStream<tokio::net::TcpStream> {
    let client_certs: Vec<CertificateDer<'static>> =
        CertificateDer::pem_slice_iter(&certs.client_cert_pem)
            .collect::<Result<_, _>>()
            .unwrap();
    let client_key: PrivateKeyDer<'static> =
        PrivateKeyDer::from_pem_slice(&certs.client_key_pem).unwrap();

    let mut cfg = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyServerCert))
        .with_client_auth_cert(client_certs, client_key)
        .unwrap();
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];

    let connector = TlsConnector::from(Arc::new(cfg));
    let stream = tokio::net::TcpStream::connect(proxy_addr).await.unwrap();
    let server_name = ServerName::try_from("127.0.0.1").unwrap();
    connector.connect(server_name, stream).await.unwrap()
}

async fn fetch_peer_leaf_der(proxy_addr: SocketAddr, certs: &TestCerts) -> Vec<u8> {
    let tls_stream = tls_connect(proxy_addr, certs).await;
    let (_, conn) = tls_stream.get_ref();
    conn.peer_certificates().unwrap()[0].to_vec()
}

// ----- (a) happy path: cert + JWT ok, tenant header enforced ---------------

#[tokio::test]
async fn valid_request_succeeds_and_tenant_header_is_enforced() {
    let h = Harness::new(0).await;
    let client = h.client();
    let token = mint_jwt("tenant-a", 3600, "read");

    let resp = client
        .post(h.url("/svc-a/hello"))
        .header("authorization", format!("Bearer {token}"))
        .header("x-ferryman-tenant", "spoofed-tenant")
        .body("hello body")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    assert_eq!(resp.headers().get("x-upstream").unwrap(), "yes");
    assert_eq!(resp.headers().get("x-echo-tenant").unwrap(), "tenant-a");
    assert_eq!(
        resp.headers().get("x-echo-host").unwrap().to_str().unwrap(),
        h.upstream_addr.to_string()
    );
    assert_eq!(resp.text().await.unwrap(), "hello body");
}

#[tokio::test]
async fn client_cannot_strip_tenant_or_spoof_forwarding_headers() {
    let h = Harness::new(0).await;
    let token = mint_jwt("tenant-a", 3600, "read");

    // HTTP/1.1 only: h2 forbids the Connection header outright.
    let resp = h
        .client_http1_only()
        .get(h.url("/svc-a/hello"))
        .header("authorization", format!("Bearer {token}"))
        .header("connection", "keep-alive, x-ferryman-tenant")
        .header("x-forwarded-for", "6.6.6.6")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    assert_eq!(resp.headers().get("x-echo-tenant").unwrap(), "tenant-a");
    assert_eq!(resp.headers().get("x-echo-xff").unwrap(), "127.0.0.1");
}

// ----- (b) HTTP/2 regression ------------------------------------------------

#[tokio::test]
async fn http2_request_succeeds() {
    let h = Harness::new(0).await;
    let client = h.client();
    let token = mint_jwt("tenant-a", 3600, "read");

    let resp = client
        .get(h.url("/svc-a/hello"))
        .header("authorization", format!("Bearer {token}"))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    assert_eq!(resp.version(), reqwest::Version::HTTP_2);

    // And HTTP/1.1 still works over the same auto-negotiating server.
    let client1 = h.client_http1_only();
    let resp1 = client1
        .get(h.url("/svc-a/hello"))
        .header("authorization", format!("Bearer {token}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp1.status(), 200);
    assert_eq!(resp1.version(), reqwest::Version::HTTP_11);
}

// ----- (c) auth failures ----------------------------------------------------

#[tokio::test]
async fn missing_or_bad_token_is_rejected() {
    let h = Harness::new(0).await;
    let client = h.client();

    let resp = client.get(h.url("/svc-a/hello")).send().await.unwrap();
    assert_eq!(resp.status(), 401);
    assert!(resp.headers().get("www-authenticate").is_some());

    let resp = client
        .get(h.url("/svc-a/hello"))
        .header("authorization", "Bearer not-a-real-token")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

// ----- (d) mTLS failures ----------------------------------------------------

#[tokio::test]
async fn bad_client_identity_fails() {
    let h = Harness::new(0).await;
    let token = mint_jwt("tenant-a", 3600, "read");

    let untrusted = h.client_untrusted_cert();
    let err = untrusted
        .get(h.url("/svc-a/hello"))
        .header("authorization", format!("Bearer {token}"))
        .send()
        .await;
    assert!(err.is_err());

    let no_cert = h.client_no_cert();
    let err = no_cert
        .get(h.url("/svc-a/hello"))
        .header("authorization", format!("Bearer {token}"))
        .send()
        .await;
    assert!(err.is_err());
}

// ----- (e) per-tenant rate limit --------------------------------------------

#[tokio::test]
async fn rate_limit_is_enforced_per_tenant() {
    let h = Harness::new(2).await;
    let client = h.client();
    let token_a = mint_jwt("tenant-rl-a", 3600, "read");

    for _ in 0..2 {
        let resp = client
            .get(h.url("/svc-a/hello"))
            .header("authorization", format!("Bearer {token_a}"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
    }
    let resp3 = client
        .get(h.url("/svc-a/hello"))
        .header("authorization", format!("Bearer {token_a}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp3.status(), 429);
    assert_eq!(
        resp3
            .headers()
            .get("retry-after")
            .unwrap()
            .to_str()
            .unwrap(),
        "1"
    );

    let token_b = mint_jwt("tenant-rl-b", 3600, "read");
    let resp_b = client
        .get(h.url("/svc-a/hello"))
        .header("authorization", format!("Bearer {token_b}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp_b.status(), 200);
}

// ----- (f) routing + body-size limits ---------------------------------------

#[tokio::test]
async fn unknown_route_and_body_size_limit() {
    let h = Harness::new(0).await;
    let client = h.client();
    let token = mint_jwt("tenant-a", 3600, "read");

    let resp404 = client
        .get(h.url("/nope"))
        .header("authorization", format!("Bearer {token}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp404.status(), 404);

    let small = vec![b'x'; 1024];
    let resp_small = client
        .post(h.url("/svc-a/echo"))
        .header("authorization", format!("Bearer {token}"))
        .body(small.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(resp_small.status(), 200);
    assert_eq!(resp_small.bytes().await.unwrap().to_vec(), small);

    let big = vec![b'y'; 9 * 1024 * 1024];
    let resp_big = client
        .post(h.url("/svc-a/echo"))
        .header("authorization", format!("Bearer {token}"))
        .body(big)
        .send()
        .await
        .unwrap();
    assert_eq!(resp_big.status(), 413);
}

// ----- (g) upstream down: breaker trips -------------------------------------

/// An oversized chunked upload (no Content-Length, so no precheck) must be
/// a client-side 413 and must NOT open the route's breaker — otherwise any
/// tenant could take a route down for everyone.
#[tokio::test]
async fn oversized_chunked_upload_is_413_and_does_not_trip_breaker() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let h = Harness::new(0).await;
    let token = mint_jwt("tenant-a", 3600, "read");
    let tls = tls_connect(h.proxy_addr, &h.certs).await;
    let (mut rd, mut wr) = tokio::io::split(tls);

    let head = format!(
        "POST /svc-a/upload HTTP/1.1\r\nhost: localhost\r\n\
         authorization: Bearer {token}\r\ntransfer-encoding: chunked\r\n\r\n"
    );
    // The proxy may answer and stop reading before we finish; ignore write
    // errors from that point on.
    let writer = tokio::spawn(async move {
        wr.write_all(head.as_bytes()).await?;
        let chunk = vec![b'x'; 64 * 1024];
        let frame = format!("{:x}\r\n", chunk.len());
        for _ in 0..(9 * 16) {
            // 9 MiB total, over the 8 MiB cap
            wr.write_all(frame.as_bytes()).await?;
            wr.write_all(&chunk).await?;
            wr.write_all(b"\r\n").await?;
        }
        wr.write_all(b"0\r\n\r\n").await?;
        std::io::Result::Ok(())
    });

    let mut buf = vec![0u8; 256];
    let n = tokio::time::timeout(std::time::Duration::from_secs(20), rd.read(&mut buf))
        .await
        .expect("proxy answered")
        .unwrap();
    let status_line = String::from_utf8_lossy(&buf[..n]);
    assert!(status_line.starts_with("HTTP/1.1 413"), "{status_line}");
    writer.abort();

    let resp = h
        .client()
        .get(h.url("/svc-a/hello"))
        .header("authorization", format!("Bearer {token}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "breaker must still be closed");
}

/// Send one raw HTTP/1.1 GET (path verbatim) and return (status line, headers+body).
async fn raw_get(h: &Harness, path: &str, token: Option<&str>) -> (String, String) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut tls = tls_connect(h.proxy_addr, &h.certs).await;
    let auth = token
        .map(|t| format!("authorization: Bearer {t}\r\n"))
        .unwrap_or_default();
    let req = format!("GET {path} HTTP/1.1\r\nhost: localhost\r\n{auth}connection: close\r\n\r\n");
    tls.write_all(req.as_bytes()).await.unwrap();
    let mut buf = Vec::new();
    let _ = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        tls.read_to_end(&mut buf),
    )
    .await
    .expect("proxy answered");
    let text = String::from_utf8_lossy(&buf).into_owned();
    let (status, rest) = text.split_once("\r\n").unwrap_or((&text, ""));
    (status.to_string(), rest.to_string())
}

#[tokio::test]
async fn dot_segment_variants_are_rejected_and_legit_paths_pass() {
    let h = Harness::new(0).await;
    let token = mint_jwt("tenant-a", 3600, "read");

    for p in [
        "/svc-a/..%2fx",
        "/svc-a/..%2Fx",
        "/svc-a/..%5cx",
        "/svc-a/..\\x",
        "/svc-a/..;/x",
        "/svc-a/.;x/y",
        "/svc-a/%252e%252e/x",
        "/svc-a/%252fx",
        "/svc-a/%255cx",
        "/svc-a/%00",
        "/svc-a/%u002e",
    ] {
        let (status, _) = raw_get(&h, p, Some(&token)).await;
        assert!(status.contains(" 400"), "{p}: {status}");
        // auth runs first
        let (status, _) = raw_get(&h, p, None).await;
        assert!(status.contains(" 401"), "{p} without token: {status}");
    }

    for p in [
        "/svc-a/group%2Fproject",
        "/svc-a/.hidden",
        "/svc-a/a..b",
        "/svc-a/x;jsessionid=1",
    ] {
        let (status, rest) = raw_get(&h, p, Some(&token)).await;
        assert!(status.contains(" 200"), "{p}: {status}");
        let want = format!("x-echo-path: {p}\r\n");
        assert!(rest.contains(&want), "{p}: {rest}");
    }
}

/// A client that completes the mTLS handshake and then sends nothing must
/// not hold the connection open forever (10s first-request timeout).
#[tokio::test]
async fn silent_client_is_disconnected() {
    use tokio::io::AsyncReadExt;

    let h = Harness::new(0).await;
    let mut tls = tls_connect(h.proxy_addr, &h.certs).await;
    let started = std::time::Instant::now();
    let mut buf = [0u8; 64];
    let n = tokio::time::timeout(std::time::Duration::from_secs(20), tls.read(&mut buf))
        .await
        .expect("server closed the idle connection")
        .unwrap_or(0);
    assert_eq!(n, 0, "expected EOF");
    assert!(started.elapsed() >= std::time::Duration::from_secs(9));
}

#[tokio::test]
async fn upstream_down_trips_the_breaker() {
    let h = Harness::new(0).await;
    let client = h.client();
    let token = mint_jwt("tenant-a", 3600, "read");

    let resp1 = client
        .get(h.url("/down/anything"))
        .header("authorization", format!("Bearer {token}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp1.status(), 502);

    let resp2 = client
        .get(h.url("/down/anything"))
        .header("authorization", format!("Bearer {token}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp2.status(), 503);
}

// ----- (h) TLS hot reload ----------------------------------------------------

#[tokio::test]
async fn tls_hot_reload_swaps_the_cert() {
    let h = Harness::new(0).await;

    let before = fetch_peer_leaf_der(h.proxy_addr, &h.certs).await;
    h.certs.rotate_server_leaf();
    h.tls.reload().unwrap();
    let after = fetch_peer_leaf_der(h.proxy_addr, &h.certs).await;

    assert_ne!(before, after);
}
