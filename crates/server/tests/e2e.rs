//! End-to-end test: real TLS handshake, real mTLS + JWT + rate-limit
//! middleware, real upstream over HTTP/1 and HTTP/2.
//!
//! Certs are generated in-process with `rcgen` (CA -> server leaf, CA ->
//! trusted client leaf, a second untrusted CA -> client leaf) and written to
//! a tempdir so `ReloadingTls` can load them from disk like it would in
//! production. JWTs are signed with the same RSA fixture keypair
//! `ferryman-edge-core`'s own tests use.

use ferryman_edge::{reload, serve_with, AppState, UpstreamClient};
use ferryman_edge_core::ferryman_core::{
    build_table, health_loop, CircuitState, ConfigToml, RouteTable, SharedTable,
};
use ferryman_edge_core::{build_limiter, Claims, JwtVerifier, Limits, ReloadingTls};
use http::{Request, Response};
use http_body_util::channel::Channel;
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
use std::time::Duration;
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

const JWT_OTHER_PRIV_PEM: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../core/tests/fixtures/jwt-test-other-priv.pem"
));
const JWT_OTHER_PUB_PEM: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../core/tests/fixtures/jwt-test-other-pub.pem"
));

fn install_crypto_provider() {
    // rustls needs a process-wide default provider; installing more than
    // once is a no-op error we don't care about.
    let _ = rustls::crypto::ring::default_provider().install_default();
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
    mint_jwt_with(JWT_PRIV_PEM, sub, ttl_secs, scope)
}

fn mint_jwt_with(key_pem: &[u8], sub: &str, ttl_secs: i64, scope: &str) -> String {
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
        &EncodingKey::from_rsa_pem(key_pem).unwrap(),
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
    if req.uri().path() == "/missing" {
        return Ok(Response::builder()
            .status(404)
            .body(Full::new(Bytes::new()))
            .unwrap());
    }
    if req.uri().path().ends_with("/fail") {
        return Ok(Response::builder()
            .status(502)
            .body(Full::new(Bytes::new()))
            .unwrap());
    }
    if req.uri().path().starts_with("/svc-a/count") {
        // Counts the body frame by frame, so a large upload never sits in memory.
        let mut body = req.into_body();
        let mut n = 0usize;
        while let Some(frame) = body.frame().await {
            let Ok(frame) = frame else { break };
            if let Ok(data) = frame.into_data() {
                n += data.len();
            }
        }
        return Ok(Response::new(Full::new(Bytes::from(n.to_string()))));
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
    let xfh = req
        .headers()
        .get("x-forwarded-host")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let xff = req
        .headers()
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let names = req
        .headers()
        .keys()
        .map(|n| n.as_str())
        .collect::<Vec<_>>()
        .join(",");
    if path.starts_with("/slow") || path.starts_with("/flaky/slow") {
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    }
    let body = req.into_body().collect().await.unwrap().to_bytes();
    Ok(Response::builder()
        .header("x-echo-xff", xff)
        .status(200)
        .header("x-upstream", "yes")
        .header("x-echo-method", method)
        .header("x-echo-path", path)
        .header("x-echo-tenant", tenant)
        .header("x-echo-host", host)
        .header("x-echo-xfh", xfh)
        .header("x-echo-names", names)
        .body(Full::new(body))
        .unwrap())
}

/// Streams `data: 0` .. `data: 5`, 500 ms apart (about 2.5 s), like a slow
/// SSE/LLM response. Stops when the reader goes away.
async fn sse_handler(_req: Request<Incoming>) -> Result<Response<Channel<Bytes>>, Infallible> {
    let (mut tx, body) = Channel::<Bytes>::new(1);
    tokio::spawn(async move {
        for i in 0..6 {
            if i > 0 {
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
            if tx
                .send_data(Bytes::from(format!("data: {i}\n\n")))
                .await
                .is_err()
            {
                return;
            }
        }
    });
    Ok(Response::builder()
        .header("content-type", "text/event-stream")
        .body(body)
        .unwrap())
}

async fn spawn_sse_upstream() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                continue;
            };
            tokio::spawn(async move {
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service_fn(sse_handler))
                    .await;
            });
        }
    });
    addr
}

/// Answers 200 with a chunked body, then closes without the terminating
/// chunk: a body error after a healthy head.
async fn spawn_truncating_upstream() -> SocketAddr {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                continue;
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                let _ = stream.read(&mut buf).await;
                let _ = stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n5\r\nhello\r\n",
                    )
                    .await;
                let _ = stream.shutdown().await;
            });
        }
    });
    addr
}

/// Sends the 200 head at once, then echoes the request body back as it
/// arrives (full duplex). An error on the request body is passed on.
async fn early_handler(req: Request<Incoming>) -> Result<Response<Channel<Bytes>>, Infallible> {
    let (mut tx, body) = Channel::<Bytes>::new(1);
    tokio::spawn(async move {
        let mut inb = req.into_body();
        while let Some(frame) = inb.frame().await {
            let Ok(frame) = frame else { return };
            if let Ok(data) = frame.into_data() {
                if tx.send_data(data).await.is_err() {
                    return;
                }
            }
        }
    });
    Ok(Response::new(body))
}

async fn spawn_early_upstream() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                continue;
            };
            tokio::spawn(async move {
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service_fn(early_handler))
                    .await;
            });
        }
    });
    addr
}

/// Reads a request head; answers a GET with an empty 200 and `connection:
/// close`. Returns the head text and any body bytes read with it, or `None`
/// once a GET has been answered.
async fn raw_head(stream: &mut tokio::net::TcpStream) -> Option<(String, Vec<u8>)> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut head = Vec::new();
    let mut buf = [0u8; 1024];
    let end = loop {
        if let Some(i) = head.windows(4).position(|w| w == b"\r\n\r\n") {
            break i + 4;
        }
        match stream.read(&mut buf).await {
            Ok(0) | Err(_) => return None,
            Ok(n) => head.extend_from_slice(&buf[..n]),
        }
    };
    let text = String::from_utf8_lossy(&head[..end]).into_owned();
    if text.starts_with("GET ") && !text.contains(" /wt/big") {
        let _ = stream
            .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\nconnection: close\r\n\r\n")
            .await;
        return None;
    }
    Some((text, head[end..].to_vec()))
}

/// Reads about 2 KB of a request body, then dies without answering (an
/// unhealthy upstream, whatever the client is doing).
async fn spawn_dying_upstream() -> SocketAddr {
    use tokio::io::AsyncReadExt;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                continue;
            };
            tokio::spawn(async move {
                let Some((_, body)) = raw_head(&mut stream).await else {
                    return;
                };
                let mut got = body.len();
                let mut buf = [0u8; 512];
                while got < 2048 {
                    match stream.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => got += n,
                    }
                }
                // Dropped with the rest of the upload unread: a reset.
            });
        }
    });
    addr
}

/// `GET /wt/big` streams a 64 MiB body under a 1 s per-write timeout (like Go's
/// `WriteTimeout` or nginx's `send_timeout`): a reader that pauses makes it
/// hang up mid-body.
async fn spawn_write_timeout_upstream() -> SocketAddr {
    use tokio::io::AsyncWriteExt;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                continue;
            };
            tokio::spawn(async move {
                if raw_head(&mut stream).await.is_none() {
                    return;
                }
                let head = b"HTTP/1.1 200 OK\r\ncontent-length: 67108864\r\n\r\n";
                if stream.write_all(head).await.is_err() {
                    return;
                }
                let chunk = vec![b'x'; 64 * 1024];
                for _ in 0..1024 {
                    let w = tokio::time::timeout(Duration::from_secs(1), stream.write_all(&chunk));
                    if !matches!(w.await, Ok(Ok(()))) {
                        return;
                    }
                }
            });
        }
    });
    addr
}

/// An upstream with a strict read timeout: it closes the connection if no
/// body bytes arrive for 1.5 s (above the proxy's 1 s stall threshold).
/// `/strict-b` sends its 200 head first, `/strict-a` does not, and
/// `/strict-g` is a gateway: it answers 502 when its (simulated) backend
/// gives up; `/strict-t` does the same with a truncated body. A GET (no
/// body) is answered normally.
async fn spawn_strict_read_upstream() -> SocketAddr {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                continue;
            };
            tokio::spawn(async move {
                let mut head = Vec::new();
                let mut buf = [0u8; 1024];
                while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                    match stream.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => head.extend_from_slice(&buf[..n]),
                    }
                }
                let text = String::from_utf8_lossy(&head).into_owned();
                if text.starts_with("GET ") {
                    let _ = stream
                        .write_all(
                            b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
                        )
                        .await;
                    return;
                }
                if text.contains(" /strict-b") {
                    let _ = stream
                        .write_all(b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n")
                        .await;
                }
                while let Ok(Ok(n)) =
                    tokio::time::timeout(Duration::from_millis(1500), stream.read(&mut buf)).await
                {
                    if n == 0 {
                        break;
                    }
                }
                if text.contains(" /strict-g") {
                    let _ = stream
                        .write_all(
                            b"HTTP/1.1 502 Bad Gateway\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
                        )
                        .await;
                }
                if text.contains(" /strict-t") {
                    // A 502 whose body is cut off (no terminating chunk).
                    let _ = stream
                        .write_all(
                            b"HTTP/1.1 502 Bad Gateway\r\ntransfer-encoding: chunked\r\n\r\n5\r\nhello\r\n",
                        )
                        .await;
                }
                // Dropping the stream closes it without a (further) answer.
            });
        }
    });
    addr
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

/// A port nobody listens on, reserved for as long as the returned socket
/// lives: it is bound but never `listen()`s, so connects are refused and no
/// parallel test can be handed the port. Each call gives a distinct port
/// (core gives each `host:port` one breaker, and routes on one `host:port`
/// must agree on the cooldown).
fn dead_port() -> (SocketAddr, tokio::net::TcpSocket) {
    let s = tokio::net::TcpSocket::new_v4().unwrap();
    s.bind("127.0.0.1:0".parse().unwrap()).unwrap();
    (s.local_addr().unwrap(), s)
}

// ----- proxy harness -------------------------------------------------------

struct Harness {
    certs: TestCerts,
    upstream_addr: SocketAddr,
    proxy_addr: SocketAddr,
    tls: Arc<ReloadingTls>,
    jwt: Arc<JwtVerifier>,
    table: SharedTable,
    /// Keeps the `/probe` and `/down` ports reserved (see `dead_port`).
    _dead: [tokio::net::TcpSocket; 2],
}

/// Harness settings. `failure_threshold` defaults to core's 3; the blame
/// tests use 1, so a single wrongly blamed failure opens the circuit and
/// shows up as a 503.
struct Opts {
    tenant_rps: u32,
    limits: Limits,
    failure_threshold: u32,
    /// Extra `[[routes]]` TOML appended to the standard set.
    extra_routes: String,
}

impl Default for Opts {
    fn default() -> Self {
        Self {
            tenant_rps: 0,
            limits: Limits::default(),
            failure_threshold: 3,
            extra_routes: String::new(),
        }
    }
}

/// One breaker failure opens the circuit (see [`Opts`]).
fn strict() -> Opts {
    Opts {
        failure_threshold: 1,
        ..Opts::default()
    }
}

impl Harness {
    async fn new(tenant_rps: u32) -> Self {
        Self::build(
            Opts {
                tenant_rps,
                ..Opts::default()
            },
            |t| t,
        )
        .await
    }

    /// Threshold 1: these callers check that a client-side failure leaves
    /// the breaker closed.
    async fn with_limits(tenant_rps: u32, limits: Limits) -> Self {
        Self::build(
            Opts {
                tenant_rps,
                limits,
                failure_threshold: 1,
                ..Opts::default()
            },
            |t| t,
        )
        .await
    }

    /// `tune` adjusts the routing table (its timeouts) before serving.
    async fn build(opts: Opts, tune: impl FnOnce(RouteTable) -> RouteTable) -> Self {
        install_crypto_provider();
        let certs = TestCerts::generate();
        let upstream_addr = spawn_upstream().await;
        let flaky_addr = spawn_upstream().await;
        let burst_addr = spawn_upstream().await;
        let sse_addr = spawn_sse_upstream().await;
        let trunc_addr = spawn_truncating_upstream().await;
        let early_addr = spawn_early_upstream().await;
        let strict_addr = spawn_strict_read_upstream().await;
        let dying_addr = spawn_dying_upstream().await;
        let wt_addr = spawn_write_timeout_upstream().await;
        let (probe_addr, probe_sock) = dead_port();
        let (down_addr, down_sock) = dead_port();

        let tls = ReloadingTls::new(
            certs.server_cert_path.to_str().unwrap(),
            certs.server_key_path.to_str().unwrap(),
            certs.ca_bundle_path.to_str().unwrap(),
        )
        .unwrap();
        let jwt = Arc::new(JwtVerifier::new(JWT_PUB_PEM).unwrap());
        let limiter = build_limiter(opts.tenant_rps);

        let mut core = format!("failure_threshold = {}\n", opts.failure_threshold);
        for (prefix, addr, extra) in [
            ("/svc-a", upstream_addr, ""),
            ("/slow", upstream_addr, ""),
            ("/rewrite", upstream_addr, "rewrite_host = true"),
            ("/sse", sse_addr, ""),
            ("/trunc", trunc_addr, ""),
            ("/early", early_addr, ""),
            ("/strict-a", strict_addr, ""),
            ("/strict-b", strict_addr, ""),
            ("/strict-g", strict_addr, ""),
            ("/strict-t", strict_addr, ""),
            ("/dies", dying_addr, ""),
            ("/wt", wt_addr, ""),
            (
                "/flaky",
                flaky_addr,
                "cooldown_secs = 1\nhealth_path = \"/missing\"",
            ),
            ("/burst", burst_addr, "cooldown_secs = 3"),
            ("/probe", probe_addr, "cooldown_secs = 1"),
            ("/down", down_addr, ""),
        ] {
            core += &format!(
                "[[routes]]\nprefix = \"{prefix}\"\nupstream = \"http://{addr}\"\n{extra}\n"
            );
        }
        core += &opts
            .extra_routes
            .replace("UPSTREAM", &format!("http://{upstream_addr}"));
        let cfg = ConfigToml::from_table(core.parse::<toml::Table>().unwrap()).unwrap();
        let table = reload::new_shared(tune(build_table(cfg, None).unwrap()));

        let client: UpstreamClient =
            Client::builder(TokioExecutor::new()).build(HttpConnector::new());

        let state = Arc::new(AppState {
            tls: tls.clone(),
            table: table.clone(),
            jwt: jwt.clone(),
            limiter,
            client,
        });

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = listener.local_addr().unwrap();
        tokio::spawn(serve_with(
            listener,
            state,
            opts.limits,
            std::future::pending(),
        ));

        Self {
            certs,
            upstream_addr,
            proxy_addr,
            tls,
            jwt,
            table,
            _dead: [probe_sock, down_sock],
        }
    }

    /// Breaker state of the upstream behind `prefix`.
    fn circuit(&self, prefix: &str) -> CircuitState {
        self.table.load().lookup(prefix).unwrap().upstream.state()
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
        rustls::crypto::ring::default_provider()
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
        format!("127.0.0.1:{}", h.proxy_addr.port()),
        "the upstream sees the host the client used"
    );
    assert_eq!(resp.text().await.unwrap(), "hello body");
}

/// HTTP/1 `Host` reaches the upstream unchanged (E1), and a client cannot
/// inject its own `x-forwarded-host`.
#[tokio::test]
async fn client_host_is_preserved_and_forwarded_host_is_not_spoofable() {
    let h = Harness::new(0).await;
    let token = mint_jwt("tenant-a", 3600, "read");
    let (s, rest) = raw_get_with(
        &h,
        "/svc-a/host",
        Some(&token),
        "x-forwarded-host: evil.example\r\n",
    )
    .await;
    assert!(s.contains(" 200"), "{s}");
    let rest = rest.to_ascii_lowercase();
    assert!(rest.contains("x-echo-host: localhost\r\n"), "{rest}");
    assert!(rest.contains("x-echo-xfh: localhost\r\n"), "{rest}");
}

/// HTTP/2 has no Host header: `:authority` becomes the upstream's Host.
#[tokio::test]
async fn h2_authority_becomes_the_upstream_host() {
    let h = Harness::new(0).await;
    let token = mint_jwt("tenant-a", 3600, "read");
    let resp = h
        .client()
        .get(h.url("/svc-a/h2"))
        .header("authorization", format!("Bearer {token}"))
        .header("X-Forwarded-Host", "evil.example")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.version(), reqwest::Version::HTTP_2);
    let want = format!("127.0.0.1:{}", h.proxy_addr.port());
    let get = |n: &str| resp.headers().get(n).unwrap().to_str().unwrap().to_string();
    assert_eq!(get("x-echo-host"), want);
    assert_eq!(get("x-echo-xfh"), want);
}

/// Duplicate and mixed-case `x-forwarded-host` headers are all replaced by
/// one value; an absolute-form target's authority beats the `Host` header;
/// `Connection: host` cannot delete the Host.
#[tokio::test]
async fn forwarded_host_variants_and_absolute_form() {
    let h = Harness::new(0).await;
    let token = mint_jwt("tenant-a", 3600, "read");
    let (s, rest) = raw_get_with(
        &h,
        "/svc-a/x",
        Some(&token),
        "X-Forwarded-Host: e1.example\r\nx-forwarded-host: e2.example\r\nconnection: host\r\n",
    )
    .await;
    assert!(s.contains(" 200"), "{s}");
    let rest = rest.to_ascii_lowercase();
    assert!(rest.contains("x-echo-xfh: localhost\r\n"), "{rest}");
    assert!(rest.contains("x-echo-host: localhost\r\n"), "{rest}");
    assert!(
        !rest.contains("evil") && !rest.contains("e1.example"),
        "{rest}"
    );

    let (s, rest) = raw_get(&h, "http://other.example/svc-a/x", Some(&token)).await;
    assert!(s.contains(" 200"), "{s}");
    let rest = rest.to_ascii_lowercase();
    assert!(rest.contains("x-echo-host: other.example\r\n"), "{rest}");
    assert!(rest.contains("x-echo-xfh: other.example\r\n"), "{rest}");
}

/// A malformed or repeated `Host` is a 400 before routing.
#[tokio::test]
async fn bad_host_headers_are_rejected_and_good_ones_pass() {
    let h = Harness::new(0).await;
    let token = mint_jwt("tenant-a", 3600, "read");
    for bad in ["a.example, b.example", "u@x", "x/y", "x:99999", "a:b", "*"] {
        let (s, rest) = raw_host(&h, &token, &[bad]).await;
        assert!(s.contains(" 400"), "{bad}: {s}");
        assert!(rest.contains("bad host"), "{bad}: {rest}");
    }
    let (s, _) = raw_host(&h, &token, &["a.example", "b.example"]).await;
    assert!(s.contains(" 400"), "{s}");
    for ok in ["a.example", "a.example:8443", "[::1]:8443", "UPPER.Example"] {
        let (s, rest) = raw_host(&h, &token, &[ok]).await;
        assert!(s.contains(" 200"), "{ok}: {s}");
        let want = format!("x-echo-host: {}\r\n", ok.to_ascii_lowercase());
        assert!(rest.to_ascii_lowercase().contains(&want), "{ok}: {rest}");
    }
}

async fn raw_host(h: &Harness, token: &str, hosts: &[&str]) -> (String, String) {
    raw_host_ver(h, token, "1.1", hosts).await
}

async fn raw_host_ver(h: &Harness, token: &str, ver: &str, hosts: &[&str]) -> (String, String) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut tls = tls_connect(h.proxy_addr, &h.certs).await;
    let hs: String = hosts.iter().map(|v| format!("host: {v}\r\n")).collect();
    let req = format!(
        "GET /svc-a/x HTTP/{ver}\r\n{hs}authorization: Bearer {token}\r\nconnection: close\r\n\r\n"
    );
    tls.write_all(req.as_bytes()).await.unwrap();
    let mut buf = Vec::new();
    let _ = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        tls.read_to_end(&mut buf),
    )
    .await;
    let text = String::from_utf8_lossy(&buf).into_owned();
    let (s, rest) = text.split_once("\r\n").unwrap_or((&text, ""));
    (s.to_string(), rest.to_string())
}

/// `rewrite_host = true` restores the 0.1.x behaviour for that route only.
#[tokio::test]
async fn rewrite_host_route_sends_the_upstream_authority() {
    let h = Harness::new(0).await;
    let token = mint_jwt("tenant-a", 3600, "read");
    let (s, rest) = raw_get(&h, "/rewrite/x", Some(&token)).await;
    assert!(s.contains(" 200"), "{s}");
    let rest = rest.to_ascii_lowercase();
    assert!(
        rest.contains(&format!("x-echo-host: {}\r\n", h.upstream_addr)),
        "{rest}"
    );
    assert!(rest.contains("x-echo-xfh: localhost\r\n"), "{rest}");
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
async fn unknown_route_is_404_and_bodies_pass_whole() {
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
        .body(big.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(resp_big.status(), 200, "no cap by default");
    assert_eq!(resp_big.bytes().await.unwrap().len(), big.len());
}

// ----- (g) upstream down: breaker trips -------------------------------------

/// An oversized chunked upload (no Content-Length, so no precheck) must be
/// a client-side 413 and must NOT open the route's breaker — otherwise any
/// tenant could take a route down for everyone.
#[tokio::test]
async fn oversized_chunked_upload_is_413_and_does_not_trip_breaker() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut limits = Limits::default();
    limits.max_request_body_bytes = Some(8 * 1024 * 1024);
    let h = Harness::with_limits(0, limits).await;
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
    raw_get_with(h, path, token, "").await
}

/// `raw_get` plus extra header lines (each ending in `\r\n`).
async fn raw_get_with(
    h: &Harness,
    path: &str,
    token: Option<&str>,
    extra: &str,
) -> (String, String) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut tls = tls_connect(h.proxy_addr, &h.certs).await;
    let auth = token
        .map(|t| format!("authorization: Bearer {t}\r\n"))
        .unwrap_or_default();
    let req =
        format!("GET {path} HTTP/1.1\r\nhost: localhost\r\n{auth}{extra}connection: close\r\n\r\n");
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
        let (status, rest) = raw_get(&h, p, Some(&token)).await;
        assert!(status.contains(" 400"), "{p}: {status}");
        assert!(rest.ends_with("bad path"), "{p}: {rest}");
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

/// A 400 bad path must not consume the half-open probe slot: the bad-path
/// check runs before `Upstream::try_acquire`. If it ran after, the 400 request
/// would take the probe and the next normal request would see 503, not 502.
#[tokio::test]
async fn bad_path_does_not_consume_half_open_probe() {
    let h = Harness::new(0).await;
    let token = mint_jwt("tenant-a", 3600, "read");
    for _ in 0..3 {
        let (s, _) = raw_get(&h, "/probe/x", Some(&token)).await;
        assert!(s.contains(" 502"), "{s}");
    } // the third failure opens the breaker
    tokio::time::sleep(std::time::Duration::from_millis(1200)).await; // cooldown (1s) elapsed
    let (s, rest) = raw_get(&h, "/probe/..%2fx", Some(&token)).await;
    assert!(
        s.contains(" 400") && rest.ends_with("bad path"),
        "{s} {rest}"
    );
    let (s, _) = raw_get(&h, "/probe/x", Some(&token)).await;
    assert!(s.contains(" 502"), "probe slot was consumed: {s}");
}

const WS: &str = "upgrade: websocket\r\nconnection: upgrade\r\n";

/// Upgrade requests get 501 (the proxy cannot splice them) and never reach
/// the upstream; `Upgrade: h2c` is exempt and proxied normally. 501 comes
/// before route lookup, so an unrouted path gets it too.
#[tokio::test]
async fn upgrade_requests_get_501_but_h2c_is_proxied() {
    let h = Harness::new(0).await;
    let token = mint_jwt("tenant-a", 3600, "read");

    let (s, rest) = raw_get_with(&h, "/svc-a/ws", Some(&token), WS).await;
    assert!(s.contains(" 501"), "{s}");
    assert!(
        rest.ends_with("protocol upgrades are not supported"),
        "{rest}"
    );
    assert!(!rest.to_ascii_lowercase().contains("x-upstream"), "{rest}");

    let (s, _) = raw_get_with(&h, "/nowhere", Some(&token), WS).await;
    assert!(s.contains(" 501"), "{s}");

    let (s, rest) = raw_get_with(
        &h,
        "/svc-a/hello",
        Some(&token),
        "upgrade: H2C\r\nconnection: upgrade, http2-settings\r\n",
    )
    .await;
    assert!(s.contains(" 200"), "{s}");
    assert!(
        rest.to_ascii_lowercase().contains("x-upstream: yes"),
        "{rest}"
    );
}

/// Like the bad-path test: a 501 must not take the half-open probe slot.
#[tokio::test]
async fn upgrade_does_not_consume_half_open_probe() {
    let h = Harness::new(0).await;
    let token = mint_jwt("tenant-a", 3600, "read");
    for _ in 0..3 {
        let (s, _) = raw_get(&h, "/probe/x", Some(&token)).await;
        assert!(s.contains(" 502"), "{s}");
    } // the third failure opens the breaker
    tokio::time::sleep(std::time::Duration::from_millis(1200)).await; // cooldown (1s) elapsed
    let (s, _) = raw_get_with(&h, "/probe/x", Some(&token), WS).await;
    assert!(s.contains(" 501"), "{s}");
    let (s, _) = raw_get(&h, "/probe/x", Some(&token)).await;
    assert!(s.contains(" 502"), "probe slot was consumed: {s}");
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

// ----- JWT key reload ----------------------------------------------------------

#[tokio::test]
async fn jwt_key_reload_rotates_the_accepted_key() {
    let h = Harness::new(0).await;
    let client = h.client();
    let old = mint_jwt("tenant-a", 3600, "read");
    let new = mint_jwt_with(JWT_OTHER_PRIV_PEM, "tenant-a", 3600, "read");
    let status = |t: String| {
        let req = client
            .get(h.url("/svc-a/hello"))
            .header("authorization", format!("Bearer {t}"));
        async move { req.send().await.unwrap().status() }
    };

    assert_eq!(status(old.clone()).await, 200); // cached under the old key
    assert_eq!(status(new.clone()).await, 401);

    h.jwt.reload_key(JWT_OTHER_PUB_PEM).unwrap();
    assert_eq!(status(old.clone()).await, 401);
    assert_eq!(status(new.clone()).await, 200);

    assert!(h.jwt.reload_key(b"not a pem").is_err());
    assert_eq!(status(new).await, 200);
    assert_eq!(status(old).await, 401);
}

// ----- configurable [limits] -------------------------------------------------

#[tokio::test]
async fn configured_body_cap_is_enforced() {
    let mut limits = Limits::default();
    limits.max_request_body_bytes = Some(1024);
    let h = Harness::with_limits(0, limits).await;
    let client = h.client();
    let token = mint_jwt("tenant-a", 3600, "read");
    let post = |n: usize| {
        client
            .post(h.url("/svc-a/echo"))
            .header("authorization", format!("Bearer {token}"))
            .body(vec![b'z'; n])
            .send()
    };
    assert_eq!(post(1024).await.unwrap().status(), 200);
    assert_eq!(post(2048).await.unwrap().status(), 413);
}

#[tokio::test]
async fn configured_upstream_timeout_gives_504() {
    let h = Harness::build(strict(), |mut t| {
        t.upstream_timeout = Duration::from_secs(1);
        t
    })
    .await;
    let token = mint_jwt("tenant-a", 3600, "read");
    let resp = h
        .client()
        .get(h.url("/slow/x"))
        .header("authorization", format!("Bearer {token}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 504);
}

#[tokio::test]
async fn configured_first_request_timeout_closes_silent_client() {
    use tokio::io::AsyncReadExt;

    let mut limits = Limits::default();
    limits.first_request_timeout_secs = 1;
    let h = Harness::with_limits(0, limits).await;
    let mut tls = tls_connect(h.proxy_addr, &h.certs).await;
    let started = std::time::Instant::now();
    let mut buf = [0u8; 64];
    let n = tokio::time::timeout(std::time::Duration::from_secs(5), tls.read(&mut buf))
        .await
        .expect("server closed the idle connection")
        .unwrap_or(0);
    assert_eq!(n, 0, "expected EOF");
    assert!(started.elapsed() < std::time::Duration::from_secs(4));
}

#[tokio::test]
async fn huge_keepalive_timeout_does_not_panic_h1_connections() {
    // Library callers can pass unvalidated timeouts; hyper adds the header
    // read timeout to `now()` without overflow checks, so serve_with caps it.
    let h = Harness::build(strict(), |t| t.with_keepalive_timeout(Duration::MAX)).await;
    let token = mint_jwt("tenant-a", 3600, "read");
    let resp = h
        .client_http1_only()
        .get(h.url("/svc-a/hello"))
        .header("authorization", format!("Bearer {token}"))
        .send()
        .await
        .expect("h1 connection task survived");
    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn configured_cap_applies_to_chunked_uploads() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut limits = Limits::default();
    limits.max_request_body_bytes = Some(1024);
    let h = Harness::with_limits(0, limits).await;
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
        let chunk = vec![b'x'; 1024];
        let frame = format!("{:x}\r\n", chunk.len());
        for _ in 0..2 {
            // 2 KiB total, over the 1 KiB cap
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

/// tokio-rustls' default features used to switch on `tls12`; with
/// `default-features = false` it must be listed explicitly or TLS 1.2-only
/// clients (older JVMs, embedded stacks) stop handshaking.
#[tokio::test]
async fn tls12_clients_still_handshake() {
    let h = Harness::new(0).await;
    let client_certs: Vec<CertificateDer<'static>> =
        CertificateDer::pem_slice_iter(&h.certs.client_cert_pem)
            .collect::<Result<_, _>>()
            .unwrap();
    let client_key = PrivateKeyDer::from_pem_slice(&h.certs.client_key_pem).unwrap();
    let mut cfg = rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS12])
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyServerCert))
        .with_client_auth_cert(client_certs, client_key)
        .unwrap();
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    let tcp = tokio::net::TcpStream::connect(h.proxy_addr).await.unwrap();
    let tls = TlsConnector::from(Arc::new(cfg))
        .connect(ServerName::try_from("127.0.0.1").unwrap(), tcp)
        .await
        .expect("TLS 1.2 handshake");
    assert_eq!(
        tls.get_ref().1.protocol_version(),
        Some(rustls::ProtocolVersion::TLSv1_2)
    );
}

#[tokio::test]
async fn huge_first_request_timeout_does_not_panic_h1_connections() {
    let mut limits = Limits::default();
    limits.first_request_timeout_secs = u64::MAX;
    let h = Harness::with_limits(0, limits).await;
    let token = mint_jwt("tenant-a", 3600, "read");
    let resp = h
        .client_http1_only()
        .get(h.url("/svc-a/hello"))
        .header("authorization", format!("Bearer {token}"))
        .send()
        .await
        .expect("h1 connection task survived");
    assert_eq!(resp.status(), 200);
}

/// `keepalive_timeout_secs` (ferryman-core's name) closes an idle HTTP/1
/// keep-alive connection; 0.1.x tied this to `first_request_timeout_secs`.
#[tokio::test]
async fn keepalive_timeout_closes_idle_h1_connection() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let h = Harness::build(strict(), |t| {
        t.with_keepalive_timeout(Duration::from_secs(1))
    })
    .await;
    let token = mint_jwt("tenant-a", 3600, "read");
    let mut tls = tls_connect(h.proxy_addr, &h.certs).await;
    let req = format!(
        "GET /svc-a/ka HTTP/1.1\r\nhost: localhost\r\nauthorization: Bearer {token}\r\n\r\n"
    );
    tls.write_all(req.as_bytes()).await.unwrap();
    let mut got = Vec::new();
    let mut buf = [0u8; 4096];
    while !got.windows(4).any(|w| w == b"\r\n\r\n") {
        let n = tls.read(&mut buf).await.unwrap();
        assert!(n > 0, "closed before the response");
        got.extend_from_slice(&buf[..n]);
    }
    assert!(
        got.starts_with(b"HTTP/1.1 200"),
        "{}",
        String::from_utf8_lossy(&got)
    );
    let idle = std::time::Instant::now();
    let n = tokio::time::timeout(Duration::from_secs(5), tls.read(&mut buf))
        .await
        .expect("idle keep-alive connection closed within 5 s")
        .unwrap_or(0);
    assert_eq!(n, 0, "expected EOF");
    assert!(idle.elapsed() < Duration::from_secs(4));
}

/// The whole-upload deadline comes from the routing table
/// (`request_body_timeout_secs`).
#[tokio::test]
async fn configured_request_body_timeout_gives_408() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let h = Harness::build(strict(), |t| {
        t.with_request_body_timeout(Duration::from_secs(1))
    })
    .await;
    let token = mint_jwt("tenant-a", 3600, "read");
    let mut tls = tls_connect(h.proxy_addr, &h.certs).await;
    let req = format!(
        "POST /svc-a/slow-upload HTTP/1.1\r\nhost: localhost\r\n\
         authorization: Bearer {token}\r\ntransfer-encoding: chunked\r\n\r\n3\r\nabc\r\n"
    );
    tls.write_all(req.as_bytes()).await.unwrap();
    // ... and never finish the body.
    let mut buf = [0u8; 512];
    let n = tokio::time::timeout(Duration::from_secs(5), tls.read(&mut buf))
        .await
        .expect("408 within 5 s")
        .unwrap();
    let head = String::from_utf8_lossy(&buf[..n]);
    assert!(head.starts_with("HTTP/1.1 408"), "{head}");
    let resp = h
        .client()
        .get(h.url("/svc-a/after"))
        .header("authorization", format!("Bearer {token}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "breaker must stay closed");
}

/// A streamed response longer than `upstream_timeout` is neither cut nor
/// blamed on the upstream: the deadline ends at the response head.
#[tokio::test]
async fn sse_outlives_the_upstream_timeout_and_keeps_the_breaker_closed() {
    let h = Harness::build(strict(), |mut t| {
        t.upstream_timeout = Duration::from_secs(1);
        t
    })
    .await;
    let token = mint_jwt("tenant-a", 3600, "read");
    let get = |p: &str| {
        h.client()
            .get(h.url(p))
            .header("authorization", format!("Bearer {token}"))
            .send()
    };
    let started = std::time::Instant::now();
    let resp = get("/sse/events").await.unwrap();
    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();
    assert!(body.contains("data: 5"), "stream was cut: {body:?}");
    assert!(started.elapsed() >= Duration::from_millis(2400));
    assert_eq!(
        get("/sse/again").await.unwrap().status(),
        200,
        "breaker must stay closed"
    );
}

/// No body cap by default: a 50 MiB upload streams through whole (exit
/// criterion 8).
#[tokio::test]
async fn fifty_mib_upload_streams_with_no_default_cap() {
    let h = Harness::new(0).await;
    let token = mint_jwt("tenant-a", 3600, "read");
    let resp = h
        .client()
        .post(h.url("/svc-a/count"))
        .header("authorization", format!("Bearer {token}"))
        .body(vec![b'u'; 50 << 20])
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text().await.unwrap(), (50usize << 20).to_string());
}

/// A client that stalls its upload gets 408 from the body's own idle
/// deadline, and the breaker never hears about it.
#[tokio::test]
async fn stalled_upload_is_408_and_does_not_trip_the_breaker() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let h = Harness::build(strict(), |t| {
        t.with_request_body_idle_timeout(Duration::from_secs(1))
    })
    .await;
    let token = mint_jwt("tenant-a", 3600, "read");
    let mut tls = tls_connect(h.proxy_addr, &h.certs).await;
    let req = format!(
        "POST /svc-a/upload HTTP/1.1\r\nhost: localhost\r\nauthorization: Bearer {token}\r\n\
         transfer-encoding: chunked\r\n\r\n4\r\nabcd\r\n"
    );
    tls.write_all(req.as_bytes()).await.unwrap();
    let mut buf = vec![0u8; 256];
    let n = tokio::time::timeout(Duration::from_secs(5), tls.read(&mut buf))
        .await
        .expect("proxy answered the stalled upload")
        .unwrap();
    let line = String::from_utf8_lossy(&buf[..n]);
    assert!(line.starts_with("HTTP/1.1 408"), "{line}");
    let resp = h
        .client()
        .get(h.url("/svc-a/after"))
        .header("authorization", format!("Bearer {token}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "breaker must stay closed");
}

#[tokio::test]
async fn client_hanging_up_mid_upload_does_not_trip_the_breaker() {
    use tokio::io::AsyncWriteExt;

    let h = Harness::build(strict(), |t| t).await;
    let token = mint_jwt("tenant-a", 3600, "read");
    let mut tls = tls_connect(h.proxy_addr, &h.certs).await;
    let req = format!(
        "POST /svc-a/upload HTTP/1.1\r\nhost: localhost\r\nauthorization: Bearer {token}\r\n\
         transfer-encoding: chunked\r\n\r\n4\r\nabcd\r\n"
    );
    tls.write_all(req.as_bytes()).await.unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    drop(tls);
    tokio::time::sleep(Duration::from_millis(200)).await;
    let resp = h
        .client()
        .get(h.url("/svc-a/after"))
        .header("authorization", format!("Bearer {token}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "breaker must stay closed");
}

#[tokio::test]
async fn client_hanging_up_mid_stream_does_not_trip_the_breaker() {
    let h = Harness::build(strict(), |t| t).await;
    let token = mint_jwt("tenant-a", 3600, "read");
    let get = |p: &str| {
        h.client()
            .get(h.url(p))
            .header("authorization", format!("Bearer {token}"))
            .send()
    };
    let mut resp = get("/sse/x").await.unwrap();
    assert_eq!(resp.status(), 200);
    let first = resp.chunk().await.unwrap().expect("first event");
    assert!(first.starts_with(b"data: 0"), "{first:?}");
    drop(resp);
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        get("/sse/again").await.unwrap().status(),
        200,
        "breaker must stay closed"
    );
}

/// An upload slower than `upstream_timeout` is fine as long as the client
/// keeps sending (ROADMAP F4): the deadline starts at end-of-body.
#[tokio::test]
async fn upstream_timeout_starts_after_upload_regression() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let h = Harness::build(strict(), |mut t| {
        t.upstream_timeout = Duration::from_secs(1);
        t
    })
    .await;
    let token = mint_jwt("tenant-a", 3600, "read");
    let mut tls = tls_connect(h.proxy_addr, &h.certs).await;
    let head = format!(
        "POST /svc-a/count HTTP/1.1\r\nhost: localhost\r\nauthorization: Bearer {token}\r\n\
         transfer-encoding: chunked\r\nconnection: close\r\n\r\n"
    );
    tls.write_all(head.as_bytes()).await.unwrap();
    for _ in 0..4 {
        tls.write_all(b"4\r\nabcd\r\n").await.unwrap();
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    tls.write_all(b"0\r\n\r\n").await.unwrap();
    let mut out = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), tls.read_to_end(&mut out))
        .await
        .expect("answered")
        .unwrap();
    let text = String::from_utf8_lossy(&out);
    assert!(text.starts_with("HTTP/1.1 200"), "{text}");
    assert!(text.ends_with("16"), "{text}");
}

/// A body error after a healthy 200 head is the upstream's fault: the breaker
/// opens. (A slow or long body, or a client hang-up, never does.)
#[tokio::test]
async fn upstream_body_reset_after_200_head_trips_the_breaker() {
    let h = Harness::build(strict(), |t| t).await;
    let token = mint_jwt("tenant-a", 3600, "read");
    let get = |p: &str| {
        h.client()
            .get(h.url(p))
            .header("authorization", format!("Bearer {token}"))
            .send()
    };
    let resp = get("/trunc/a").await.unwrap();
    assert_eq!(resp.status(), 200);
    assert!(resp.bytes().await.is_err(), "body must error");
    assert_eq!(
        get("/trunc/b").await.unwrap().status(),
        503,
        "breaker must open"
    );
}

/// A client that keeps sending within the idle gap but past the total
/// deadline gets 408, and the breaker never hears about it.
#[tokio::test]
async fn trickling_upload_past_the_total_deadline_is_408_and_breaker_stays_closed() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let h = Harness::build(strict(), |t| {
        t.with_request_body_idle_timeout(Duration::from_secs(1))
            .with_request_body_timeout(Duration::from_secs(2))
    })
    .await;
    let token = mint_jwt("tenant-a", 3600, "read");
    let tls = tls_connect(h.proxy_addr, &h.certs).await;
    let (mut rd, mut wr) = tokio::io::split(tls);
    let head = format!(
        "POST /svc-a/upload HTTP/1.1\r\nhost: localhost\r\nauthorization: Bearer {token}\r\n\
         transfer-encoding: chunked\r\n\r\n"
    );
    // Keeps trickling well past the total deadline; the answer must come
    // from that deadline, not from the client running out of data.
    let writer = tokio::spawn(async move {
        wr.write_all(head.as_bytes()).await?;
        for _ in 0..30 {
            wr.write_all(b"1\r\nx\r\n").await?;
            tokio::time::sleep(Duration::from_millis(400)).await;
        }
        std::io::Result::Ok(())
    });
    let mut buf = [0u8; 256];
    let started = std::time::Instant::now();
    let n = tokio::time::timeout(Duration::from_secs(4), rd.read(&mut buf))
        .await
        .expect("answered by the total deadline")
        .unwrap();
    assert!(started.elapsed() >= Duration::from_millis(1500));
    writer.abort();
    let line = String::from_utf8_lossy(&buf[..n]);
    assert!(line.starts_with("HTTP/1.1 408"), "{line}");
    let resp = h
        .client()
        .get(h.url("/svc-a/after"))
        .header("authorization", format!("Bearer {token}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "breaker must stay closed");
}

/// The upstream answers 200 before the upload ends; the client then stalls
/// its upload. The error that reaches the response body is the client's, so
/// the breaker must stay closed.
#[tokio::test]
async fn client_stalling_after_an_early_upstream_answer_does_not_trip_the_breaker() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let h = Harness::build(strict(), |t| {
        t.with_request_body_idle_timeout(Duration::from_secs(1))
    })
    .await;
    let token = mint_jwt("tenant-a", 3600, "read");
    let mut tls = tls_connect(h.proxy_addr, &h.certs).await;
    let req = format!(
        "POST /early/x HTTP/1.1\r\nhost: localhost\r\nauthorization: Bearer {token}\r\n\
         transfer-encoding: chunked\r\n\r\n4\r\nabcd\r\n"
    );
    tls.write_all(req.as_bytes()).await.unwrap();
    let mut buf = vec![0u8; 512];
    let n = tokio::time::timeout(Duration::from_secs(5), tls.read(&mut buf))
        .await
        .expect("200 head")
        .unwrap();
    assert!(String::from_utf8_lossy(&buf[..n]).starts_with("HTTP/1.1 200"));
    // Stall past the idle gap, then let the proxy finish tearing down.
    tokio::time::sleep(Duration::from_millis(2000)).await;
    drop(tls);
    tokio::time::sleep(Duration::from_millis(200)).await;
    let resp = h
        .client()
        .get(h.url("/early/after"))
        .header("authorization", format!("Bearer {token}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "breaker must stay closed");
}

/// The client stalls its upload (inside the proxy's idle gap) for longer than
/// the upstream's own read timeout, so the upstream hangs up. That is the
/// client's stall, not an unhealthy upstream: the breaker must stay closed,
/// whether the upstream closes before its head or after an early one.
#[tokio::test]
async fn upstream_read_timeout_during_a_client_stall_does_not_trip_the_breaker() {
    use tokio::io::AsyncWriteExt;

    let h = Harness::build(strict(), |t| {
        t.with_request_body_idle_timeout(Duration::from_secs(5))
            .with_request_body_timeout(Duration::from_secs(30))
    })
    .await;
    let token = mint_jwt("tenant-a", 3600, "read");
    for route in ["/strict-a", "/strict-b"] {
        let mut tls = tls_connect(h.proxy_addr, &h.certs).await;
        let req = format!(
            "POST {route}/up HTTP/1.1\r\nhost: localhost\r\nauthorization: Bearer {token}\r\n\
             transfer-encoding: chunked\r\n\r\n4\r\nabcd\r\n"
        );
        tls.write_all(req.as_bytes()).await.unwrap();
        tokio::time::sleep(Duration::from_millis(2000)).await;
        drop(tls);
        tokio::time::sleep(Duration::from_millis(200)).await;
        let resp = h
            .client()
            .get(h.url(&format!("{route}/after")))
            .header("authorization", format!("Bearer {token}"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200, "{route}: breaker must stay closed");
    }
}

/// An upstream that dies mid-upload while the client is actively sending is
/// unhealthy: the breaker opens. The proxy is parked on the client between
/// chunks nearly all the time, so "waiting on the client" alone must not
/// excuse the upstream; only a stall of at least the threshold does.
#[tokio::test]
async fn upstream_dying_mid_upload_while_the_client_sends_trips_the_breaker() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let h = Harness::build(strict(), |t| t).await;
    let token = mint_jwt("tenant-a", 3600, "read");
    let tls = tls_connect(h.proxy_addr, &h.certs).await;
    let (mut rd, mut wr) = tokio::io::split(tls);
    let head = format!(
        "POST /dies/up HTTP/1.1\r\nhost: localhost\r\nauthorization: Bearer {token}\r\n\
         transfer-encoding: chunked\r\n\r\n"
    );
    let writer = tokio::spawn(async move {
        wr.write_all(head.as_bytes()).await?;
        let chunk = format!("100\r\n{}\r\n", "x".repeat(256));
        for _ in 0..400 {
            wr.write_all(chunk.as_bytes()).await?;
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        std::io::Result::Ok(())
    });
    let mut buf = [0u8; 256];
    let n = tokio::time::timeout(Duration::from_secs(5), rd.read(&mut buf))
        .await
        .expect("answered")
        .unwrap();
    writer.abort();
    let line = String::from_utf8_lossy(&buf[..n]);
    assert!(line.starts_with("HTTP/1.1 502"), "{line}");
    let resp = h
        .client()
        .get(h.url("/dies/after"))
        .header("authorization", format!("Bearer {token}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 503, "breaker must open");
}

/// A client that pauses reading a large response makes an upstream with a
/// write timeout hang up mid-body. That is the client's stall: the breaker
/// must stay closed.
#[tokio::test]
async fn upstream_write_timeout_during_a_paused_reader_does_not_trip_the_breaker() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let h = Harness::build(strict(), |t| t).await;
    let token = mint_jwt("tenant-a", 3600, "read");
    let mut tls = tls_connect(h.proxy_addr, &h.certs).await;
    let req = format!(
        "GET /wt/big HTTP/1.1\r\nhost: localhost\r\nauthorization: Bearer {token}\r\n\
         connection: close\r\n\r\n"
    );
    tls.write_all(req.as_bytes()).await.unwrap();
    let mut buf = vec![0u8; 64 * 1024];
    let mut got = 0;
    while got < 64 * 1024 {
        let n = tls.read(&mut buf).await.unwrap();
        assert!(n > 0, "response ended early");
        got += n;
    }
    tokio::time::sleep(Duration::from_secs(4)).await;
    let mut total = got;
    while let Ok(Ok(n)) = tokio::time::timeout(Duration::from_secs(5), tls.read(&mut buf)).await {
        if n == 0 {
            break;
        }
        total += n;
    }
    assert!(total < 64 << 20, "upstream must have hung up mid-body");
    let resp = h
        .client()
        .get(h.url("/wt/after"))
        .header("authorization", format!("Bearer {token}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "breaker must stay closed");
}

// ----- ferryman-core: threshold, normalised lookup, health, admission ------

/// Edge 0.1.x opened on the first failure; core's breaker needs three in a
/// row (one 502 used to blackhole a route for a whole cooldown).
#[tokio::test]
async fn breaker_opens_on_the_third_consecutive_failure() {
    let h = Harness::new(0).await;
    let token = mint_jwt("tenant-a", 3600, "read");
    for i in 1..=3 {
        let (s, _) = raw_get(&h, "/down/x", Some(&token)).await;
        assert!(s.contains(" 502"), "attempt {i}: {s}");
    }
    let (s, _) = raw_get(&h, "/down/x", Some(&token)).await;
    assert!(s.contains(" 503"), "{s}");
}

/// Matching uses core's normalised path; the upstream still receives the
/// bytes the client sent. An encoded separator that would pick a different
/// route under an upstream's reading is 400 (`ambiguous_route`).
#[tokio::test]
async fn routes_match_the_normalised_path_but_forward_it_raw() {
    let h = Harness::new(0).await;
    let token = mint_jwt("tenant-a", 3600, "read");
    for (p, want) in [
        ("/%73vc-a/x", 200),
        ("//svc-a/x", 200),
        ("/svc-a//x", 200),
        ("/SVC-A/x", 404),
        ("/svc-a%2fx", 400),
    ] {
        let (s, rest) = raw_get(&h, p, Some(&token)).await;
        assert!(s.contains(&format!(" {want}")), "{p}: {s}");
        if want == 200 {
            assert!(
                rest.contains(&format!("x-echo-path: {p}\r\n")),
                "{p} forwarded raw: {rest}"
            );
        }
    }
}

/// With a `/` catch-all next to `/api`, a path an upstream could read as
/// `/api/...` (encoded or back slash, `;params`) while the proxy routes it
/// to `/` is 400. It is checked right after `bad_path`, before Host and the
/// upgrade check. An encoded slash that does not change the route passes.
#[tokio::test]
async fn ambiguous_routes_are_rejected_before_host_and_upgrade_checks() {
    let h = Harness::build(
        Opts {
            extra_routes: "[[routes]]\nprefix = \"/\"\nupstream = \"UPSTREAM\"\n\
                           [[routes]]\nprefix = \"/api\"\nupstream = \"UPSTREAM\"\n"
                .into(),
            ..Opts::default()
        },
        |t| t,
    )
    .await;
    let token = mint_jwt("tenant-a", 3600, "read");
    for p in [
        "/api%2Fsecret",
        "/api%5Csecret",
        "/api\\secret",
        "/api;x/secret",
    ] {
        let (s, rest) = raw_get(&h, p, Some(&token)).await;
        assert!(
            s.contains(" 400") && rest.ends_with("bad path"),
            "{p}: {s} {rest}"
        );
        let (s, rest) = raw_get_with(&h, p, Some(&token), WS).await;
        assert!(rest.ends_with("bad path"), "{p} before 501: {s} {rest}");
        let (s, rest) = raw_host(&h, &token, &["a", "b"]).await;
        assert!(rest.ends_with("bad host"), "control: {s}");
    }
    // Ordering against Host: the ambiguous path wins over a duplicate Host.
    let (s, rest) = raw_get_with(&h, "/api%2Fsecret", Some(&token), "host: other\r\n").await;
    assert!(rest.ends_with("bad path"), "before Host: {s} {rest}");

    let p = "/api/v4/projects/group%2Fproject";
    let (s, rest) = raw_get(&h, p, Some(&token)).await;
    assert!(s.contains(" 200"), "{p}: {s}");
    assert!(rest.contains(&format!("x-echo-path: {p}\r\n")), "{rest}");
}

/// Core health semantics: any answer below 500 means the upstream is up.
#[tokio::test]
async fn health_probe_answering_404_keeps_the_route_up() {
    let h = Harness::new(0).await;
    let token = mint_jwt("tenant-a", 3600, "read");
    tokio::spawn(health_loop(h.table.clone(), Duration::from_millis(100)));
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(h.circuit("/flaky"), CircuitState::Closed);
    let (s, _) = raw_get(&h, "/flaky/ok", Some(&token)).await;
    assert!(s.contains(" 200"), "{s}");
}

/// Opens `/flaky` (three 502s) and waits out its 1 s cooldown.
async fn open_flaky_and_wait(h: &Harness, token: &str) {
    for _ in 0..3 {
        let (s, _) = raw_get(h, "/flaky/fail", Some(token)).await;
        assert!(s.contains(" 502"), "{s}");
    }
    let (s, _) = raw_get(h, "/flaky/ok", Some(token)).await;
    assert!(s.contains(" 503"), "open: {s}");
    tokio::time::sleep(Duration::from_millis(1200)).await;
}

/// The half-open probe is admitted, then its client hangs up mid-upload.
/// That says nothing about the upstream: the circuit must not close, and the
/// ticket is released, so the very next request can probe (no extra
/// cooldown). The route has no health loop to rescue it.
#[tokio::test]
async fn client_aborted_probe_does_not_close_the_breaker() {
    use tokio::io::AsyncWriteExt;

    let h = Harness::new(0).await;
    let token = mint_jwt("tenant-a", 3600, "read");
    open_flaky_and_wait(&h, &token).await;

    let mut tls = tls_connect(h.proxy_addr, &h.certs).await;
    let req = format!(
        "POST /flaky/ok HTTP/1.1\r\nhost: localhost\r\nauthorization: Bearer {token}\r\n\
         transfer-encoding: chunked\r\n\r\n4\r\nabcd\r\n"
    );
    tls.write_all(req.as_bytes()).await.unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        h.circuit("/flaky"),
        CircuitState::HalfOpen,
        "probe admitted"
    );
    drop(tls);
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_ne!(
        h.circuit("/flaky"),
        CircuitState::Closed,
        "an aborted probe must not close the circuit"
    );

    let (s, _) = raw_get(&h, "/flaky/ok", Some(&token)).await;
    assert!(
        s.contains(" 200"),
        "released probe slot is usable at once: {s}"
    );
    assert_eq!(h.circuit("/flaky"), CircuitState::Closed);
}

/// h2 variant: the probe waits on a slow upstream and the client resets the
/// stream. hyper drops the handler future; the ticket's drop releases it.
#[tokio::test]
async fn h2_reset_probe_is_released() {
    let h = Harness::new(0).await;
    let token = mint_jwt("tenant-a", 3600, "read");
    open_flaky_and_wait(&h, &token).await;

    let client = h.client();
    let err = client
        .get(h.url("/flaky/slow"))
        .header("authorization", format!("Bearer {token}"))
        .timeout(Duration::from_millis(300))
        .send()
        .await
        .expect_err("timed out: the stream is reset");
    assert!(err.is_timeout(), "{err}");
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(
        h.circuit("/flaky"),
        CircuitState::HalfOpen,
        "probe admitted"
    );

    let resp = client
        .get(h.url("/flaky/ok"))
        .header("authorization", format!("Bearer {token}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.version(), reqwest::Version::HTTP_2);
    assert_eq!(resp.status(), 200, "released probe slot is usable at once");
}

/// A burst of clients that take the half-open probe and abort re-arms the
/// slot at most once per cooldown: the following requests are refused, not
/// all turned into probes against the still-sick upstream.
#[tokio::test]
async fn aborted_probe_burst_rearms_at_most_once_per_cooldown() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let h = Harness::new(0).await;
    let token = mint_jwt("tenant-a", 3600, "read");
    for _ in 0..3 {
        let (s, _) = raw_get(&h, "/burst/fail", Some(&token)).await;
        assert!(s.contains(" 502"), "{s}");
    }
    tokio::time::sleep(Duration::from_millis(3100)).await; // cooldown 3 s

    // Everything below must happen within one cooldown of the first probe,
    // or the stale-probe rule legitimately hands out another one.
    let started = std::time::Instant::now();
    let mut admitted = 0;
    for _ in 0..20 {
        let mut tls = tls_connect(h.proxy_addr, &h.certs).await;
        let req = format!(
            "POST /burst/up HTTP/1.1\r\nhost: localhost\r\nauthorization: Bearer {token}\r\n\
             transfer-encoding: chunked\r\n\r\n4\r\nabcd\r\n"
        );
        tls.write_all(req.as_bytes()).await.unwrap();
        let mut buf = [0u8; 64];
        match tokio::time::timeout(Duration::from_millis(400), tls.read(&mut buf)).await {
            // Refused at once: 503.
            Ok(Ok(n)) => {
                let line = String::from_utf8_lossy(&buf[..n]);
                assert!(line.starts_with("HTTP/1.1 503"), "{line}");
            }
            // Forwarded and waiting on the upload: a probe. Abort it.
            _ => admitted += 1,
        }
        drop(tls);
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_ne!(h.circuit("/burst"), CircuitState::Closed);
    let (s, _) = raw_get(&h, "/burst/fail", Some(&token)).await;
    let elapsed = started.elapsed();
    assert!(
        elapsed < Duration::from_secs(3),
        "burst took {elapsed:?}, longer than the 3 s cooldown: inconclusive"
    );
    assert!(
        (1..=2).contains(&admitted),
        "the probe plus at most one re-arm, got {admitted}"
    );
    assert!(s.contains(" 503"), "no further probe this cooldown: {s}");
}

/// A gateway upstream whose backend gives up on a stalled upload answers
/// 502. The client stalled for at least θ, so the 502 is forwarded but not
/// blamed (ferryman does the same).
#[tokio::test]
async fn gateway_502_after_a_client_stall_does_not_trip_the_breaker() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let h = Harness::build(strict(), |t| {
        t.with_request_body_idle_timeout(Duration::from_secs(5))
    })
    .await;
    let token = mint_jwt("tenant-a", 3600, "read");
    let mut tls = tls_connect(h.proxy_addr, &h.certs).await;
    let req = format!(
        "POST /strict-g/up HTTP/1.1\r\nhost: localhost\r\nauthorization: Bearer {token}\r\n\
         transfer-encoding: chunked\r\n\r\n4\r\nabcd\r\n"
    );
    tls.write_all(req.as_bytes()).await.unwrap();
    let mut buf = [0u8; 256];
    let n = tokio::time::timeout(Duration::from_secs(5), tls.read(&mut buf))
        .await
        .expect("gateway answered")
        .unwrap();
    let line = String::from_utf8_lossy(&buf[..n]);
    assert!(line.starts_with("HTTP/1.1 502"), "{line}");
    drop(tls);
    let (s, _) = raw_get(&h, "/strict-g/after", Some(&token)).await;
    assert!(s.contains(" 200"), "breaker must stay closed: {s}");
}

/// The client stalls its upload for at least θ, then finishes it. The
/// gateway's backend gave up during the stall, so the gateway answers 502
/// only after the upload is complete: by then only the "stalled at some
/// point" record exempts it. `/strict-t` sends that 502 with a truncated
/// body, which the same record exempts on the response-body path.
#[tokio::test]
async fn gateway_502_after_a_finished_client_stall_does_not_trip_the_breaker() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let h = Harness::build(strict(), |t| {
        t.with_request_body_idle_timeout(Duration::from_secs(5))
    })
    .await;
    let token = mint_jwt("tenant-a", 3600, "read");
    for route in ["/strict-g", "/strict-t"] {
        let mut tls = tls_connect(h.proxy_addr, &h.certs).await;
        let req = format!(
            "POST {route}/up HTTP/1.1\r\nhost: localhost\r\nauthorization: Bearer {token}\r\n\
             transfer-encoding: chunked\r\nconnection: close\r\n\r\n4\r\nabcd\r\n"
        );
        tls.write_all(req.as_bytes()).await.unwrap();
        tokio::time::sleep(Duration::from_millis(1250)).await; // θ = 1 s
        tls.write_all(b"0\r\n\r\n").await.unwrap();
        // Read to the end, so the proxy polls (and fails) the whole body.
        let mut out = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(5), tls.read_to_end(&mut out)).await;
        let text = String::from_utf8_lossy(&out);
        assert!(text.starts_with("HTTP/1.1 502"), "{route}: {text}");
        drop(tls);
        let (s, _) = raw_get(&h, &format!("{route}/after"), Some(&token)).await;
        assert!(s.contains(" 200"), "{route}: breaker must stay closed: {s}");
    }
}

/// The client stalls for at least θ, then resumes sending; the upstream then
/// dies mid-upload. As in ferryman, a stall earlier in the request exempts
/// the upstream: released, not blamed. (An upstream dying under a client that
/// never paused is still blamed: see
/// `upstream_dying_mid_upload_while_the_client_sends_trips_the_breaker`.)
#[tokio::test]
async fn upstream_dying_after_an_earlier_client_stall_is_not_blamed() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let h = Harness::build(strict(), |t| {
        t.with_request_body_idle_timeout(Duration::from_secs(5))
    })
    .await;
    let token = mint_jwt("tenant-a", 3600, "read");
    let tls = tls_connect(h.proxy_addr, &h.certs).await;
    let (mut rd, mut wr) = tokio::io::split(tls);
    let head = format!(
        "POST /dies/up HTTP/1.1\r\nhost: localhost\r\nauthorization: Bearer {token}\r\n\
         transfer-encoding: chunked\r\n\r\n"
    );
    let writer = tokio::spawn(async move {
        let chunk = format!("100\r\n{}\r\n", "x".repeat(256));
        wr.write_all(head.as_bytes()).await?;
        wr.write_all(chunk.as_bytes()).await?; // 256 B: the upstream wants 2 KB
        tokio::time::sleep(Duration::from_millis(1250)).await; // θ = 1 s
        for _ in 0..400 {
            wr.write_all(chunk.as_bytes()).await?;
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        std::io::Result::Ok(())
    });
    let mut buf = [0u8; 256];
    let n = tokio::time::timeout(Duration::from_secs(6), rd.read(&mut buf))
        .await
        .expect("answered")
        .unwrap();
    writer.abort();
    let line = String::from_utf8_lossy(&buf[..n]);
    assert!(line.starts_with("HTTP/1.1 502"), "{line}");
    let (s, _) = raw_get(&h, "/dies/after", Some(&token)).await;
    assert!(s.contains(" 200"), "earlier stall: not blamed: {s}");
}

/// Only the canonical spelling of a header the proxy asserts reaches the
/// upstream; other headers keep their names.
#[tokio::test]
async fn non_canonical_proxy_header_spellings_are_stripped_e2e() {
    let h = Harness::new(0).await;
    let token = mint_jwt("tenant-a", 3600, "read");
    let (s, rest) = raw_get_with(
        &h,
        "/svc-a/x",
        Some(&token),
        "X_Ferryman_Tenant: victim\r\nX_Forwarded_For: 6.6.6.6\r\nx_custom: 1\r\n",
    )
    .await;
    assert!(s.contains(" 200"), "{s}");
    let rest = rest.to_ascii_lowercase();
    let names = rest
        .lines()
        .find_map(|l| l.strip_prefix("x-echo-names: "))
        .unwrap_or_default()
        .to_string();
    let names: Vec<&str> = names.split(',').collect();
    assert!(!names.contains(&"x_ferryman_tenant"), "{names:?}");
    assert!(!names.contains(&"x_forwarded_for"), "{names:?}");
    assert!(names.contains(&"x_custom"), "{names:?}");
    assert!(rest.contains("x-echo-tenant: tenant-a\r\n"), "{rest}");
    assert!(!rest.contains("victim"), "only the real tenant: {rest}");
    assert!(rest.contains("x-echo-xff: 127.0.0.1\r\n"), "{rest}");
}
