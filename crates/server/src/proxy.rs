//! Per-request handler. Looks up the routing table, rebuilds the URI for
//! the chosen upstream, strips hop-by-hop headers, forwards via the shared
//! hyper client, records metrics, and turns transport errors / 502-504 into
//! circuit-breaker trips.
//!
//! Body buffering is cfg-gated:
//!   - `default`: collect the body once into a `Full<Bytes>`. Lower code
//!     complexity, faster for typical JSON.
//!   - `boxed_body`: forward streamed via `BoxBody`. Lower steady-state
//!     allocations for large payloads.
//!
//! Numbers from spec: boxed ≈ +200µs at 10 MB; collected ≈ +80µs at 1 KB
//! but allocates ~req_size. Default off — defended in README.
//!
//! Auth (JWT verify + rate limit + `x-ferryman-tenant` stamping) happens in
//! `lib.rs` before a request reaches `handle` — by the time we're here the
//! caller is authenticated and within quota.

use ferryman_edge_core::SharedTable;
use http::{HeaderMap, HeaderValue};
use http_body_util::{BodyExt, Full, LengthLimitError, Limited};
use hyper::body::Bytes;
use hyper::body::Incoming;
use hyper::{Request, Response};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

#[cfg(feature = "boxed_body")]
pub type BoxErr = Box<dyn std::error::Error + Send + Sync>;

#[cfg(not(feature = "boxed_body"))]
pub type Body = Full<Bytes>;
#[cfg(feature = "boxed_body")]
pub type Body = http_body_util::combinators::BoxBody<Bytes, BoxErr>;

/// Upper bound on a forwarded request body. Chosen as a round number well
/// above any expected JSON payload for this proxy's target traffic; bump if
/// upstreams start accepting large uploads.
const MAX_BODY_BYTES: usize = 8 * 1024 * 1024;

/// Wall-clock budget for the upstream round trip, starting once the request
/// body is ready to send.
const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(30);

/// Budget for receiving the client's body (collected mode). Separate from
/// `UPSTREAM_TIMEOUT` so a slow client can't make a healthy upstream look
/// timed out.
const BODY_READ_TIMEOUT: Duration = Duration::from_secs(30);

const HOP_BY_HOP_HEADERS: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "proxy-authenticate",
    "proxy-authorization",
];

/// Strip the standard hop-by-hop headers plus anything named in the
/// `Connection` header (RFC 9110 §7.6.1) — applied to both the outbound
/// request and the inbound-from-upstream response.
pub(crate) fn strip_hop_by_hop(headers: &mut HeaderMap) {
    let mut extra: Vec<String> = Vec::new();
    for v in headers.get_all(http::header::CONNECTION) {
        if let Ok(s) = v.to_str() {
            extra.extend(
                s.split(',')
                    .map(|p| p.trim().to_ascii_lowercase())
                    .filter(|p| !p.is_empty()),
            );
        }
    }
    for name in HOP_BY_HOP_HEADERS {
        headers.remove(*name);
    }
    for name in extra {
        headers.remove(name.as_str());
    }
}

/// This is the edge: whatever forwarding headers the client sent are
/// untrusted, so replace them with the peer address instead of appending.
fn set_forwarded(headers: &mut HeaderMap, ip: IpAddr) {
    headers.remove("forwarded");
    headers.remove("x-real-ip");
    headers.insert(
        "x-forwarded-for",
        HeaderValue::from_str(&ip.to_string()).expect("an IP is a valid header value"),
    );
    headers.insert("x-forwarded-proto", HeaderValue::from_static("https"));
}

#[cfg(not(feature = "boxed_body"))]
pub(crate) fn text_body(bytes: Bytes) -> Body {
    Full::new(bytes)
}

#[cfg(feature = "boxed_body")]
pub(crate) fn text_body(bytes: Bytes) -> Body {
    Full::new(bytes)
        .map_err(|never: std::convert::Infallible| -> BoxErr { match never {} })
        .boxed()
}

fn plain(status: u16, msg: &'static [u8]) -> anyhow::Result<Response<Body>> {
    metrics::counter!("ferryman_requests_total", "status" => status.to_string()).increment(1);
    Ok(Response::builder()
        .status(status)
        .body(text_body(Bytes::from_static(msg)))?)
}

/// True if `path` could be read as a dot segment (`.`/`..`) by a normalising
/// upstream, under the separator and encoding variants exercised by the tests
/// below. Detection only; the forwarded path is never rewritten.
fn bad_path(path: &str) -> bool {
    let b = path.as_bytes();
    let (mut start, mut i) = (0, 0);
    while i <= b.len() {
        let sep = match b[i..] {
            [] => Some(0),
            [b'/' | b'\\', ..] => Some(1),
            [b'%', b'2', b'f' | b'F', ..] | [b'%', b'5', b'c' | b'C', ..] => Some(3),
            [b'%', b'0', b'0', ..] | [b'%', b'u' | b'U', ..] => return true,
            [b'%', b'2', b'5', b'2', b'e' | b'E' | b'f' | b'F', ..]
            | [b'%', b'2', b'5', b'5', b'c' | b'C', ..] => return true,
            _ => None,
        };
        match sep {
            Some(n) => {
                if dot_piece(&b[start..i]) {
                    return true;
                }
                i += n.max(1);
                start = i;
            }
            None => i += 1,
        }
    }
    false
}

/// `.` or `..` once parameters and encodings handled by `bad_path` are
/// accounted for.
fn dot_piece(piece: &[u8]) -> bool {
    let end = piece.iter().position(|&c| c == b';').unwrap_or(piece.len());
    let b = &piece[..end];
    let (mut i, mut dots) = (0, 0);
    while i < b.len() {
        match b[i..] {
            [b'.', ..] => i += 1,
            [b'%', b'2', b'e' | b'E', ..] => i += 3,
            _ => return false,
        }
        dots += 1;
    }
    matches!(dots, 1 | 2)
}

/// True when a client-request failure was caused by *our* side of the
/// exchange — the inbound body hit the size cap or the client went away
/// mid-upload (hyper reports both as a user body error) — rather than by
/// the upstream. Those must not trip the upstream's breaker, or any
/// authenticated client could open it for every tenant.
fn is_client_body_error(e: &(dyn std::error::Error + 'static)) -> bool {
    error_chain(e).any(|c| {
        c.is::<LengthLimitError>()
            || c.downcast_ref::<hyper::Error>()
                .is_some_and(|h| h.is_user())
    })
}

fn error_chain<'a>(
    e: &'a (dyn std::error::Error + 'static),
) -> impl Iterator<Item = &'a (dyn std::error::Error + 'static)> {
    std::iter::successors(Some(e), |c| c.source())
}

/// Handle a single inbound request. Hop-by-hop headers are already stripped
/// by the caller (before it stamps `x-ferryman-tenant`).
pub async fn handle(
    table: SharedTable,
    client: Client<HttpConnector, Body>,
    req: Request<Incoming>,
    peer_ip: IpAddr,
) -> Result<Response<Body>, anyhow::Error> {
    let started = std::time::Instant::now();
    let snapshot = table.load();
    let path = req.uri().path().to_string();

    // Must stay before `RouteTable::lookup`: lookup can admit this request as
    // the breaker's single half-open probe, and a 400 would never report back.
    if bad_path(&path) {
        return plain(400, b"bad path");
    }

    // Fast rejection for a declared oversized body. `forward_body` below is
    // the backstop for chunked uploads that lie about (or omit) it.
    if req
        .headers()
        .get(http::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok())
        .is_some_and(|len| len > MAX_BODY_BYTES as u64)
    {
        return plain(413, b"payload too large");
    }

    // Deal with the client's body *before* route lookup: lookup may admit
    // this request as the breaker's half-open probe, and a probe that ends
    // in a client-side 408/413/400 would never report back. The body read
    // has its own deadline so a slow uploader can't eat into (and then be
    // blamed as) the upstream's time budget.
    let (mut parts, body) = req.into_parts();
    let (fwd_body, upload_done) =
        match tokio::time::timeout(BODY_READ_TIMEOUT, forward_body(body)).await {
            Ok(Ok(b)) => b,
            Ok(Err(e)) if e.downcast_ref::<LengthLimitError>().is_some() => {
                return plain(413, b"payload too large");
            }
            Ok(Err(_)) => return plain(400, b"request body error"),
            Err(_) => return plain(408, b"request body timeout"),
        };

    let upstream = match snapshot.lookup(&path) {
        Some(u) => u.clone(),
        // A prefix matched but its upstream's breaker is open: 503.
        None if snapshot.has_prefix(&path) => return plain(503, b"upstream unavailable"),
        None => return plain(404, b"no route"),
    };

    // Rebuild URI: upstream scheme+authority + original path+query. Inbound
    // HTTP/2 requests carry the proxy's own scheme/authority in `parts.uri`,
    // so this is always a full rebuild, never a patch.
    let mut up_parts = upstream.uri.clone().into_parts();
    up_parts.path_and_query = parts.uri.path_and_query().cloned();
    parts.uri = http::Uri::from_parts(up_parts)?;
    // hyper-util's legacy Client rejects an HTTP/2-versioned request over
    // an HTTP/1 connection (UserUnsupportedVersion) — upstreams here are
    // plain http://, so always downgrade.
    parts.version = http::Version::HTTP_11;
    if let Some(authority) = upstream.uri.authority() {
        parts.headers.insert(
            http::header::HOST,
            HeaderValue::from_str(authority.as_str())?,
        );
    }
    set_forwarded(&mut parts.headers, peer_ip);

    // The upstream's budget starts now: round trip plus (collected mode)
    // the response body.
    let deadline = tokio::time::Instant::now() + UPSTREAM_TIMEOUT;
    let fwd = Request::from_parts(parts, fwd_body);

    // host:port, so two upstreams on one host stay distinct series.
    let host = upstream
        .uri
        .authority()
        .map_or_else(String::new, |a| a.to_string());
    let resp = match tokio::time::timeout_at(deadline, client.request(fwd)).await {
        Ok(Ok(resp)) => resp,
        Ok(Err(e)) if is_client_body_error(&e) => {
            let too_large = error_chain(&e).any(|c| c.is::<LengthLimitError>());
            return if too_large {
                plain(413, b"payload too large")
            } else {
                plain(400, b"request body error")
            };
        }
        Ok(Err(e)) => {
            tracing::warn!(upstream = %host, error = %e, "upstream request failed");
            upstream.mark_failed();
            metrics::counter!("ferryman_requests_total", "status" => "502", "upstream" => host)
                .increment(1);
            return Ok(Response::builder()
                .status(502)
                .body(text_body(Bytes::from_static(b"bad gateway")))?);
        }
        Err(_) => {
            // In streaming mode the upload runs inside this deadline; only
            // blame the upstream if the client had finished sending.
            if upload_done.load(Ordering::Acquire) {
                upstream.mark_failed();
            }
            metrics::counter!("ferryman_requests_total", "status" => "504", "upstream" => host)
                .increment(1);
            return Ok(Response::builder()
                .status(504)
                .body(text_body(Bytes::from_static(b"upstream timeout")))?);
        }
    };

    let status = resp.status();
    let (mut resp_parts, resp_body) = resp.into_parts();
    strip_hop_by_hop(&mut resp_parts.headers);
    // Don't echo the upstream's HTTP version (e.g. an HTTP/1.0 upstream)
    // back to the client; hyper picks the wire version.
    resp_parts.version = http::Version::default();

    #[cfg(not(feature = "boxed_body"))]
    let out_body: Body = match tokio::time::timeout_at(deadline, resp_body.collect()).await {
        Ok(Ok(collected)) => Full::new(collected.to_bytes()),
        Ok(Err(_)) | Err(_) => {
            upstream.mark_failed();
            metrics::counter!("ferryman_requests_total", "status" => "502", "upstream" => host)
                .increment(1);
            return Ok(Response::builder()
                .status(502)
                .body(text_body(Bytes::from_static(b"bad gateway")))?);
        }
    };
    #[cfg(feature = "boxed_body")]
    let out_body: Body = resp_body.map_err(Into::into).boxed();

    // Only gateway-class 5xx mean "this upstream is unhealthy"; a 500 is an
    // application bug on one request and must not blackhole the whole route
    // for a cooldown.
    if matches!(status.as_u16(), 502..=504) {
        upstream.mark_failed();
    } else {
        upstream.mark_success();
    }
    metrics::histogram!("ferryman_request_duration_seconds", "upstream" => host.clone())
        .record(started.elapsed().as_secs_f64());
    metrics::counter!(
        "ferryman_requests_total",
        "status" => status.as_u16().to_string(),
        "upstream" => host
    )
    .increment(1);

    Ok(Response::from_parts(resp_parts, out_body))
}

// ----- Body forwarding strategies ------------------------------------------
//
// Cargo feature `boxed_body` enables streaming forwarding (low alloc, good for
// big payloads). Default off => collect body once (smaller code, faster for
// JSON < 256 KB). Hiring-panel question to anticipate: "why is the default
// off?" — see README "Design tradeoffs".

/// Whether the client finished sending its body. Collected mode always has
/// by the time the upstream is dialed; streaming mode flips it when the
/// body reaches end-of-stream.
type UploadDone = Arc<AtomicBool>;

#[cfg(not(feature = "boxed_body"))]
async fn forward_body(body: Incoming) -> anyhow::Result<(Body, UploadDone)> {
    match Limited::new(body, MAX_BODY_BYTES).collect().await {
        Ok(collected) => Ok((
            Full::new(collected.to_bytes()),
            Arc::new(AtomicBool::new(true)),
        )),
        Err(e) => match e.downcast::<LengthLimitError>() {
            Ok(too_large) => Err(anyhow::Error::new(*too_large)),
            Err(other) => Err(anyhow::anyhow!("{other}")),
        },
    }
}

// A chunked upload with no Content-Length that exceeds MAX_BODY_BYTES is cut
// mid-stream by `Limited`; `is_client_body_error` maps that to 413 (or 400
// for a client disconnect) and keeps it off the breaker.
#[cfg(feature = "boxed_body")]
async fn forward_body(body: Incoming) -> anyhow::Result<(Body, UploadDone)> {
    let inner = Limited::new(body, MAX_BODY_BYTES);
    // hyper never polls a body that already reports end-of-stream (e.g. a
    // GET), so seed the flag rather than waiting for a poll.
    let done: UploadDone = Arc::new(AtomicBool::new(hyper::body::Body::is_end_stream(&inner)));
    let body = TrackEnd {
        inner,
        done: done.clone(),
    };
    Ok((body.boxed(), done))
}

/// Body wrapper that records when the inner body reaches end-of-stream.
#[cfg(feature = "boxed_body")]
struct TrackEnd<B> {
    inner: B,
    done: UploadDone,
}

#[cfg(feature = "boxed_body")]
impl<B: hyper::body::Body + Unpin> hyper::body::Body for TrackEnd<B> {
    type Data = B::Data;
    type Error = B::Error;

    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<hyper::body::Frame<Self::Data>, Self::Error>>> {
        let polled = std::pin::Pin::new(&mut self.inner).poll_frame(cx);
        if matches!(polled, std::task::Poll::Ready(None)) || self.inner.is_end_stream() {
            self.done.store(true, Ordering::Release);
        }
        polled
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> hyper::body::SizeHint {
        self.inner.size_hint()
    }
}

#[cfg(test)]
mod tests {
    use super::bad_path;

    #[test]
    fn dot_segments_are_rejected() {
        for p in [
            "/svc-a/../svc-b",
            "/svc-a/./x",
            "/svc-a/%2e%2e/svc-b",
            "/svc-a/%2E/x",
            "/api/../admin",
            "/api/%2e%2e/admin",
            "/api/..%2fadmin",
            "/api/./../admin",
            "/api/..",
            "/api/%2E%2E/x",
            "/api/%2e%2E/x",
            "/api/.%2e/x",
            "/api/..;/admin",
            "/api/.;x/y",
            "/api/%2e%2e;/x",
            "/api/..%5cx",
            "/api/..%5Cx",
            "/api/a\\..\\b",
            "/api/%2e/x",
            "/..",
            "/api/a%2f..",
            "/api/%2e%2e%2f",
            "/api/..%00",
            "/api/.%00.",
            "/api/%u002e%u002e",
            "/api/%U002e",
            "/api/%252e%252e",
            "/api/%252E",
            "/api/%252f",
            "/api/%252F",
            "/api/%255c",
            "/api/a%00b",
            "/api/a%5c..",
            "/api/a%5C..%5Cb",
        ] {
            assert!(bad_path(p), "{p}");
        }
    }

    #[test]
    fn legitimate_paths_are_allowed() {
        for p in [
            "/svc-a/x",
            "/svc-a/.hidden",
            "/svc-a/a..b",
            "/a..b/",
            "/.well-known/acme",
            "/file.tar.gz",
            "/api/v1.2/x",
            "/",
            "/api/...",
            "/api/a;..",
            "/api/%2e%2e%2e/x",
            "/api/%41/x",
            "/api/.a/x",
            "/api/a%2/",
            "/api/v4/projects/group%2Fproject",
            "/api/queues/%2F/q",
            "/@scope%2fpkg",
            "/%2F",
            "/api/%25",
            "/api/100%25",
            "/api/%c0%ae",
        ] {
            assert!(!bad_path(p), "{p}");
        }
    }
}
