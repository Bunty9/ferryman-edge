//! Per-request handler. Rejects everything that needs no upstream (bad
//! path, upgrade, declared oversized body) *before* route lookup, then
//! streams the request to the chosen upstream and the response back, and
//! turns upstream-caused failures into circuit-breaker trips.
//!
//! Bodies always stream; nothing is buffered. `upstream_timeout` starts
//! when the client has finished uploading and ends at the upstream's
//! response head. The response body has no deadline, so a long SSE stream
//! or download is never cut and never trips the breaker. The upload has
//! its own idle and total deadlines and an optional size cap. Those fail
//! with 408/413 and never touch the breaker. An error from the response body
//! (not a slow or long one) counts against the breaker. An upstream failure
//! after the client stalled its upload or its response reads for at least
//! θ = min(1 s, idle gap / 2), floored at 100 ms, does not: the upstream was
//! reacting to the client. Known limits, where the upstream is still blamed:
//! its own read/write timeout is under θ; it is a gateway answering 502/504
//! because its backend timed out on a stalled upload; or it has a total
//! request or response deadline (Go `http.Server` `ReadTimeout` /
//! `WriteTimeout`) that a slow but steady client exceeds, since every gap is
//! under θ and the stall exemption does not apply.
//!
//! Auth (JWT verify + rate limit + `x-ferryman-tenant` stamping) happens in
//! `lib.rs` before a request reaches `handle`.

use ferryman_edge_core::{Limits, SharedTable, Upstream};
use http::{HeaderMap, HeaderValue};
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
// Trait methods (`poll_frame`, `is_end_stream`, `size_hint`) on `Incoming`,
// without shadowing the `Body` alias below.
use hyper::body::Body as _;
use hyper::body::{Bytes, Frame, Incoming, SizeHint};
use hyper::{Request, Response};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::sync::oneshot;
use tokio::time::Sleep;

pub type BoxErr = Box<dyn std::error::Error + Send + Sync>;
/// Every response body: a streamed upstream body or a local error page.
pub type Body = BoxBody<Bytes, BoxErr>;

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

/// A local error answer labelled with the upstream (`host:port`).
fn upstream_error(status: u16, msg: &'static [u8], host: String) -> anyhow::Result<Response<Body>> {
    metrics::counter!("ferryman_requests_total", "status" => status.to_string(), "upstream" => host)
        .increment(1);
    Ok(Response::builder()
        .status(status)
        .body(text_body(Bytes::from_static(msg)))?)
}

/// True if `path` could be read as a dot segment (`.`/`..`) by a normalising
/// upstream, under the variants exercised by the tests
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

/// Why the proxy failed the client's upload. Never the upstream's fault.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UploadError {
    TooLarge,
    IdleTimeout,
    TotalTimeout,
}

impl std::fmt::Display for UploadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            UploadError::TooLarge => "request body too large",
            UploadError::IdleTimeout => "request body idle timeout",
            UploadError::TotalTimeout => "request body total timeout",
        })
    }
}

impl std::error::Error for UploadError {}

/// The status for a failed `client.request` that the *client* caused:
/// its body hit the cap (413), stalled or over-ran its deadline (408), or
/// broke off (400; hyper reports a failing outgoing body as a user error).
/// `None` means the upstream's fault. Client-caused failures must never
/// reach the breaker, or any tenant could open a route for everyone.
fn client_fault(e: &(dyn std::error::Error + 'static)) -> Option<(u16, &'static [u8])> {
    if let Some(u) = error_chain(e).find_map(|c| c.downcast_ref::<UploadError>()) {
        return Some(match u {
            UploadError::TooLarge => (413, &b"payload too large"[..]),
            UploadError::IdleTimeout | UploadError::TotalTimeout => {
                (408, &b"request body timeout"[..])
            }
        });
    }
    error_chain(e)
        .any(|c| {
            c.downcast_ref::<hyper::Error>()
                .is_some_and(|h| h.is_user())
        })
        .then_some((400, &b"request body error"[..]))
}

fn error_chain<'a>(
    e: &'a (dyn std::error::Error + 'static),
) -> impl Iterator<Item = &'a (dyn std::error::Error + 'static)> {
    std::iter::successors(Some(e), |c| c.source())
}

/// True for a protocol-upgrade request (`Upgrade` other than `h2c`) or CONNECT.
///
/// Upgrades (WebSocket etc.) need both hops spliced together, which this
/// proxy doesn't do; say so instead of forwarding a mangled plain GET.
/// `h2c` is exempt: servers may ignore it (RFC 9110 §7.8), and clients
/// like curl --http2 or Java's HttpClient send it on every plain request.
/// Plain CONNECT (HTTP/1 or h2) is caught here; h2 extended CONNECT
/// (`:protocol`) is refused by the h2 layer itself, which doesn't enable it.
///
/// Must be called *before* `strip_hop_by_hop`, which removes `Upgrade`.
pub(crate) fn wants_upgrade<B>(req: &Request<B>) -> bool {
    req.method() == http::Method::CONNECT
        || req
            .headers()
            .get(http::header::UPGRADE)
            .is_some_and(|v| !v.as_bytes().eq_ignore_ascii_case(b"h2c"))
}

/// The client's request body, streamed to the upstream. It enforces the
/// optional size cap, the idle deadline between frames and the total
/// deadline, and it signals end-of-stream so `upstream_timer` starts
/// only once the upload is complete. Never buffers.
///
/// The total deadline also runs while the upstream drains the body slowly: an
/// upload that takes longer than it because the upstream reads slowly gets a
/// 408, which touches no breaker.
pub struct RequestBody {
    inner: Incoming,
    remaining: Option<u64>,
    idle: Duration,
    deadline: tokio::time::Instant,
    // Armed only while waiting on the client, so a slow upstream connect or
    // an upstream that is not reading is never blamed on the client.
    idle_sleep: Option<Pin<Box<Sleep>>>,
    total_sleep: Option<Pin<Box<Sleep>>>,
    eos: Option<oneshot::Sender<()>>,
    state: Arc<BodyState>,
}

/// What the timer and the blame checks can see of the body: whether hyper
/// polled it, and since when the last poll has been left waiting on the
/// client (rather than hyper having stopped reading because the upstream
/// isn't draining it).
struct BodyState {
    polled: AtomicBool,
    /// Start of the current wait on the client, as nanoseconds since `base`
    /// plus one; 0 while not waiting. Set on a `Pending` poll, cleared by
    /// any `Ready` (frame, end of stream, error).
    waiting_since: AtomicU64,
    base: tokio::time::Instant,
    /// How long a client must stall (upload, or pulling the response) before
    /// an upstream failure is put down to that stall: min(1 s, idle gap / 2).
    stall: Duration,
    /// The request body yielded an error (cap, deadline, client broke off).
    client_failed: AtomicBool,
}

/// θ: min(1 s, idle / 2), floored at 100 ms so a zero idle gap cannot turn
/// response-body blame off entirely.
fn stall_threshold(idle: Duration) -> Duration {
    (idle / 2)
        .min(Duration::from_secs(1))
        .max(Duration::from_millis(100))
}

impl BodyState {
    fn new(idle: Duration) -> Self {
        Self {
            polled: AtomicBool::new(false),
            waiting_since: AtomicU64::new(0),
            base: tokio::time::Instant::now(),
            stall: stall_threshold(idle),
            client_failed: AtomicBool::new(false),
        }
    }

    fn now_mark(&self) -> u64 {
        u64::try_from(self.base.elapsed().as_nanos())
            .unwrap_or(u64::MAX - 1)
            .saturating_add(1)
    }

    /// The last poll of the upload was left waiting on the client. During a
    /// normal upload this is true most of the time (the proxy drains the
    /// client faster than it sends), so it is no excuse for an upstream
    /// failure on its own; see [`Self::client_stalled`].
    fn waiting_on_client(&self) -> bool {
        self.waiting_since.load(Ordering::Acquire) != 0
    }

    /// The proxy has been waiting on the client's next upload frame for at
    /// least `stall`. An upstream that gives up now (its own read timeout,
    /// say) is reacting to the client's stall, so it is not blamed. An
    /// upstream that dies while the client keeps sending is.
    fn client_stalled(&self) -> bool {
        let since = self.waiting_since.load(Ordering::Acquire);
        since != 0 && Duration::from_nanos(self.now_mark().saturating_sub(since)) >= self.stall
    }
}

/// End-of-upload signal for [`upstream_timer`].
pub(crate) struct Eos {
    rx: oneshot::Receiver<()>,
    state: Arc<BodyState>,
}

impl RequestBody {
    fn new(inner: Incoming, cap: Option<u64>, idle: Duration, total: Duration) -> (Self, Eos) {
        let (tx, rx) = oneshot::channel();
        let state = Arc::new(BodyState::new(idle));
        let mut b = Self {
            inner,
            remaining: cap,
            idle,
            deadline: tokio::time::Instant::now() + total,
            idle_sleep: None,
            total_sleep: None,
            eos: Some(tx),
            state: state.clone(),
        };
        b.signal_if_done();
        (b, Eos { rx, state })
    }

    fn signal_if_done(&mut self) {
        if self.inner.is_end_stream() {
            if let Some(tx) = self.eos.take() {
                let _ = tx.send(());
            }
        }
    }
}

impl hyper::body::Body for RequestBody {
    type Data = Bytes;
    type Error = BoxErr;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BoxErr>>> {
        let this = self.get_mut();
        let polled = this.poll_inner(cx);
        let state = &this.state;
        match polled {
            Poll::Pending => {
                if state.waiting_since.load(Ordering::Acquire) == 0 {
                    state
                        .waiting_since
                        .store(state.now_mark(), Ordering::Release);
                }
            }
            Poll::Ready(ref r) => {
                state.waiting_since.store(0, Ordering::Release);
                if matches!(r, Some(Err(_))) {
                    state.client_failed.store(true, Ordering::Release);
                }
            }
        }
        polled
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

impl RequestBody {
    fn poll_inner(&mut self, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, BoxErr>>> {
        let this = self;
        this.state.polled.store(true, Ordering::Release);
        if tokio::time::Instant::now() >= this.deadline {
            return Poll::Ready(Some(Err(UploadError::TotalTimeout.into())));
        }
        match Pin::new(&mut this.inner).poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                this.idle_sleep = None;
                if let (Some(left), Some(data)) = (this.remaining.as_mut(), frame.data_ref()) {
                    let n = data.len() as u64;
                    if n > *left {
                        return Poll::Ready(Some(Err(UploadError::TooLarge.into())));
                    }
                    *left -= n;
                }
                // The last frame of a content-length body may not be
                // followed by another poll, so check here as well as on None.
                this.signal_if_done();
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(Some(Err(e))) => Poll::Ready(Some(Err(e.into()))),
            Poll::Ready(None) => {
                if let Some(tx) = this.eos.take() {
                    let _ = tx.send(());
                }
                Poll::Ready(None)
            }
            Poll::Pending => {
                let idle = this.idle;
                let idle_sleep = this
                    .idle_sleep
                    .get_or_insert_with(|| Box::pin(tokio::time::sleep(idle)));
                if idle_sleep.as_mut().poll(cx).is_ready() {
                    return Poll::Ready(Some(Err(UploadError::IdleTimeout.into())));
                }
                let deadline = this.deadline;
                let total_sleep = this
                    .total_sleep
                    .get_or_insert_with(|| Box::pin(tokio::time::sleep_until(deadline)));
                if total_sleep.as_mut().poll(cx).is_ready() {
                    return Poll::Ready(Some(Err(UploadError::TotalTimeout.into())));
                }
                Poll::Pending
            }
        }
    }
}

/// Completes when the request must fail as an upstream timeout (504).
/// That is `upstream_timeout` after the upload finished, or a whole window
/// in which hyper stopped reading the body while the client was not the
/// one stalling (the upstream is not draining it). A merely slow client is
/// left to the body's own deadlines (408).
async fn upstream_timer(eos: Eos, upstream_timeout: Duration) {
    let Eos { mut rx, state } = eos;
    loop {
        tokio::select! {
            r = &mut rx => {
                // Sender dropped without EOS: the body failed, and the
                // request future reports that. Never time out for it.
                if r.is_err() {
                    std::future::pending::<()>().await;
                }
                break;
            }
            () = tokio::time::sleep(upstream_timeout) => {
                if !state.polled.swap(false, Ordering::AcqRel)
                    && !state.waiting_on_client()
                {
                    return;
                }
            }
        }
    }
    tokio::time::sleep(upstream_timeout).await;
}

/// The upstream's response body. An error from it (reset, truncated chunked
/// stream) is the upstream's fault and counts against the breaker, once. The
/// head already reported success; a slow or long body is never blamed, and a
/// client that goes away drops the body without a poll error.
///
/// Not blamed either: an error after the client was slow to pull the
/// response. hyper polls this body only when the client side can take more,
/// so a gap of at least `stall` between a frame (or the head) and the next
/// poll means the client paused reading; an upstream with a write timeout
/// then hangs up, reacting to that client.
struct WatchedBody {
    inner: Incoming,
    upstream: Upstream,
    request: Arc<BodyState>,
    failed: bool,
    /// When the head or the last frame was handed on and not yet followed
    /// by another poll.
    ready_at: Option<tokio::time::Instant>,
    /// Sticky: the client once took at least `stall` to pull the next frame.
    client_stalled_reading: bool,
}

impl hyper::body::Body for WatchedBody {
    type Data = Bytes;
    type Error = hyper::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, hyper::Error>>> {
        let this = self.get_mut();
        let now = tokio::time::Instant::now();
        if let Some(t) = this.ready_at.take() {
            if now - t >= this.request.stall {
                this.client_stalled_reading = true;
            }
        }
        let polled = Pin::new(&mut this.inner).poll_frame(cx);
        if let Poll::Ready(Some(Ok(_))) = &polled {
            this.ready_at = Some(now);
        }
        // The upstream may answer before it has read the whole upload. If the
        // client then aborts or stalls, hyper tears the connection down and
        // surfaces a plain "connection error" here, with no trace of the
        // client's error in its source chain. So besides the head's
        // classifier, check whether the request body itself failed.
        if let Poll::Ready(Some(Err(e))) = &polled {
            if !this.failed
                && client_fault(e).is_none()
                && !this.request.client_failed.load(Ordering::Acquire)
                && !this.request.client_stalled()
                && !this.client_stalled_reading
            {
                this.failed = true;
                this.upstream.mark_failed();
            }
        }
        polled
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

fn declared_len<B>(req: &Request<B>) -> Option<u64> {
    req.headers()
        .get(http::header::CONTENT_LENGTH)?
        .to_str()
        .ok()?
        .parse()
        .ok()
}

/// Handle a single inbound request with [`Limits::default`]. Hop-by-hop
/// headers are expected to be stripped by the caller (before it stamps
/// `x-ferryman-tenant`); upgrades are detected from what is still present.
pub async fn handle(
    table: SharedTable,
    client: Client<HttpConnector, RequestBody>,
    req: Request<Incoming>,
    peer_ip: IpAddr,
) -> anyhow::Result<Response<Body>> {
    handle_with(table, client, req, peer_ip, &Limits::default()).await
}

/// `handle` with explicit [`Limits`] (body cap).
pub async fn handle_with(
    table: SharedTable,
    client: Client<HttpConnector, RequestBody>,
    req: Request<Incoming>,
    peer_ip: IpAddr,
    limits: &Limits,
) -> anyhow::Result<Response<Body>> {
    let upgrade = wants_upgrade(&req);
    handle_checked(table, client, req, peer_ip, upgrade, limits).await
}

/// `handle` with the upgrade check done by the caller, who saw the headers
/// before they were stripped.
pub(crate) async fn handle_checked(
    table: SharedTable,
    client: Client<HttpConnector, RequestBody>,
    req: Request<Incoming>,
    peer_ip: IpAddr,
    upgrade: bool,
    limits: &Limits,
) -> anyhow::Result<Response<Body>> {
    let started = std::time::Instant::now();
    // `load_full`: the snapshot is held across awaits.
    let snapshot = table.load_full();
    let path = req.uri().path().to_string();

    // Everything that needs no upstream is rejected before `lookup`:
    // lookup may admit this request as the breaker's single half-open
    // probe, and a probe must report back.
    if bad_path(&path) {
        return plain(400, b"bad path");
    }
    if upgrade {
        return plain(501, b"protocol upgrades are not supported");
    }
    if let Some(max) = limits.max_request_body_bytes {
        if declared_len(&req).is_some_and(|len| len > max) {
            return plain(413, b"payload too large");
        }
    }

    let upstream = match snapshot.lookup(&path) {
        Some(u) => u.clone(),
        // A prefix matched but its upstream's breaker is open: 503.
        None if snapshot.has_prefix(&path) => return plain(503, b"upstream unavailable"),
        None => return plain(404, b"no route"),
    };

    let (mut parts, body) = req.into_parts();
    let (body, eos) = RequestBody::new(
        body,
        limits.max_request_body_bytes,
        snapshot.request_body_idle_timeout(),
        snapshot.request_body_timeout(),
    );

    // Rebuild URI: upstream scheme+authority + original path+query. Inbound
    // HTTP/2 requests carry the proxy's own authority in `parts.uri`, so
    // this is always a full rebuild, never a patch.
    let mut up_parts = upstream.uri.clone().into_parts();
    up_parts.path_and_query = parts.uri.path_and_query().cloned();
    if let Some(authority) = upstream.uri.authority() {
        parts.headers.insert(
            http::header::HOST,
            HeaderValue::from_str(authority.as_str())?,
        );
    }
    parts.uri = http::Uri::from_parts(up_parts)?;
    // hyper-util's legacy Client rejects an HTTP/2-versioned request on an
    // HTTP/1 connection; upstreams here are plain http://, so downgrade.
    parts.version = http::Version::HTTP_11;
    set_forwarded(&mut parts.headers, peer_ip);

    // host:port, so two upstreams on one host stay distinct series.
    let host = upstream
        .uri
        .authority()
        .map_or_else(String::new, |a| a.to_string());
    let client_state = eos.state.clone();
    let fwd = Request::from_parts(parts, body);
    let result = tokio::select! {
        r = client.request(fwd) => Some(r),
        () = upstream_timer(eos, snapshot.upstream_timeout) => None,
    };
    let resp = match result {
        Some(Ok(resp)) => resp,
        Some(Err(e)) => {
            if let Some((status, msg)) = client_fault(&e) {
                // Deliberately reports nothing to the breaker: not
                // `mark_failed` (the upstream is not at fault) and not
                // `mark_success` (a client must not close an open breaker by
                // aborting an upload). If `lookup` admitted this request as
                // the half-open probe, the slot stays held until the stale
                // HalfOpen rule re-arms it after one cooldown, until the
                // core breaker grows an explicit release.
                return plain(status, msg);
            }
            tracing::warn!(upstream = %host, error = %e, "upstream request failed");
            // An upstream that drops the connection after the client stalled
            // its upload for `stall` is reacting to that stall: answer 502,
            // blame no one.
            if !client_state.client_stalled() {
                upstream.mark_failed();
            }
            return upstream_error(502, b"bad gateway", host);
        }
        None => {
            upstream.mark_failed();
            return upstream_error(504, b"upstream timeout", host);
        }
    };

    let status = resp.status();
    // Health is judged on the response head; the body then streams with no
    // deadline. Only gateway-class 5xx mean "this upstream is unhealthy": a
    // 500 is one request's bug and must not blackhole the route.
    if matches!(status.as_u16(), 502..=504) {
        upstream.mark_failed();
    } else {
        upstream.mark_success();
    }
    let (mut resp_parts, resp_body) = resp.into_parts();
    let resp_body = WatchedBody {
        inner: resp_body,
        upstream: upstream.clone(),
        request: client_state,
        failed: false,
        // The gap between the head and the first body poll counts too.
        ready_at: Some(tokio::time::Instant::now()),
        client_stalled_reading: false,
    };
    strip_hop_by_hop(&mut resp_parts.headers);
    // Don't echo the upstream's HTTP version back; hyper picks the wire version.
    resp_parts.version = http::Version::default();
    metrics::histogram!("ferryman_request_duration_seconds", "upstream" => host.clone())
        .record(started.elapsed().as_secs_f64());
    metrics::counter!(
        "ferryman_requests_total",
        "status" => status.as_u16().to_string(),
        "upstream" => host
    )
    .increment(1);
    Ok(Response::from_parts(
        resp_parts,
        resp_body.map_err(Into::into).boxed(),
    ))
}

#[cfg(test)]
mod tests {
    use super::{bad_path, stall_threshold, wants_upgrade};
    use std::time::Duration;

    #[test]
    fn stall_threshold_is_clamped() {
        let ms = Duration::from_millis;
        assert_eq!(stall_threshold(Duration::ZERO), ms(100));
        assert_eq!(stall_threshold(ms(100)), ms(100));
        assert_eq!(stall_threshold(ms(600)), ms(300));
        assert_eq!(stall_threshold(Duration::from_secs(30)), ms(1000));
    }

    #[test]
    fn upgrade_detection() {
        let get = |u: Option<&str>| {
            let mut b = http::Request::get("/");
            if let Some(u) = u {
                b = b.header("upgrade", u);
            }
            b.body(()).unwrap()
        };
        assert!(wants_upgrade(
            &http::Request::connect("example.com:443").body(()).unwrap()
        ));
        assert!(wants_upgrade(&get(Some("h2c, websocket"))));
        assert!(wants_upgrade(&get(Some("websocket"))));
        assert!(!wants_upgrade(&get(Some("h2c"))));
        assert!(!wants_upgrade(&get(Some("H2C"))));
        assert!(!wants_upgrade(&get(None)));
    }

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
