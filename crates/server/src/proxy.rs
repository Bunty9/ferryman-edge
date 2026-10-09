//! Per-request handler. Rejects everything that needs no upstream (bad or
//! ambiguous path, bad Host, upgrade, declared oversized body) *before*
//! route lookup, then streams the request to the chosen upstream and the
//! response back, and turns upstream-caused failures into circuit-breaker
//! failures.
//!
//! Admission: `RouteTable::lookup` picks the route; `Upstream::try_acquire`
//! is the last gate before forwarding. Its ticket reports exactly once (see
//! `Ticket`); a request that ends without a verdict on the upstream
//! releases it instead.
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
//! reacting to the client. The upload stall counts if it happened at any
//! point of the request, not only if it is still going on, and it also
//! exempts a forwarded 502–504 (a gateway whose backend gave up on the
//! stalled upload). Known limits, where the
//! upstream is still blamed: its own read/write timeout is under θ; or it
//! has a total request or response deadline (Go `http.Server` `ReadTimeout`
//! / `WriteTimeout`) that a slow but steady client exceeds, since every gap
//! is under θ and the stall exemption does not apply.
//!
//! Auth (JWT verify + rate limit + `x-ferryman-tenant` stamping) happens in
//! `lib.rs` before a request reaches `handle`.

use ferryman_edge_core::ferryman_core::path::{ambiguous_route, bad_path};
use ferryman_edge_core::ferryman_core::{Admission, SharedTable, Upstream};
use ferryman_edge_core::Limits;
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
        // The proxy relies on `Host`; a client must not delete it by naming
        // it in `Connection`.
        if name == "host" {
            continue;
        }
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

/// One admitted request's breaker report, created right after
/// `Upstream::try_acquire`. `success` and `failure` take `self`, so the
/// admission reports at most once. Dropped without a verdict (client body
/// error 400/408/413, an upload stall the upstream reacted to, or the
/// handler future dropped because the client hung up or reset its h2
/// stream before the upstream answered), it hands the admission back with
/// `Upstream::release`: core re-arms a half-open probe slot at most once per
/// cooldown, and a normal admission is a no-op. Upstream timeouts and
/// errors never get here; they call `failure`.
struct Ticket {
    upstream: Upstream,
    admission: Option<Admission>,
}

impl Ticket {
    fn new(upstream: Upstream, admission: Admission) -> Self {
        Self {
            upstream,
            admission: Some(admission),
        }
    }

    fn success(mut self) {
        if let Some(a) = self.admission.take() {
            self.upstream.record_success(a);
        }
    }

    fn failure(mut self) {
        if let Some(a) = self.admission.take() {
            self.upstream.record_failure(a);
        }
    }

    /// No verdict on the upstream: hand the admission back (see `Drop`).
    fn release(self) {}
}

impl Drop for Ticket {
    fn drop(&mut self) {
        if let Some(a) = self.admission.take() {
            self.upstream.release(a);
        }
    }
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
    /// Sticky: a finished wait on the client lasted at least `stall`.
    stalled_once: AtomicBool,
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
            stalled_once: AtomicBool::new(false),
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
        self.stalled_for(self.waiting_since.load(Ordering::Acquire))
    }

    /// The client stalled its upload for at least `stall` at some point of
    /// this request, or is stalling now (ferryman's rule). Every blame path
    /// checks this: an upstream that hangs up, breaks its body, or (as a
    /// gateway) answers 502–504 after such a stall may be reacting to it, so
    /// it is not blamed. One whose client never paused that long is.
    fn stalled_during_request(&self) -> bool {
        self.stalled_once.load(Ordering::Acquire) || self.client_stalled()
    }

    /// A wait that started at `since` (a `now_mark`, 0 = none) has lasted
    /// at least `stall`.
    fn stalled_for(&self, since: u64) -> bool {
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
                if state.stalled_for(state.waiting_since.swap(0, Ordering::AcqRel)) {
                    state.stalled_once.store(true, Ordering::Release);
                }
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
/// stream) is the upstream's fault and counts against the breaker, once, as
/// an ordinary (`Admission::Normal`) failure: the head already gave the
/// ticket's verdict. A slow or long body is never blamed, and a client that
/// goes away drops the body without a poll error. (ferryman itself never
/// blames after the head; edge does on purpose.)
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
                && !this.request.stalled_during_request()
                && !this.client_stalled_reading
            {
                this.failed = true;
                this.upstream.record_failure(Admission::Normal);
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

/// The `Host` the upstream sees, and `x-forwarded-host` (E1).
///
/// By default this is the client's host: the request-target authority
/// (h2 `:authority`, or an HTTP/1 absolute-form URI) wins over `Host`, per
/// RFC 9112 section 3.2.2. `rewrite_host` sends the upstream's own
/// authority instead (the 0.1.x behaviour). A client-sent
/// `x-forwarded-host` is always replaced.
///
/// This is the only place `rewrite_host` is interpreted.
fn set_host(
    headers: &mut HeaderMap,
    client_uri: &http::Uri,
    upstream_uri: &http::Uri,
    rewrite_host: bool,
) {
    let client_host = client_uri
        .authority()
        .and_then(host_value)
        .or_else(|| headers.get(http::header::HOST).and_then(parse_host));
    headers.remove("x-forwarded-host");
    if let Some(h) = &client_host {
        headers.insert("x-forwarded-host", h.clone());
    }
    let host = if rewrite_host {
        upstream_uri.authority().and_then(host_value)
    } else {
        client_host
    };
    match host {
        Some(h) => {
            headers.insert(http::header::HOST, h);
        }
        None => {
            headers.remove(http::header::HOST);
        }
    }
}

/// A `Host` header value as `host[:port]`; `None` unless it is a bare
/// authority (no userinfo, list or path).
fn parse_host(v: &HeaderValue) -> Option<HeaderValue> {
    if v.as_bytes()
        .iter()
        .any(|b| matches!(b, b'@' | b',' | b'/') || *b >= 0x80)
    {
        return None;
    }
    let s = v.to_str().ok()?;
    // Whatever follows the host part (after `]` for an IPv6 literal) must be
    // `:` plus a 1-5 digit port that fits u16; `Authority` alone accepts
    // `a:b`, `x:99999` and `x:`.
    let rest = if s.starts_with('[') {
        s.find(']').map(|i| &s[i + 1..])?
    } else {
        s.find(':').map_or("", |i| &s[i..])
    };
    if !rest.is_empty() {
        let port = rest.strip_prefix(':')?;
        if port.len() > 5
            || !port.bytes().all(|b| b.is_ascii_digit())
            || port.parse::<u16>().is_err()
        {
            return None;
        }
    }
    if s == "*" {
        return None;
    }
    http::uri::Authority::try_from(v.as_bytes())
        .ok()
        .and_then(|a| host_value(&a))
}

/// More than one `Host`, or (when the request target has no authority, so
/// the header is what gets used) one that is not a plain authority. Checked
/// before `lookup`, so the 400 cannot leak a half-open probe slot.
fn bad_host(headers: &HeaderMap, uri: &http::Uri, version: http::Version) -> bool {
    let mut it = headers.get_all(http::header::HOST).iter();
    match (it.next(), it.next()) {
        // RFC 9112 section 3.2: HTTP/1.1 needs a Host or an absolute target.
        (None, _) => version == http::Version::HTTP_11 && uri.authority().is_none(),
        (Some(v), None) => uri.authority().is_none() && parse_host(v).is_none(),
        _ => true,
    }
}

/// `host[:port]` of an authority, without userinfo.
fn host_value(a: &http::uri::Authority) -> Option<HeaderValue> {
    let s = match a.port() {
        Some(p) => format!("{}:{p}", a.host()),
        None => a.host().to_string(),
    };
    HeaderValue::from_str(&s).ok()
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

    // Everything that needs no upstream is rejected before admission
    // (`try_acquire` may hand this request the breaker's single half-open
    // probe), in this order: bad path, ambiguous route (both on the raw
    // path; `ambiguous_route` relies on `bad_path` having run), Host,
    // upgrade, declared body size.
    if bad_path(&path) || ambiguous_route(&snapshot, &path) {
        return plain(400, b"bad path");
    }
    if bad_host(req.headers(), req.uri(), req.version()) {
        return plain(400, b"bad host");
    }
    if upgrade {
        return plain(501, b"protocol upgrades are not supported");
    }
    if let Some(max) = limits.max_request_body_bytes {
        if declared_len(&req).is_some_and(|len| len > max) {
            return plain(413, b"payload too large");
        }
    }

    // `lookup` takes the raw path and normalises it for matching only; it
    // ignores breaker state and never falls through to a shorter prefix.
    let Some(route) = snapshot.lookup(&path) else {
        return plain(404, b"no route");
    };
    let rewrite_host = route.rewrite_host;
    let upstream = route.upstream.clone();
    // The last gate. From here on this request holds an admission (maybe
    // the half-open probe) and reports it exactly once through `ticket`;
    // every early return, `?` or dropped future releases it.
    let Some(admission) = upstream.try_acquire() else {
        return plain(503, b"upstream unavailable");
    };
    let ticket = Ticket::new(upstream.clone(), admission);

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
    set_host(&mut parts.headers, &parts.uri, &upstream.uri, rewrite_host);
    parts.uri = http::Uri::from_parts(up_parts)?;
    // hyper-util's legacy Client rejects an HTTP/2-versioned request on an
    // HTTP/1 connection; upstreams here are plain http://, so downgrade.
    parts.version = http::Version::HTTP_11;
    set_forwarded(&mut parts.headers, peer_ip);

    // host:port, so two upstreams on one host stay distinct series.
    let host = upstream.name.clone();
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
                // No verdict: not `failure` (the upstream is not at fault)
                // and not `success` (a client must not close an open breaker
                // by aborting an upload).
                ticket.release();
                return plain(status, msg);
            }
            tracing::warn!(upstream = %host, error = %e, "upstream request failed");
            // An upstream that drops the connection after the client stalled
            // its upload for `stall` (now or earlier in the request) may be
            // reacting to that stall: answer 502, blame no one.
            if client_state.stalled_during_request() {
                ticket.release();
            } else {
                ticket.failure();
            }
            return upstream_error(502, b"bad gateway", host);
        }
        None => {
            ticket.failure();
            return upstream_error(504, b"upstream timeout", host);
        }
    };

    let status = resp.status();
    // Health is judged on the response head; the body then streams with no
    // deadline. Only gateway-class 5xx mean "this upstream is unhealthy": a
    // 500 is one request's bug and must not blackhole the route. A gateway
    // answering 502–504 after the client stalled its upload is passing on
    // its backend's reaction to that stall: no verdict (and never success).
    if matches!(status.as_u16(), 502..=504) {
        if client_state.stalled_during_request() {
            ticket.release();
        } else {
            ticket.failure();
        }
    } else {
        ticket.success();
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
    use super::{bad_host, set_host, stall_threshold, strip_hop_by_hop, wants_upgrade};
    use http::{HeaderMap, HeaderValue};
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
    fn host_policy() {
        let up: http::Uri = "http://10.0.0.5:8001".parse().unwrap();
        let get = |h: &HeaderMap, n: &str| h.get(n).unwrap().to_str().unwrap().to_string();

        // Origin-form: the Host header is kept; a client XFH is replaced.
        let mut h = HeaderMap::new();
        h.insert("host", HeaderValue::from_static("app.example"));
        h.insert("x-forwarded-host", HeaderValue::from_static("evil.example"));
        set_host(&mut h, &"/x".parse().unwrap(), &up, false);
        assert_eq!(get(&h, "host"), "app.example");
        assert_eq!(get(&h, "x-forwarded-host"), "app.example");

        // A request-target authority (h2 :authority, absolute-form) wins.
        let mut h = HeaderMap::new();
        h.insert("host", HeaderValue::from_static("ignored.example"));
        let abs: http::Uri = "https://api.example:8443/x".parse().unwrap();
        set_host(&mut h, &abs, &up, false);
        assert_eq!(get(&h, "host"), "api.example:8443");

        // rewrite_host: upstream authority as Host, client host in XFH.
        set_host(&mut h, &abs, &up, true);
        assert_eq!(get(&h, "host"), "10.0.0.5:8001");
        assert_eq!(get(&h, "x-forwarded-host"), "api.example:8443");

        // Userinfo never reaches a header.
        let mut h = HeaderMap::new();
        set_host(
            &mut h,
            &"http://u:p@a.example/x".parse().unwrap(),
            &up,
            false,
        );
        assert_eq!(get(&h, "host"), "a.example");

        // No host at all: no Host header and no XFH.
        let mut h = HeaderMap::new();
        set_host(&mut h, &"/x".parse().unwrap(), &up, false);
        assert!(h.get("host").is_none() && h.get("x-forwarded-host").is_none());
    }

    #[test]
    fn host_validation() {
        const V: http::Version = http::Version::HTTP_11;
        let h = |vals: &[&str]| {
            let mut m = HeaderMap::new();
            for v in vals {
                m.append("host", HeaderValue::from_str(v).unwrap());
            }
            m
        };
        for bad in [
            "a.example, b.example",
            "u@x",
            "x/y",
            "",
            "a:b",
            "x:99999",
            "x:",
            "*",
            "[::1]:",
        ] {
            assert!(bad_host(&h(&[bad]), &"/".parse().unwrap(), V), "{bad:?}");
        }
        assert!(bad_host(
            &h(&["a.example", "b.example"]),
            &"/".parse().unwrap(),
            V
        ));
        for ok in [
            "a.example",
            "a.example:8443",
            "x:8443",
            "[::1]",
            "[::1]:8443",
            "LOCALHOST",
        ] {
            assert!(!bad_host(&h(&[ok]), &"/".parse().unwrap(), V), "{ok:?}");
        }
        // No Host: an error on HTTP/1.1 only.
        assert!(bad_host(&HeaderMap::new(), &"/".parse().unwrap(), V));
        assert!(!bad_host(
            &HeaderMap::new(),
            &"/".parse().unwrap(),
            http::Version::HTTP_10
        ));
        assert!(!bad_host(
            &HeaderMap::new(),
            &"http://a.example/".parse().unwrap(),
            V
        ));
        // With a URI authority the header is not used, so it is not judged.
        assert!(!bad_host(
            &h(&["u@x"]),
            &"http://a.example/".parse().unwrap(),
            V
        ));
        assert!(bad_host(
            &h(&["a", "b"]),
            &"http://a.example/".parse().unwrap(),
            V
        ));
        // The validated value is what gets forwarded.
        let mut m = h(&["[::1]:8443"]);
        set_host(
            &mut m,
            &"/x".parse().unwrap(),
            &"http://u:1".parse().unwrap(),
            false,
        );
        assert_eq!(m.get("x-forwarded-host").unwrap(), "[::1]:8443");
    }

    #[test]
    fn connection_cannot_delete_host() {
        let mut m = HeaderMap::new();
        m.insert("host", HeaderValue::from_static("a.example"));
        m.insert("connection", HeaderValue::from_static("Host, x-other"));
        m.insert("x-other", HeaderValue::from_static("1"));
        strip_hop_by_hop(&mut m);
        assert!(m.get("host").is_some() && m.get("x-other").is_none());
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
}
