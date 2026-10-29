//! Sample upstream service for the ferryman-edge demo.
//!
//! This is what one of *your* backends looks like behind the proxy.
//!
//! # Trust model
//!
//! The proxy authenticates the client (mTLS), validates the JWT, and then
//! stamps the JWT `sub` into the `x-ferryman-tenant` request header,
//! discarding any value the client sent. This service therefore reads the
//! header as *the* caller identity and does no auth of its own.
//!
//! That is only safe because of where this process listens: it must be
//! reachable **only** from the proxy (loopback, a private network, a
//! compose-internal network). If a client could reach this port directly it
//! could send `x-ferryman-tenant: admin` itself. The proxy also replaces
//! `x-forwarded-for` with the real peer IP and sets `x-forwarded-proto`, so
//! those are equally trustworthy here and equally spoofable if you expose
//! the port.
//!
//! # Endpoints
//!
//! * `GET /health`: `200 ok`. The proxy's active health checker probes
//!   this to drive its circuit breaker.
//! * `GET <anything>/slow?ms=N`: sleeps `N` ms (capped at 10 000), then
//!   echoes. Used to show graceful shutdown finishing an in-flight request.
//! * `GET <anything>/sse?secs=N`: `text/event-stream`, one `data: tick i` per
//!   second for `i` in `0..=N` (N <= 600).
//! * everything else: `200` JSON echo of what this service saw.
//!
//! The request body is streamed and counted, never buffered whole.

use axum::extract::{Request, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use clap::Parser;
use http_body_util::channel::Channel;
use http_body_util::BodyExt;
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

#[derive(Parser)]
#[command(about = "ferryman-edge demo upstream service")]
struct Args {
    /// Service name, echoed back in every response.
    #[arg(long)]
    name: String,
    /// Address to listen on. Keep this private: see the module docs.
    #[arg(long, default_value = "127.0.0.1:9101")]
    bind: SocketAddr,
}

/// Upper bound for `/slow?ms=N` so a typo cannot pin a connection forever.
const MAX_SLOW_MS: u64 = 10_000;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let app = Router::new()
        .route("/health", get(|| async { "ok" }))
        .fallback(echo)
        .with_state(Arc::<str>::from(args.name.as_str()));

    // tokio's `bind` sets SO_REUSEADDR on Unix, so the breaker scenario can
    // restart this service on the same port right after killing it.
    let listener = tokio::net::TcpListener::bind(args.bind).await?;
    // The demo driver waits for this exact line before starting the proxy.
    println!(
        "backend {} listening on {}",
        args.name,
        listener.local_addr()?
    );

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

/// Upper bound for `/sse?secs=N`.
const MAX_SSE_SECS: u64 = 600;

async fn echo(state: State<Arc<str>>, req: Request) -> Response {
    if req.uri().path().ends_with("/sse") {
        return sse(req.uri().query());
    }
    match echo_json(state, req).await {
        Ok(json) => json.into_response(),
        Err(e) => e.into_response(),
    }
}

/// A slow event stream, like an LLM token stream.
fn sse(query: Option<&str>) -> Response {
    let secs = query
        .and_then(|q| q.split('&').find_map(|kv| kv.strip_prefix("secs=")))
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(1)
        .min(MAX_SSE_SECS);
    let (mut tx, body) = Channel::<axum::body::Bytes, std::convert::Infallible>::new(1);
    tokio::spawn(async move {
        for i in 0..=secs {
            if tx
                .send_data(format!("data: tick {i}\n\n").into())
                .await
                .is_err()
            {
                return;
            }
            if i < secs {
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        }
    });
    Response::builder()
        .header(header::CONTENT_TYPE, "text/event-stream")
        .body(axum::body::Body::new(body))
        .expect("static response")
}

async fn echo_json(
    State(service): State<Arc<str>>,
    req: Request,
) -> Result<Json<Value>, (StatusCode, &'static str)> {
    let (parts, mut body) = req.into_parts();

    if parts.uri.path().ends_with("/slow") {
        let ms = parts
            .uri
            .query()
            .and_then(|q| q.split('&').find_map(|kv| kv.strip_prefix("ms=")))
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(0)
            .min(MAX_SLOW_MS);
        // Lets the demo know the request is in flight before it signals the proxy.
        println!("slow request started");
        tokio::time::sleep(Duration::from_millis(ms)).await;
    }

    // Count the body frame by frame; a large upload never sits in memory.
    let mut body_bytes = 0usize;
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|_| (StatusCode::BAD_REQUEST, "body error"))?;
        if let Some(data) = frame.data_ref() {
            body_bytes += data.len();
        }
    }

    let header_str = |name: &str| {
        parts
            .headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned)
    };
    Ok(Json(json!({
        "service": &*service,
        "method": parts.method.as_str(),
        "path": parts.uri.path(),
        // Trustworthy only because the proxy overwrote it: see module docs.
        "tenant": header_str("x-ferryman-tenant"),
        // The client's host, as the proxy preserves it (E1).
        "host": header_str(header::HOST.as_str()),
        "forwarded_host": header_str("x-forwarded-host"),
        "forwarded_for": header_str("x-forwarded-for"),
        "forwarded_proto": header_str("x-forwarded-proto"),
        "body_bytes": body_bytes,
    })))
}

/// Resolves on SIGTERM or Ctrl-C so in-flight requests can finish.
async fn shutdown_signal() {
    use tokio::signal::unix::{signal, SignalKind};
    let mut term = signal(SignalKind::terminate()).expect("install SIGTERM handler");
    tokio::select! {
        _ = term.recv() => {}
        _ = tokio::signal::ctrl_c() => {}
    }
}
