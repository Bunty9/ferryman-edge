//! The narrated walkthrough behind `edge-demo run`.
//!
//! One `async fn` per feature. Each records `check`s (kept going within a
//! scenario) and every scenario uses its own JWT `sub`: the rate limiter is
//! keyed by `sub`, so sharing one would cause spurious 429s. Only the
//! rate-limit scenario deliberately bursts.

use crate::client::{self, mtls_client, peer_cert_sha256, raw_http1};
use crate::pki::Pki;
use crate::procs::{eventually, free_port, spawn_backend, spawn_proxy, Child};
use crate::proxy_config::{self, Topology};
use crate::tokens::{self, TokenSpec};
use anyhow::Context;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

/// What the sample backend saw (see `backend.rs`).
#[derive(Deserialize)]
struct Echo {
    service: String,
    path: String,
    tenant: Option<String>,
    host: Option<String>,
    forwarded_host: Option<String>,
    forwarded_for: Option<String>,
    forwarded_proto: Option<String>,
    body_bytes: usize,
}

/// Cheap-to-clone handle for sending authenticated requests, so polling
/// closures can own one.
#[derive(Clone)]
struct Edge {
    pki: Pki,
    client: reqwest::Client,
    addr: SocketAddr,
}

impl Edge {
    fn url(&self, path: &str) -> String {
        format!("https://{}{path}", self.addr)
    }

    fn token(&self, sub: &str) -> anyhow::Result<String> {
        tokens::mint(&self.pki, &TokenSpec::valid(sub))
    }

    async fn get(&self, path: &str, sub: &str) -> anyhow::Result<reqwest::Response> {
        Ok(self
            .client
            .get(self.url(path))
            .bearer_auth(self.token(sub)?)
            .send()
            .await?)
    }

    async fn status(&self, path: &str, sub: &str) -> anyhow::Result<u16> {
        Ok(self.get(path, sub).await?.status().as_u16())
    }

    async fn echo(&self, path: &str, sub: &str) -> anyhow::Result<Echo> {
        let resp = self.get(path, sub).await?;
        let status = resp.status();
        anyhow::ensure!(status.is_success(), "GET {path} returned {status}");
        Ok(resp.json().await?)
    }
}

/// Everything the scenarios share.
struct Demo {
    edge: Edge,
    dir: PathBuf,
    topo: Topology,
    config: PathBuf,
    metrics: SocketAddr,
    backend_addrs: BTreeMap<&'static str, SocketAddr>,
    // Dropping a `Child` kills it, so an early `?`, a failed run or a panic
    // cannot orphan processes.
    backends: BTreeMap<&'static str, Child>,
    proxy: Child,
    passed: usize,
    failed: usize,
}

impl Demo {
    async fn start(dir: PathBuf) -> anyhow::Result<Demo> {
        let pki = Pki::generate(&dir)?;

        // Distinct free ports: proxy, metrics and three backends.
        let mut ports = Vec::new();
        while ports.len() < 5 {
            let p = free_port()?;
            if !ports.contains(&p) {
                ports.push(p);
            }
        }
        let (proxy_addr, metrics) = (ports[0], ports[1]);
        let backend_addrs: BTreeMap<&'static str, SocketAddr> = [
            ("orders", ports[2]),
            ("inventory", ports[3]),
            ("payments", ports[4]),
        ]
        .into();

        let mut backends = BTreeMap::new();
        for (name, addr) in &backend_addrs {
            backends.insert(*name, spawn_backend(name, *addr, &dir).await?);
        }

        // `payments` runs from the start but is only routed by the reload scenario.
        let topo = Topology {
            routes: vec![
                ("/orders".into(), backend_addrs["orders"], None),
                ("/inventory".into(), backend_addrs["inventory"], Some(2)),
            ],
            tenant_rps: 5,
            health_interval_secs: 1,
            default_cooldown_secs: 2,
        };
        let config = dir.join("ferryman.toml");
        proxy_config::write(&pki, &topo, &config)?;
        let proxy = spawn_proxy(&config, proxy_addr, metrics, &dir).await?;

        let edge = Edge {
            client: mtls_client(&pki, false)?,
            pki,
            addr: proxy_addr,
        };
        Ok(Demo {
            edge,
            dir,
            topo,
            config,
            metrics,
            backend_addrs,
            backends,
            proxy,
            passed: 0,
            failed: 0,
        })
    }

    fn scenario(&self, name: &str) {
        println!("\n▶ {name}");
    }

    /// Record one expectation and keep going.
    fn check(&mut self, name: &str, ok: bool, detail: impl std::fmt::Display) {
        if ok {
            self.passed += 1;
            println!("  ✓ {name}");
        } else {
            self.failed += 1;
            println!("  ✗ {name}: {detail}");
        }
    }

    fn check_status(&mut self, name: &str, got: u16, want: u16) {
        self.check(name, got == want, format!("expected {want}, got {got}"));
    }

    async fn metrics_text(&self) -> anyhow::Result<String> {
        // Plain http, and a separate port from the mTLS listener: scrapers
        // need no client certificate.
        let url = format!("http://{}/metrics", self.metrics);
        Ok(reqwest::get(url).await?.text().await?)
    }
}

/// Run all scenarios. `Ok(false)` means at least one check failed.
pub async fn run(dir: PathBuf, keep: bool) -> anyhow::Result<bool> {
    // Install the handlers before spawning anything, and race *startup* as
    // well as the scenarios against them: Ctrl-C / SIGTERM then return
    // normally instead of killing us, and dropping the cancelled future drops
    // every `Child` spawned so far, whose `Drop` kills it. SIGTERM matters
    // for `timeout` and CI cancellation.
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let stop = async move {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => "interrupted",
            _ = term.recv() => "terminated",
        }
    };
    tokio::pin!(stop);

    let mut d = tokio::select! {
        r = Demo::start(dir) => r?,
        why = &mut stop => anyhow::bail!(why),
    };
    println!("proxy on {} (log: {})", d.edge.addr, d.proxy.log.display());
    let pids: Vec<u32> = d
        .backends
        .values()
        .map(|c| c.pid)
        .chain([d.proxy.pid])
        .collect();

    tokio::select! {
        r = all_scenarios(&mut d) => r?,
        why = &mut stop => anyhow::bail!(why),
    };

    if keep {
        keep_running(&mut d).await?;
    }
    let (passed, mut failed) = (d.passed, d.failed);
    let (dir, mut leftover) = (d.dir.clone(), false);
    drop(d);

    // Children are killed on drop; confirm none of ours survived
    // (`kill -0` succeeds only while the process exists).
    for pid in pids {
        let alive = std::process::Command::new("kill")
            .args(["-0", &pid.to_string()])
            .stderr(std::process::Stdio::null())
            .status()?
            .success();
        leftover |= alive;
    }
    if leftover {
        println!("\n  ✗ child processes left behind");
        failed += 1;
    }
    if failed == 0 {
        println!("\n{passed} checks passed (logs in {})", dir.display());
    } else {
        println!(
            "\n{passed} checks passed, {failed} FAILED (logs in {})",
            dir.display()
        );
    }
    Ok(failed == 0)
}

async fn all_scenarios(d: &mut Demo) -> anyhow::Result<()> {
    // The first health probe can race startup; wait for a clean first request.
    let edge = d.edge.clone();
    eventually(Duration::from_secs(10), "proxy to serve /orders", || {
        let edge = edge.clone();
        async move { Ok(edge.status("/orders/warmup", "tenant-warmup").await? == 200) }
    })
    .await?;

    mtls(d).await?;
    jwt(d).await?;
    identity(d).await?;
    routing(d).await?;
    bodies(d).await?;
    rate_limit(d).await?;
    circuit_breaker(d).await?;
    reload_routes(d).await?;
    reload_cert(d).await?;
    metrics(d).await?;
    graceful_shutdown(d).await?;
    Ok(())
}

// 1 ---------------------------------------------------------------------

async fn mtls(d: &mut Demo) -> anyhow::Result<()> {
    d.scenario("mTLS: the proxy only talks to clients holding a cert from its CA");
    let sub = "tenant-mtls";
    let resp = d.edge.get("/orders/1", sub).await?;
    let (status, version) = (resp.status().as_u16(), resp.version());
    d.check_status("valid client cert, HTTP/2", status, 200);
    d.check(
        "negotiated HTTP/2 via ALPN",
        version == reqwest::Version::HTTP_2,
        format!("{version:?}"),
    );

    let h1 = Edge {
        client: mtls_client(&d.edge.pki, true)?,
        ..d.edge.clone()
    };
    let resp = h1.get("/orders/1", sub).await?;
    d.check(
        "valid client cert, HTTP/1.1",
        resp.status() == 200 && resp.version() == reqwest::Version::HTTP_11,
        resp.status(),
    );

    // A valid token does not help without a certificate: TLS fails first.
    // Each refusal must yield no response and be counted by the proxy as a
    // failed TLS handshake.
    let token = d.edge.token(sub)?;
    let none = client::client_without_cert(&d.edge.pki)?;
    let rogue = client::rogue_client(&d.edge.pki)?;
    for (name, client) in [
        ("no client cert", none),
        ("cert from an untrusted CA", rogue),
    ] {
        let before = handshake_failures(d).await?;
        let r = client
            .get(d.edge.url("/orders/1"))
            .bearer_auth(&token)
            .send()
            .await;
        match r {
            Ok(resp) => d.check(
                &format!("{name} is refused"),
                false,
                format!("got {}", resp.status()),
            ),
            Err(e) => {
                let chain = error_chain(&e);
                // How the client words the failure varies with timing (TLS 1.3
                // finishes the client's handshake before the server checks its
                // certificate, so it may see the alert or only a closed
                // connection). It must not be a timeout; the server-side
                // counter below is what proves it was a handshake rejection.
                d.check(
                    &format!("{name} is refused (no response)"),
                    !e.is_timeout(),
                    &chain,
                );
                let metrics = d.metrics;
                let r = eventually(
                    Duration::from_secs(3),
                    "handshake failure counter",
                    || async move {
                        let text = reqwest::get(format!("http://{metrics}/metrics"))
                            .await?
                            .text()
                            .await?;
                        Ok(
                            counter(&text, "ferryman_tls_handshake_failures_total").unwrap_or(0.0)
                                > before,
                        )
                    },
                )
                .await;
                d.check(
                    &format!("...and counted in ferryman_tls_handshake_failures_total ({name})"),
                    r.is_ok(),
                    format!("{r:?}"),
                );
            }
        }
    }
    Ok(())
}

async fn handshake_failures(d: &Demo) -> anyhow::Result<f64> {
    let text = d.metrics_text().await?;
    Ok(counter(&text, "ferryman_tls_handshake_failures_total").unwrap_or(0.0))
}

/// Value of an unlabelled counter/gauge line in Prometheus text.
fn counter(text: &str, name: &str) -> Option<f64> {
    text.lines()
        .find_map(|l| l.strip_prefix(name)?.strip_prefix(' ')?.parse().ok())
}

/// Every message in an error's `source()` chain, lowercased.
fn error_chain(e: &dyn std::error::Error) -> String {
    let mut out = vec![e.to_string()];
    let mut cur = e.source();
    while let Some(c) = cur {
        out.push(c.to_string());
        cur = c.source();
    }
    out.join(": ").to_lowercase()
}

// 2 ---------------------------------------------------------------------

async fn jwt(d: &mut Demo) -> anyhow::Result<()> {
    d.scenario("JWT: signature, expiry, not-before, issuer and audience are all enforced");
    let sub = "tenant-jwt";
    let edge = d.edge.clone();
    let url = edge.url("/orders/1");
    let send = |auth: Option<String>| {
        let mut req = edge.client.get(&url);
        if let Some(a) = auth {
            req = req.header("authorization", a);
        }
        req.send()
    };

    let resp = send(None).await?;
    let challenge = resp
        .headers()
        .get("www-authenticate")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let status = resp.status().as_u16();
    d.check_status("no Authorization header", status, 401);
    d.check(
        "401 carries `www-authenticate: Bearer`",
        challenge.as_deref() == Some("Bearer"),
        format!("{challenge:?}"),
    );

    let bad_tokens: Vec<(&str, String)> = {
        let mint = |tweak: &dyn Fn(&mut TokenSpec)| {
            let mut spec = TokenSpec::valid(sub);
            tweak(&mut spec);
            tokens::mint(&edge.pki, &spec)
        };
        vec![
            ("garbage token", "not.a.jwt".to_string()),
            // Beyond the proxy's 60 s clock-skew leeway.
            ("expired token", mint(&|s| s.ttl_secs = -120)?),
            (
                "wrong audience",
                mint(&|s| s.aud = Some("some-other-service".into()))?,
            ),
            (
                "wrong issuer",
                mint(&|s| s.iss = Some("https://evil.example".into()))?,
            ),
            (
                "not-before in the future",
                mint(&|s| s.nbf_offset = Some(600))?,
            ),
            ("signed by an untrusted key", mint(&|s| s.other_key = true)?),
        ]
    };
    for (name, token) in bad_tokens {
        let status = send(Some(format!("Bearer {token}")))
            .await?
            .status()
            .as_u16();
        d.check_status(name, status, 401);
    }

    let status = send(Some(format!("Bearer {}", d.edge.token(sub)?)))
        .await?
        .status()
        .as_u16();
    d.check_status("valid token", status, 200);
    Ok(())
}

// 3 ---------------------------------------------------------------------

async fn identity(d: &mut Demo) -> anyhow::Result<()> {
    d.scenario("Identity propagation: the backend sees the proxy's view, not the client's");
    let sub = "acme-corp";

    // h2: the client lies about who it is and where it came from.
    let resp = d
        .edge
        .client
        .get(d.edge.url("/orders/1"))
        .bearer_auth(d.edge.token(sub)?)
        .header("x-ferryman-tenant", "admin")
        .header("x-forwarded-for", "6.6.6.6")
        .header("x-forwarded-host", "evil.example")
        .send()
        .await?;
    let e: Echo = resp.json().await?;
    d.check(
        "tenant is the JWT sub, not the client's header",
        e.tenant.as_deref() == Some(sub),
        format!("{:?}", e.tenant),
    );
    let client_host = d.edge.addr.to_string();
    d.check(
        "Host is the one the client used (h2 :authority), not the upstream's",
        e.host.as_deref() == Some(&client_host),
        format!("{:?}", e.host),
    );
    d.check(
        "x-forwarded-host carries the same host",
        e.forwarded_host.as_deref() == Some(&client_host), // not the forged one
        format!("{:?}", e.forwarded_host),
    );
    d.check(
        "x-forwarded-for is the peer IP, not the client's claim",
        e.forwarded_for.as_deref() == Some("127.0.0.1"),
        format!("{:?}", e.forwarded_for),
    );
    d.check(
        "x-forwarded-proto is https",
        e.forwarded_proto.as_deref() == Some("https"),
        format!("{:?}", e.forwarded_proto),
    );

    // HTTP/1.1: try to make the proxy strip the tenant header as hop-by-hop.
    let h1 = mtls_client(&d.edge.pki, true)?;
    let e: Echo = h1
        .get(d.edge.url("/orders/1"))
        .bearer_auth(d.edge.token(sub)?)
        .header("x-ferryman-tenant", "admin")
        .header("connection", "x-ferryman-tenant")
        .send()
        .await?
        .json()
        .await?;
    d.check(
        "`Connection: x-ferryman-tenant` cannot delete the stamped tenant",
        e.tenant.as_deref() == Some(sub),
        format!("{:?}", e.tenant),
    );
    Ok(())
}

// 4 ---------------------------------------------------------------------

async fn routing(d: &mut Demo) -> anyhow::Result<()> {
    d.scenario("Routing: longest prefix on a path-segment boundary");
    let sub = "tenant-routing";
    let e = d.edge.echo("/orders/42", sub).await?;
    d.check(
        "/orders/42 goes to orders, path unchanged",
        e.service == "orders" && e.path == "/orders/42",
        format!("{}:{}", e.service, e.path),
    );
    let e = d.edge.echo("/inventory/sku-1", sub).await?;
    d.check(
        "/inventory/sku-1 goes to inventory",
        e.service == "inventory",
        &e.service,
    );

    let s = d.edge.status("/ordersX", sub).await?;
    d.check_status("/ordersX is not under /orders", s, 404);
    let s = d.edge.status("/nope", sub).await?;
    d.check_status("unknown prefix", s, 404);

    // `..` would let /orders/.. match the orders route and be resolved by the
    // backend into another service's path. Sent raw: reqwest would normalise it.
    let req = format!(
        "GET /orders/../inventory HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {}\r\nConnection: close\r\n\r\n",
        d.edge.token("tenant-routing-raw")?
    );
    let line = raw_http1(&d.edge.pki, d.edge.addr, req.as_bytes()).await?;
    d.check(
        "/orders/../inventory is rejected",
        line.contains(" 400"),
        line,
    );

    // The proxy can't splice a WebSocket, so it says so instead of
    // forwarding a mangled GET.
    let req = format!(
        "GET /orders/ws HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n",
        d.edge.token("tenant-routing-ws")?
    );
    let line = raw_http1(&d.edge.pki, d.edge.addr, req.as_bytes()).await?;
    d.check("a WebSocket upgrade gets 501", line.contains(" 501"), line);
    Ok(())
}

// 5 ---------------------------------------------------------------------

async fn bodies(d: &mut Demo) -> anyhow::Result<()> {
    d.scenario("Bodies: streamed both ways, no size cap by default");
    let sub = "tenant-bodies";
    let edge = d.edge.clone();
    let token = edge.token(sub)?;
    // A `len`-byte body: real JSON for the small case, opaque bytes otherwise.
    let post = |len: usize, json: bool| {
        let (body, ctype) = if json {
            let filler = "a".repeat(len - r#"{"data":""}"#.len());
            (
                format!(r#"{{"data":"{filler}"}}"#).into_bytes(),
                "application/json",
            )
        } else {
            (vec![b'a'; len], "application/octet-stream")
        };
        edge.client
            .post(edge.url("/orders/upload"))
            .bearer_auth(&token)
            .header("content-type", ctype)
            .body(body)
            .send()
    };

    for (name, len, json) in [
        ("64 KiB JSON", 64 << 10, true),
        ("6 MiB binary", 6 << 20, false),
        ("9 MiB binary", 9 << 20, false),
    ] {
        let resp = post(len, json).await?;
        let status = resp.status().as_u16();
        let e: Echo = resp.json().await?;
        d.check(
            &format!("{name} upload arrives whole"),
            status == 200 && e.body_bytes == len,
            format!("{status}, backend counted {}", e.body_bytes),
        );
    }
    Ok(())
}

// 6 ---------------------------------------------------------------------

async fn rate_limit(d: &mut Demo) -> anyhow::Result<()> {
    d.scenario("Rate limiting: per tenant, keyed by JWT sub (5 rps, burst 5)");
    let (burst, other) = ("tenant-burst", "tenant-other");
    let token = d.edge.token(burst)?;

    // Six requests at once: the burst is 5, so exactly one is refused however
    // the tokens refill in between (at 5 rps a token returns every 200 ms).
    let calls: Vec<_> = (0..6)
        .map(|_| {
            let (edge, token) = (d.edge.clone(), token.clone());
            tokio::spawn(async move {
                let resp = edge
                    .client
                    .get(edge.url("/orders/1"))
                    .bearer_auth(token)
                    .send()
                    .await?;
                let retry = resp
                    .headers()
                    .get("retry-after")
                    .and_then(|v| v.to_str().ok())
                    .map(str::to_owned);
                anyhow::Ok((resp.status().as_u16(), retry))
            })
        })
        .collect();
    let mut results = Vec::new();
    for c in calls {
        results.push(c.await??);
    }
    let ok = results.iter().filter(|(s, _)| *s == 200).count();
    let limited: Vec<_> = results.iter().filter(|(s, _)| *s == 429).collect();
    d.check(
        "6 concurrent requests: 5 pass, 1 is limited",
        ok == 5 && limited.len() == 1,
        format!("{results:?}"),
    );
    d.check(
        "429 carries `retry-after: 1`",
        limited.iter().all(|(_, r)| r.as_deref() == Some("1")),
        format!("{limited:?}"),
    );
    let s = d.edge.status("/orders/1", other).await?;
    d.check_status("another tenant is unaffected", s, 200);
    Ok(())
}

// 7 ---------------------------------------------------------------------

/// Parse `name{upstream="ADDR"} VALUE` out of Prometheus text.
fn gauge(text: &str, name: &str, upstream: SocketAddr) -> Option<f64> {
    let label = format!("upstream=\"{upstream}\"");
    text.lines()
        .filter(|l| l.starts_with(name) && l[name.len()..].starts_with('{') && l.contains(&label))
        .find_map(|l| l.rsplit(' ').next()?.parse().ok())
}

async fn circuit_breaker(d: &mut Demo) -> anyhow::Result<()> {
    d.scenario("Circuit breaker + health checks: a dead backend is isolated, then recovers");
    let addr = d.backend_addrs["inventory"];
    // Unique sub per poll: the limiter is 5 rps per sub and we poll faster.
    let poll_edge = d.edge.clone();
    let mut n = 0;
    let mut inventory_status = move || {
        n += 1;
        let (edge, sub) = (poll_edge.clone(), format!("tenant-breaker-{n}"));
        async move { edge.status("/inventory/x", &sub).await }
    };

    d.backends
        .get_mut("inventory")
        .context("inventory backend")?
        .kill();
    let first = inventory_status().await?;
    d.check(
        "first request after the kill fails fast",
        first == 502 || first == 503,
        format!("got {first}"),
    );

    let r = eventually(Duration::from_secs(5), "breaker to open (503)", || {
        let next = inventory_status();
        async move { Ok(next.await? == 503) }
    })
    .await;
    d.check(
        "breaker opens: /inventory answers 503",
        r.is_ok(),
        format!("{r:?}"),
    );
    let s = d.edge.status("/orders/x", "tenant-breaker-orders").await?;
    d.check_status("/orders is unaffected", s, 200);

    let text = d.metrics_text().await?;
    let g = gauge(&text, "ferryman_circuit_state", addr);
    d.check(
        "ferryman_circuit_state is 1 (open)",
        g == Some(1.0),
        format!("{g:?}"),
    );

    d.backends
        .insert("inventory", spawn_backend("inventory", addr, &d.dir).await?);
    let r = eventually(
        Duration::from_secs(10),
        "inventory to serve 200 again",
        || {
            let next = inventory_status();
            async move { Ok(next.await? == 200) }
        },
    )
    .await;
    d.check(
        "after restart on the same port, /inventory is 200 again",
        r.is_ok(),
        format!("{r:?}"),
    );
    let metrics = d.metrics;
    let r = eventually(
        Duration::from_secs(5),
        "circuit gauge to return to 0",
        || async move {
            let text = reqwest::get(format!("http://{metrics}/metrics"))
                .await?
                .text()
                .await?;
            Ok(gauge(&text, "ferryman_circuit_state", addr) == Some(0.0))
        },
    )
    .await;
    d.check(
        "ferryman_circuit_state back to 0 (closed)",
        r.is_ok(),
        format!("{r:?}"),
    );
    Ok(())
}

// 8 ---------------------------------------------------------------------

async fn reload_routes(d: &mut Demo) -> anyhow::Result<()> {
    d.scenario("Hot reload (routes): SIGUSR1 swaps the table, no restart");
    let s = d
        .edge
        .status("/payments/p1", "tenant-reload-routes")
        .await?;
    d.check_status("/payments is unrouted at first", s, 404);

    d.topo
        .routes
        .push(("/payments".into(), d.backend_addrs["payments"], None));
    proxy_config::write(&d.edge.pki, &d.topo, &d.config)?;
    d.proxy.signal("USR1")?;

    // The signal returns before the swap: poll.
    let edge = d.edge.clone();
    let r = eventually(Duration::from_secs(5), "/payments to be routed", || {
        let edge = edge.clone();
        async move {
            Ok(edge
                .echo("/payments/p1", "tenant-reload-payments")
                .await?
                .service
                == "payments")
        }
    })
    .await;
    d.check(
        "/payments served by the payments backend after reload",
        r.is_ok(),
        format!("{r:?}"),
    );
    let s = d.edge.status("/orders/1", "tenant-reload-routes").await?;
    d.check_status("/orders still fine", s, 200);
    Ok(())
}

// 9 ---------------------------------------------------------------------

async fn reload_cert(d: &mut Demo) -> anyhow::Result<()> {
    d.scenario("Hot reload (certificate): renewal without dropping anyone");
    let sub = "tenant-reload-cert";
    let old_client = mtls_client(&d.edge.pki, false)?;
    let old = Edge {
        client: old_client,
        ..d.edge.clone()
    };
    let s = old.status("/orders/1", sub).await?;
    d.check_status("client connected before the rotation", s, 200);

    let before = peer_cert_sha256(&d.edge.pki, d.edge.addr).await?;
    d.edge.pki.rotate_server_cert()?;
    d.proxy.signal("USR1")?;

    let pki = d.edge.pki.clone();
    let addr = d.edge.addr;
    let r = eventually(Duration::from_secs(5), "the new server certificate", || {
        let (pki, before) = (pki.clone(), before.clone());
        async move { Ok(peer_cert_sha256(&pki, addr).await? != before) }
    })
    .await;
    d.check(
        "new handshakes present the rotated certificate",
        r.is_ok(),
        format!("{r:?}"),
    );

    let fresh = Edge {
        client: mtls_client(&d.edge.pki, false)?,
        ..d.edge.clone()
    };
    let s = fresh.status("/orders/1", sub).await?;
    d.check_status("a fresh client trusts the new leaf (same CA)", s, 200);
    let s = old.status("/orders/1", sub).await?;
    d.check_status("the client built before rotation still works", s, 200);
    Ok(())
}

// 10 --------------------------------------------------------------------

async fn metrics(d: &mut Demo) -> anyhow::Result<()> {
    d.scenario("Metrics: Prometheus text on its own port, bounded label sets");
    let text = d.metrics_text().await?;
    for name in [
        "ferryman_requests_total",
        "ferryman_auth_failures_total{reason=\"missing\"}",
        "ferryman_ratelimited_total",
        "ferryman_tls_handshake_seconds",
        "ferryman_circuit_state",
        "ferryman_upstream_alive",
    ] {
        d.check(
            &format!("exposes {name}"),
            text.contains(name),
            "missing from /metrics",
        );
    }
    println!("  ferryman_requests_total:");
    for line in text
        .lines()
        .filter(|l| l.starts_with("ferryman_requests_total"))
    {
        println!("    {line}");
    }
    Ok(())
}

// 11 --------------------------------------------------------------------

async fn graceful_shutdown(d: &mut Demo) -> anyhow::Result<()> {
    d.scenario("Graceful shutdown: SIGTERM lets in-flight requests finish");
    let edge = d.edge.clone();
    let slow =
        tokio::spawn(async move { edge.status("/orders/slow?ms=1500", "tenant-shutdown").await });

    // Signal only once the backend says the request is in flight, not after a
    // guessed delay.
    let log = d.backends["orders"].log.clone();
    let started = eventually(
        Duration::from_secs(5),
        "the slow request to reach the backend",
        || {
            let log = log.clone();
            async move { Ok(std::fs::read_to_string(&log)?.contains("slow request started")) }
        },
    )
    .await;
    d.check(
        "slow request is in flight before SIGTERM",
        started.is_ok(),
        format!("{started:?}"),
    );
    d.proxy.signal("TERM")?;

    let status = slow.await?;
    d.check(
        "the in-flight request completes with 200",
        matches!(status, Ok(200)),
        format!("{status:?}"),
    );
    let exit = d.proxy.wait_exit(Duration::from_secs(30)).await;
    d.check(
        "proxy exits with status 0",
        exit.as_ref().is_ok_and(|e| e.success()),
        format!("{exit:?}"),
    );
    let refused = tokio::net::TcpStream::connect(d.edge.addr).await.is_err();
    d.check("new connections are refused", refused, "still accepting");
    Ok(())
}

/// `--keep`: bring the proxy back (scenario 11 stopped it) and wait.
async fn keep_running(d: &mut Demo) -> anyhow::Result<()> {
    d.proxy = spawn_proxy(&d.config, d.edge.addr, d.metrics, &d.dir).await?;
    println!(
        "\nproxy back up on https://{} (metrics http://{}); Ctrl-C to stop",
        d.edge.addr, d.metrics
    );
    tokio::signal::ctrl_c().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gauge_parses_the_matching_upstream_only() {
        let a: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let b: SocketAddr = "127.0.0.1:2".parse().unwrap();
        let text = "ferryman_circuit_state{upstream=\"127.0.0.1:1\"} 1\nferryman_circuit_state{upstream=\"127.0.0.1:2\"} 0\n";
        assert_eq!(gauge(text, "ferryman_circuit_state", a), Some(1.0));
        assert_eq!(gauge(text, "ferryman_circuit_state", b), Some(0.0));
        assert_eq!(gauge(text, "ferryman_upstream_alive", a), None);
    }
}
