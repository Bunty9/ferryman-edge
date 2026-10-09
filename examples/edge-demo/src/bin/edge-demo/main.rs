//! `edge-demo`: a reference driver for the ferryman-edge proxy.
//!
//! * `setup`: generate the PKI and a proxy config for fixed local ports and
//!   print the commands to run everything by hand.
//! * `token`: mint a JWT for a tenant.
//! * `run`: start the real `ferryman-edge-server` in front of sample
//!   backends and walk through every feature with checked expectations.
//!
//! Unix only: the proxy is controlled with SIGUSR1 / SIGTERM.
//!
//! `DEFAULT_DIR` is resolved at compile time from `CARGO_MANIFEST_DIR`
//! (`examples/edge-demo/.demo`), so it does not depend on the working
//! directory; `--dir` overrides it. `setup` writes there directly; `run`
//! uses its own `<dir>/run/` subdirectory so it never clobbers the material
//! a manual or compose setup is using.

mod client;
mod pki;
mod procs;
mod proxy_config;
mod scenarios;
mod tokens;

use clap::{Parser, Subcommand};
use pki::Pki;
use proxy_config::Topology;
use std::path::PathBuf;

/// Generated keys, tokens, config and logs live here (gitignored).
const DEFAULT_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/.demo");

/// Fixed ports for the manual walkthrough. `run` uses free ports instead.
const PROXY: &str = "127.0.0.1:8443";
const METRICS: &str = "127.0.0.1:9090";
const BACKENDS: [(&str, &str); 3] = [
    ("orders", "127.0.0.1:9101"),
    ("inventory", "127.0.0.1:9102"),
    ("payments", "127.0.0.1:9103"),
];

#[derive(Parser)]
#[command(about = "ferryman-edge reference demo")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Write the PKI and a config for the manual walkthrough.
    Setup {
        #[arg(long, default_value = DEFAULT_DIR)]
        dir: PathBuf,
    },
    /// Print a signed JWT.
    Token {
        #[arg(long, default_value = DEFAULT_DIR)]
        dir: PathBuf,
        /// Tenant identity (`sub`).
        #[arg(long)]
        sub: String,
        /// Lifetime in seconds (negative = already expired).
        #[arg(long, default_value_t = 300, allow_hyphen_values = true)]
        ttl: i64,
        #[arg(long)]
        aud: Option<String>,
        #[arg(long)]
        iss: Option<String>,
    },
    /// Run every scenario against a real proxy; exit non-zero on any failure.
    /// Files go to `<dir>/run/`.
    Run {
        #[arg(long, default_value = DEFAULT_DIR)]
        dir: PathBuf,
        /// Leave the proxy and backends running afterwards, until Ctrl-C.
        #[arg(long)]
        keep: bool,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // install ring once before any client config is built.
    let _ = rustls::crypto::ring::default_provider().install_default();

    match Cli::parse().cmd {
        Cmd::Setup { dir } => setup(dir),
        Cmd::Token {
            dir,
            sub,
            ttl,
            aud,
            iss,
        } => {
            let mut spec = tokens::TokenSpec::valid(&sub);
            spec.ttl_secs = ttl;
            spec.aud = aud.or(spec.aud);
            spec.iss = iss.or(spec.iss);
            println!(
                "{}",
                tokens::mint(&Pki::at(&std::path::absolute(dir)?)?, &spec)?
            );
            Ok(())
        }
        Cmd::Run { dir, keep } => {
            let ok = scenarios::run(std::path::absolute(dir)?.join("run"), keep).await?;
            std::process::exit(if ok { 0 } else { 1 });
        }
    }
}

fn setup(dir: PathBuf) -> anyhow::Result<()> {
    let dir = std::path::absolute(dir)?;
    let pki = Pki::generate(&dir)?;
    let topo = Topology {
        routes: vec![
            ("/orders".into(), BACKENDS[0].1.parse()?, None),
            ("/inventory".into(), BACKENDS[1].1.parse()?, Some(2)),
            ("/payments".into(), BACKENDS[2].1.parse()?, None),
        ],
        tenant_rps: 5,
        health_interval_secs: 1,
        default_cooldown_secs: 2,
        unprobed: vec![],
    };
    let config = dir.join("ferryman.toml");
    proxy_config::write(&pki, &topo, &config)?;

    let d = dir.display();
    println!("wrote PKI and config to {d}\n");
    println!("# 1. backends (private: only the proxy should reach these)");
    for (name, addr) in BACKENDS {
        println!("target/debug/backend --name {name} --bind {addr} &");
    }
    println!("\n# 2. the proxy");
    println!("target/debug/ferryman-edge-server --config {d}/ferryman.toml --bind {PROXY} --metrics-bind {METRICS} &");
    println!("\n# 3. a request through it");
    println!("TOKEN=$(target/debug/edge-demo token --sub acme)");
    println!(
        "curl --cacert {d}/ca.crt --cert {d}/client.crt --key {d}/client.key \\\n     -H \"Authorization: Bearer $TOKEN\" https://{PROXY}/orders/42"
    );
    Ok(())
}
