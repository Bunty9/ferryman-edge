//! Child-process management: find binaries, spawn them with their output in
//! log files, wait until they are ready, signal them, and make sure they die.

use anyhow::{bail, Context};
use std::future::Future;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

const READY_TIMEOUT: Duration = Duration::from_secs(10);
const POLL: Duration = Duration::from_millis(100);

/// Find a workspace binary: an override env var, then next to this
/// executable (where cargo puts every bin of the workspace), then `PATH`.
pub fn locate_binary(name: &str) -> anyhow::Result<PathBuf> {
    let env_var = match name {
        "ferryman-edge-server" => Some("FERRYMAN_EDGE_BIN"),
        "backend" => Some("BACKEND_BIN"),
        _ => None,
    };
    if let Some(var) = env_var {
        if let Some(p) = std::env::var_os(var) {
            let p = PathBuf::from(p);
            anyhow::ensure!(p.is_file(), "{var}={} is not a file", p.display());
            return Ok(p);
        }
    }
    if let Some(dir) = std::env::current_exe()?.parent() {
        let p = dir.join(name);
        if p.is_file() {
            return Ok(p);
        }
    }
    if let Some(path) = std::env::var_os("PATH") {
        if let Some(p) = std::env::split_paths(&path)
            .map(|d| d.join(name))
            .find(|p| p.is_file())
        {
            return Ok(p);
        }
    }
    // `cargo run -p ferryman-edge-demo` builds only the demo's own bins, so
    // a bare spawn failure here would be baffling. Say how to fix it.
    bail!(
        "could not find the `{name}` binary. Build the proxy and the demo first:\n    \
         cargo build -p ferryman-edge -p ferryman-edge-demo\n\
         (or point {} at a prebuilt binary)",
        env_var.unwrap_or("PATH")
    )
}

/// A spawned process whose stdout/stderr go to a log file. Killed on drop,
/// so a failed check, an error or a panic cannot leave it running.
pub struct Child {
    pub name: String,
    pub pid: u32,
    pub log: PathBuf,
    inner: std::process::Child,
}

impl Child {
    fn spawn(name: &str, mut cmd: Command, log: &Path) -> anyhow::Result<Child> {
        // A log *file*, not a pipe: an unread pipe fills up and blocks the child.
        let out = std::fs::File::create(log)?;
        let err = out.try_clone()?;
        let inner = cmd
            // Own process group, so cleanup can signal the child and anything
            // it spawned with one `kill -<sig> -<pgid>`.
            .process_group(0)
            .stdin(Stdio::null())
            .stdout(out)
            .stderr(err)
            .spawn()
            .with_context(|| format!("spawning {name}"))?;
        Ok(Child {
            name: name.to_string(),
            pid: inner.id(),
            log: log.to_path_buf(),
            inner,
        })
    }

    /// Send a signal by name (`"USR1"`, `"TERM"`). Uses `kill(1)` so the demo
    /// needs no libc/nix dependency.
    pub fn signal(&self, sig: &str) -> anyhow::Result<()> {
        let status = Command::new("kill")
            .arg(format!("-{sig}"))
            .arg(self.pid.to_string())
            .status()?;
        anyhow::ensure!(
            status.success(),
            "kill -{sig} {} failed ({})",
            self.pid,
            self.name
        );
        Ok(())
    }

    /// Stop the whole process group and reap: SIGTERM first, SIGKILL if it is
    /// still alive after a short grace period. Idempotent. Synchronous on
    /// purpose so it also works from `Drop` during a panic.
    pub fn kill(&mut self) {
        if matches!(self.inner.try_wait(), Ok(Some(_))) {
            return;
        }
        let group = format!("-{}", self.pid);
        let _ = Command::new("kill")
            .args(["-TERM", "--", &group])
            .stderr(Stdio::null())
            .status();
        let end = Instant::now() + Duration::from_millis(500);
        while Instant::now() < end && matches!(self.inner.try_wait(), Ok(None)) {
            std::thread::sleep(Duration::from_millis(20));
        }
        let _ = Command::new("kill")
            .args(["-KILL", "--", &group])
            .stderr(Stdio::null())
            .status();
        let _ = self.inner.wait();
    }

    /// Wait for the process to exit on its own.
    pub async fn wait_exit(&mut self, within: Duration) -> anyhow::Result<ExitStatus> {
        let end = Instant::now() + within;
        loop {
            if let Some(status) = self.inner.try_wait()? {
                return Ok(status);
            }
            anyhow::ensure!(
                Instant::now() < end,
                "{} still running after {within:?}",
                self.name
            );
            tokio::time::sleep(POLL).await;
        }
    }

    fn early_exit(&mut self) -> Option<ExitStatus> {
        self.inner.try_wait().ok().flatten()
    }
}

impl Drop for Child {
    fn drop(&mut self) {
        self.kill();
    }
}

/// Start the sample upstream and wait for its "listening" line.
pub async fn spawn_backend(name: &str, addr: SocketAddr, logs: &Path) -> anyhow::Result<Child> {
    let mut cmd = Command::new(locate_binary("backend")?);
    cmd.args(["--name", name, "--bind", &addr.to_string()]);
    let mut child = Child::spawn(
        &format!("backend-{name}"),
        cmd,
        &logs.join(format!("backend-{name}.log")),
    )?;
    let end = Instant::now() + READY_TIMEOUT;
    loop {
        let log = std::fs::read_to_string(&child.log).unwrap_or_default();
        if log.contains("listening on") {
            return Ok(child);
        }
        if let Some(status) = child.early_exit() {
            bail!("backend {name} exited ({status}) before listening:\n{log}");
        }
        anyhow::ensure!(
            Instant::now() < end,
            "backend {name} not listening in time:\n{log}"
        );
        tokio::time::sleep(POLL).await;
    }
}

/// Start the real proxy binary and wait until it accepts TCP connections on
/// both its listener and its metrics port.
pub async fn spawn_proxy(
    config: &Path,
    bind: SocketAddr,
    metrics: SocketAddr,
    logs: &Path,
) -> anyhow::Result<Child> {
    let mut cmd = Command::new(locate_binary("ferryman-edge-server")?);
    cmd.arg("--config").arg(config);
    cmd.args([
        "--bind",
        &bind.to_string(),
        "--metrics-bind",
        &metrics.to_string(),
    ]);
    let mut child = Child::spawn("proxy", cmd, &logs.join("proxy.log"))?;
    let end = Instant::now() + READY_TIMEOUT;
    while ![bind, metrics]
        .iter()
        .all(|a| TcpStream::connect_timeout(a, POLL).is_ok())
    {
        if let Some(status) = child.early_exit() {
            let log = std::fs::read_to_string(&child.log).unwrap_or_default();
            bail!("proxy exited ({status}) during startup:\n{log}");
        }
        anyhow::ensure!(
            Instant::now() < end,
            "proxy not accepting connections in time"
        );
        tokio::time::sleep(POLL).await;
    }
    Ok(child)
}

/// An unused loopback port. Racy by nature (someone could grab it before
/// the caller binds), which is fine for a local demo.
pub fn free_port() -> anyhow::Result<SocketAddr> {
    Ok(TcpListener::bind("127.0.0.1:0")?.local_addr()?)
}

/// Poll `f` until it returns `Ok(true)` or `deadline` passes. Reloads and
/// breaker transitions are asynchronous, so checks poll instead of sleeping
/// a fixed time. The last error, if any, is reported on timeout.
pub async fn eventually<F, Fut>(deadline: Duration, what: &str, mut f: F) -> anyhow::Result<()>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = anyhow::Result<bool>>,
{
    let end = Instant::now() + deadline;
    let mut last_err = None;
    loop {
        match f().await {
            Ok(true) => return Ok(()),
            Ok(false) => {}
            Err(e) => last_err = Some(e),
        }
        if Instant::now() >= end {
            match last_err {
                Some(e) => bail!("timed out after {deadline:?} waiting for {what}: {e:#}"),
                None => bail!("timed out after {deadline:?} waiting for {what}"),
            }
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_binary_error_says_how_to_build() {
        let err = locate_binary("definitely-not-here")
            .unwrap_err()
            .to_string();
        assert!(err.contains("cargo build -p ferryman-edge"), "{err}");
    }

    #[tokio::test]
    async fn eventually_times_out_with_reason() {
        let err = eventually(Duration::from_millis(300), "never", || async { Ok(false) })
            .await
            .unwrap_err();
        assert!(err.to_string().contains("never"));
    }
}
