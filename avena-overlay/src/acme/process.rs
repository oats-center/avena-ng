use crate::AcmeConfig;
use std::process::Stdio;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};
use tracing::{debug, info, warn};

use super::AcmeError;

pub struct AcmeProcessController {
    tx_process: Option<Child>,
    rx_process: Option<Child>,
}

impl std::fmt::Debug for AcmeProcessController {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AcmeProcessController")
            .field("tx_running", &self.tx_process.is_some())
            .field("rx_running", &self.rx_process.is_some())
            .finish()
    }
}

impl AcmeProcessController {
    pub async fn start(config: &AcmeConfig) -> Result<Self, AcmeError> {
        if config.interface.trim().is_empty() {
            return Err(AcmeError::Config(
                "acme.interface must be set when ACME is enabled".into(),
            ));
        }

        let mut tx_cmd = Command::new(&config.binary_path);
        tx_cmd
            .args([
                "-E",
                "-D",
                &config.destination,
                "-t",
                &config.event_port.to_string(),
                "-x",
                &config.interface,
                "-L",
                &config.tx_local_port.to_string(),
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        info!(
            binary = %config.binary_path.display(),
            interface = %config.interface,
            destination = %config.destination,
            event_port = config.event_port,
            listen_port = config.tx_local_port,
            "starting ACME TX helper"
        );

        let mut rx_cmd = Command::new(&config.binary_path);
        rx_cmd
            .args([
                "-E",
                "-R",
                "-D",
                &config.destination,
                "-p",
                &config.event_port.to_string(),
                "-x",
                &config.interface,
                "-X",
                &config.proxy_ip.to_string(),
                "-Y",
                &config.rx_local_port.to_string(),
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        info!(
            binary = %config.binary_path.display(),
            interface = %config.interface,
            destination = %config.destination,
            event_port = config.event_port,
            target_ip = %config.proxy_ip,
            target_port = config.rx_local_port,
            "starting ACME RX helper"
        );

        let mut tx_process = tx_cmd.spawn()?;
        let mut rx_process = rx_cmd.spawn()?;
        spawn_log_task("acme-tx", tx_process.stdout.take(), tx_process.stderr.take());
        spawn_log_task("acme-rx", rx_process.stdout.take(), rx_process.stderr.take());

        if config.startup_delay_ms > 0 {
            tokio::time::sleep(std::time::Duration::from_millis(config.startup_delay_ms)).await;
        }

        if let Some(status) = tx_process.try_wait()? {
            let _ = rx_process.start_kill();
            let _ = rx_process.wait().await;
            return Err(AcmeError::Process(format!(
                "TX helper exited early with status {status}"
            )));
        }

        if let Some(status) = rx_process.try_wait()? {
            let _ = tx_process.start_kill();
            let _ = tx_process.wait().await;
            return Err(AcmeError::Process(format!(
                "RX helper exited early with status {status}"
            )));
        }

        Ok(Self {
            tx_process: Some(tx_process),
            rx_process: Some(rx_process),
        })
    }

    pub async fn stop(&mut self) {
        if let Some(mut tx_process) = self.tx_process.take() {
            let _ = tx_process.start_kill();
            let _ = tx_process.wait().await;
        }
        if let Some(mut rx_process) = self.rx_process.take() {
            let _ = rx_process.start_kill();
            let _ = rx_process.wait().await;
        }
    }
}

fn spawn_log_task(
    name: &'static str,
    stdout: Option<impl tokio::io::AsyncRead + Unpin + Send + 'static>,
    stderr: Option<impl tokio::io::AsyncRead + Unpin + Send + 'static>,
) {
    if let Some(stdout) = stdout {
        tokio::spawn(async move {
            let mut lines = BufReader::new(stdout).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                debug!(component = name, stream = "stdout", line = %line, "acme helper");
            }
        });
    }
    if let Some(stderr) = stderr {
        tokio::spawn(async move {
            let mut lines = BufReader::new(stderr).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                warn!(component = name, stream = "stderr", line = %line, "acme helper");
            }
        });
    }
}
