use crate::ns3_plumbing::Ns3EndpointNames;
use crate::scenario::{
    EmulationBackend, NodeConfig, NodePosition, NodeRadioConfig, RadioProfileConfig, Scenario,
};
use serde::Serialize;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use thiserror::Error;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};
use tokio::task::JoinHandle;
use tokio::time::{timeout, Duration};

const READY_MARKER: &str = "ns3_ready";

#[derive(Error, Debug)]
pub enum Ns3DriverError {
    #[error(
        "ns3 driver binary is not configured; set emulation.ns3.driver_bin or AVENA_NS3_DRIVER_BIN"
    )]
    MissingDriverBinary,

    #[error("invalid radio reference '{value}', expected '<node_id>:<radio_id>'")]
    InvalidRadioRef { value: String },

    #[error("failed to serialize ns3 runtime config: {0}")]
    Serialize(#[from] serde_json::Error),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("timed out waiting for ns3 ready marker after {timeout_secs}s")]
    ReadyTimeout { timeout_secs: u64 },

    #[error("ns3 process exited before emitting ready marker")]
    ReadyMarkerNotSeen,
}

pub struct Ns3DriverProcess {
    child: Child,
    stdout_task: JoinHandle<()>,
    stderr_task: JoinHandle<()>,
    event_rx: Option<UnboundedReceiver<Ns3DriverEvent>>,
    pub config_path: PathBuf,
}

impl std::fmt::Debug for Ns3DriverProcess {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ns3DriverProcess")
            .field("config_path", &self.config_path)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Serialize)]
pub struct Ns3RuntimeConfig {
    pub scenario_name: String,
    pub duration_secs: u64,
    pub realtime_hard_limit_ms: u32,
    pub emit_pcap: bool,
    pub nodes: Vec<Ns3RuntimeNode>,
    pub links: Vec<Ns3RuntimeLink>,
    pub bridges: Vec<Ns3RuntimeBridge>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Ns3DriverEvent {
    pub payload: serde_json::Value,
}

#[derive(Debug, Serialize)]
pub struct Ns3RuntimeNode {
    pub id: String,
    pub mobility: Ns3Mobility,
    pub radios: Vec<Ns3RuntimeRadio>,
}

#[derive(Debug, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Ns3Mobility {
    Trace { path: String },
    Fixed { x_m: f64, y_m: f64, z_m: f64 },
}

#[derive(Debug, Serialize)]
pub struct Ns3RuntimeRadio {
    pub id: String,
    pub profile: Option<String>,
    pub kind: Option<String>,
    pub phy_backend: Option<String>,
    pub standard: Option<String>,
    pub band: Option<String>,
    pub channel: Option<u32>,
    pub channel_width_mhz: Option<u32>,
    pub tx_power_dbm: Option<f32>,
    pub rx_noise_figure_db: Option<f32>,
    pub propagation: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct Ns3RuntimeEndpoint {
    pub node_id: String,
    pub radio_id: String,
    pub ns_if: String,
    pub tap_if: String,
    pub underlay_ipv4: String,
}

#[derive(Debug, Serialize)]
pub struct Ns3RuntimeLink {
    pub id: String,
    pub medium: Option<String>,
    pub latency_ms: u32,
    pub bandwidth_kbps: u32,
    pub loss_percent: f32,
    pub enabled: bool,
    pub endpoints: [Ns3RuntimeEndpoint; 2],
}

#[derive(Debug, Serialize)]
pub struct Ns3RuntimeBridge {
    pub id: String,
    pub medium: Option<String>,
    pub latency_ms: u32,
    pub bandwidth_kbps: u32,
    pub loss_percent: f32,
    pub members: Vec<Ns3RuntimeEndpoint>,
}

impl Ns3DriverProcess {
    pub async fn start_if_needed(
        scenario: &Scenario,
        work_dir: &Path,
    ) -> Result<Option<Self>, Ns3DriverError> {
        if scenario.emulation.backend != EmulationBackend::Ns3 {
            return Ok(None);
        }

        let config_path = write_runtime_config_file(scenario, work_dir)?;
        let driver_bin = scenario
            .emulation
            .ns3
            .driver_bin
            .clone()
            .or_else(|| std::env::var("AVENA_NS3_DRIVER_BIN").ok())
            .ok_or(Ns3DriverError::MissingDriverBinary)?;

        let mut cmd = Command::new(&driver_bin);
        cmd.args(&scenario.emulation.ns3.driver_args);
        cmd.arg("--config")
            .arg(&config_path)
            .arg("--duration-secs")
            .arg(scenario.duration_secs.to_string());
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());

        let mut child = cmd.spawn()?;
        let (event_tx, event_rx) = unbounded_channel();

        let stdout = child.stdout.take().ok_or_else(|| {
            Ns3DriverError::Io(std::io::Error::other("failed to capture ns3 stdout"))
        })?;
        let stderr = child.stderr.take().ok_or_else(|| {
            Ns3DriverError::Io(std::io::Error::other("failed to capture ns3 stderr"))
        })?;

        let mut stdout_lines = BufReader::new(stdout).lines();
        let ready_timeout_secs = scenario.emulation.ns3.ready_timeout_secs;

        let ready_result = timeout(Duration::from_secs(ready_timeout_secs), async {
            loop {
                match stdout_lines.next_line().await? {
                    Some(line) => {
                        tracing::debug!(line = %line, "ns3 stdout");
                        maybe_emit_event(&line, &event_tx);
                        if line.contains(READY_MARKER) {
                            return Ok::<(), Ns3DriverError>(());
                        }
                    }
                    None => return Err(Ns3DriverError::ReadyMarkerNotSeen),
                }
            }
        })
        .await;

        match ready_result {
            Ok(Ok(())) => {}
            Ok(Err(err)) => {
                let _ = child.kill().await;
                let _ = child.wait().await;
                return Err(err);
            }
            Err(_) => {
                let _ = child.kill().await;
                let _ = child.wait().await;
                return Err(Ns3DriverError::ReadyTimeout {
                    timeout_secs: ready_timeout_secs,
                });
            }
        }

        let stdout_event_tx = event_tx.clone();
        let stdout_task = tokio::spawn(async move {
            while let Ok(Some(line)) = stdout_lines.next_line().await {
                tracing::debug!(line = %line, "ns3 stdout");
                maybe_emit_event(&line, &stdout_event_tx);
            }
        });

        let mut stderr_lines = BufReader::new(stderr).lines();
        let stderr_task = tokio::spawn(async move {
            while let Ok(Some(line)) = stderr_lines.next_line().await {
                tracing::warn!(line = %line, "ns3 stderr");
            }
        });

        Ok(Some(Self {
            child,
            stdout_task,
            stderr_task,
            event_rx: Some(event_rx),
            config_path,
        }))
    }

    pub async fn shutdown(&mut self) -> Result<(), Ns3DriverError> {
        if self.child.try_wait()?.is_none() {
            let _ = self.child.kill().await;
        }
        let _ = self.child.wait().await;

        self.stdout_task.abort();
        self.stderr_task.abort();

        Ok(())
    }

    pub fn drain_events(&mut self) -> Vec<Ns3DriverEvent> {
        let Some(event_rx) = self.event_rx.as_mut() else {
            return Vec::new();
        };

        let mut events = Vec::new();
        while let Ok(event) = event_rx.try_recv() {
            events.push(event);
        }
        events
    }

    pub fn take_event_receiver(&mut self) -> Option<UnboundedReceiver<Ns3DriverEvent>> {
        self.event_rx.take()
    }
}

pub fn build_runtime_config(scenario: &Scenario) -> Result<Ns3RuntimeConfig, Ns3DriverError> {
    let mut subnet_counter = 1u8;

    let nodes = scenario
        .nodes
        .iter()
        .map(|node| Ns3RuntimeNode {
            id: node.id.clone(),
            mobility: mobility_for_node(node),
            radios: node
                .radios
                .iter()
                .map(|radio| {
                    resolved_radio_config(node, radio, &scenario.emulation.ns3.radio_profiles)
                })
                .collect(),
        })
        .collect();

    let mut links = Vec::new();
    for link in &scenario.links {
        let link_id = link.resolved_link_id();
        let (node_a, radio_a) = parse_radio_ref(&link.endpoints.0)?;
        let (node_b, radio_b) = parse_radio_ref(&link.endpoints.1)?;
        let names_a = Ns3EndpointNames::from_ids(&link_id, node_a, radio_a);
        let names_b = Ns3EndpointNames::from_ids(&link_id, node_b, radio_b);

        let endpoint_a = Ns3RuntimeEndpoint {
            node_id: node_a.to_string(),
            radio_id: radio_a.to_string(),
            ns_if: names_a.ns_if,
            tap_if: names_a.tap_if,
            underlay_ipv4: std::net::Ipv4Addr::new(10, subnet_counter, 0, 1).to_string(),
        };
        let endpoint_b = Ns3RuntimeEndpoint {
            node_id: node_b.to_string(),
            radio_id: radio_b.to_string(),
            ns_if: names_b.ns_if,
            tap_if: names_b.tap_if,
            underlay_ipv4: std::net::Ipv4Addr::new(10, subnet_counter, 0, 2).to_string(),
        };

        links.push(Ns3RuntimeLink {
            id: link_id,
            medium: link.medium.clone(),
            latency_ms: link.latency_ms,
            bandwidth_kbps: link.bandwidth_kbps,
            loss_percent: link.loss_percent,
            enabled: link.enabled,
            endpoints: [endpoint_a, endpoint_b],
        });

        subnet_counter = subnet_counter.wrapping_add(1);
    }

    let mut bridges = Vec::new();
    for bridge in &scenario.bridges {
        let mut members = Vec::with_capacity(bridge.nodes.len());
        for (idx, member) in bridge.nodes.iter().enumerate() {
            let (node_id, radio_id) = parse_radio_ref(member)?;
            let names = Ns3EndpointNames::from_ids(&bridge.id, node_id, radio_id);
            members.push(Ns3RuntimeEndpoint {
                node_id: node_id.to_string(),
                radio_id: radio_id.to_string(),
                ns_if: names.ns_if,
                tap_if: names.tap_if,
                underlay_ipv4: std::net::Ipv4Addr::new(10, subnet_counter, 0, (idx as u8) + 1)
                    .to_string(),
            });
        }

        bridges.push(Ns3RuntimeBridge {
            id: bridge.id.clone(),
            medium: bridge.medium.clone(),
            latency_ms: bridge.latency_ms,
            bandwidth_kbps: bridge.bandwidth_kbps,
            loss_percent: bridge.loss_percent,
            members,
        });

        subnet_counter = subnet_counter.wrapping_add(1);
    }

    Ok(Ns3RuntimeConfig {
        scenario_name: scenario.name.clone(),
        duration_secs: scenario.duration_secs,
        realtime_hard_limit_ms: scenario.emulation.ns3.realtime_hard_limit_ms,
        emit_pcap: scenario.emulation.ns3.emit_pcap,
        nodes,
        links,
        bridges,
    })
}

pub fn write_runtime_config_file(
    scenario: &Scenario,
    work_dir: &Path,
) -> Result<PathBuf, Ns3DriverError> {
    let config = build_runtime_config(scenario)?;
    std::fs::create_dir_all(work_dir)?;

    let config_path = work_dir.join("ns3-runtime-config.json");
    let bytes = serde_json::to_vec_pretty(&config)?;
    std::fs::write(&config_path, bytes)?;

    Ok(config_path)
}

fn parse_radio_ref(value: &str) -> Result<(&str, &str), Ns3DriverError> {
    let Some((node_id, radio_id)) = value.split_once(':') else {
        return Err(Ns3DriverError::InvalidRadioRef {
            value: value.to_string(),
        });
    };

    if node_id.is_empty() || radio_id.is_empty() || radio_id.contains(':') {
        return Err(Ns3DriverError::InvalidRadioRef {
            value: value.to_string(),
        });
    }

    Ok((node_id, radio_id))
}

fn parse_event_line(line: &str) -> Option<Ns3DriverEvent> {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.contains(READY_MARKER) {
        return None;
    }

    let payload = serde_json::from_str::<serde_json::Value>(trimmed).ok()?;
    Some(Ns3DriverEvent { payload })
}

fn maybe_emit_event(line: &str, tx: &UnboundedSender<Ns3DriverEvent>) {
    if let Some(event) = parse_event_line(line) {
        let _ = tx.send(event);
    }
}

fn mobility_for_node(node: &crate::scenario::NodeConfig) -> Ns3Mobility {
    if let Some(trace) = &node.mobility_trace {
        return Ns3Mobility::Trace {
            path: trace.clone(),
        };
    }

    if let Some(position) = &node.position {
        return fixed_from_position(position);
    }

    Ns3Mobility::Fixed {
        x_m: 0.0,
        y_m: 0.0,
        z_m: 0.0,
    }
}

fn fixed_from_position(position: &NodePosition) -> Ns3Mobility {
    Ns3Mobility::Fixed {
        x_m: position.x_m,
        y_m: position.y_m,
        z_m: position.z_m,
    }
}

fn resolved_radio_config(
    node: &NodeConfig,
    radio: &NodeRadioConfig,
    profiles: &HashMap<String, RadioProfileConfig>,
) -> Ns3RuntimeRadio {
    let mut resolved = Ns3RuntimeRadio {
        id: radio.id.clone(),
        profile: radio.profile.clone().or_else(|| node.radio_profile.clone()),
        kind: None,
        phy_backend: None,
        standard: None,
        band: None,
        channel: None,
        channel_width_mhz: None,
        tx_power_dbm: None,
        rx_noise_figure_db: None,
        propagation: None,
    };

    if let Some(node_profile_name) = node.radio_profile.as_ref() {
        if let Some(profile) = profiles.get(node_profile_name) {
            apply_profile_to_runtime(&mut resolved, profile);
        }
    }

    if let Some(radio_profile_name) = radio.profile.as_ref() {
        if let Some(profile) = profiles.get(radio_profile_name) {
            apply_profile_to_runtime(&mut resolved, profile);
        }
    }

    resolved.kind = radio.kind.clone().or(resolved.kind);
    resolved.phy_backend = radio.phy_backend.clone().or(resolved.phy_backend);
    resolved.standard = radio.standard.clone().or(resolved.standard);
    resolved.band = radio.band.clone().or(resolved.band);
    resolved.channel = radio.channel.or(resolved.channel);
    resolved.channel_width_mhz = radio.channel_width_mhz.or(resolved.channel_width_mhz);
    resolved.tx_power_dbm = radio.tx_power_dbm.or(resolved.tx_power_dbm);
    resolved.rx_noise_figure_db = radio.rx_noise_figure_db.or(resolved.rx_noise_figure_db);
    resolved.propagation = radio.propagation.clone().or(resolved.propagation);

    resolved
}

fn apply_profile_to_runtime(runtime: &mut Ns3RuntimeRadio, profile: &RadioProfileConfig) {
    runtime.kind = profile.kind.clone().or(runtime.kind.clone());
    runtime.phy_backend = profile.phy_backend.clone().or(runtime.phy_backend.clone());
    runtime.standard = profile.standard.clone().or(runtime.standard.clone());
    runtime.band = profile.band.clone().or(runtime.band.clone());
    runtime.channel = profile.channel.or(runtime.channel);
    runtime.channel_width_mhz = profile.channel_width_mhz.or(runtime.channel_width_mhz);
    runtime.tx_power_dbm = profile.tx_power_dbm.or(runtime.tx_power_dbm);
    runtime.rx_noise_figure_db = profile.rx_noise_figure_db.or(runtime.rx_noise_figure_db);
    runtime.propagation = profile.propagation.clone().or(runtime.propagation.clone());
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn ns3_scenario_toml(driver_args: &str, timeout_secs: u64) -> String {
        format!(
            r#"
name = "ns3-driver"
duration_secs = 3

[emulation]
backend = "ns3"

[emulation.ns3]
driver_bin = "/bin/bash"
driver_args = {driver_args}
ready_timeout_secs = {timeout_secs}

[emulation.ns3.radio_profiles.default_wifi]
kind = "wifi"

[[nodes]]
id = "nodeA"
position = {{ x_m = 0.0, y_m = 0.0, z_m = 0.0 }}
radio_profile = "default_wifi"

[[nodes.radios]]
id = "wifi0"
channel = 36

[[nodes]]
id = "nodeB"
position = {{ x_m = 1.0, y_m = 0.0, z_m = 0.0 }}
radio_profile = "default_wifi"

[[nodes.radios]]
id = "wifi0"
channel = 36

[[links]]
id = "ab"
medium = "wifi"
endpoints = ["nodeA:wifi0", "nodeB:wifi0"]
latency_ms = 10
bandwidth_kbps = 1000

[[bridges]]
id = "farm"
medium = "wifi"
members = ["nodeA:wifi0", "nodeB:wifi0"]
"#
        )
    }

    #[test]
    fn build_runtime_config_assigns_expected_taps_and_subnets() {
        let toml = ns3_scenario_toml("[\"-c\", \"echo ns3_ready; sleep 0.1\"]", 5);
        let scenario = Scenario::from_toml(&toml).expect("valid scenario");

        let config = build_runtime_config(&scenario).expect("runtime config");
        assert_eq!(config.links.len(), 1);
        assert_eq!(config.bridges.len(), 1);

        let link = &config.links[0];
        assert_eq!(link.id, "ab");
        assert_eq!(link.endpoints[0].underlay_ipv4, "10.1.0.1");
        assert_eq!(link.endpoints[1].underlay_ipv4, "10.1.0.2");

        let expected_a = Ns3EndpointNames::from_ids("ab", "nodeA", "wifi0");
        assert_eq!(link.endpoints[0].tap_if, expected_a.tap_if);
        assert_eq!(link.endpoints[0].ns_if, expected_a.ns_if);

        let bridge = &config.bridges[0];
        assert_eq!(bridge.members[0].underlay_ipv4, "10.2.0.1");
        assert_eq!(bridge.members[1].underlay_ipv4, "10.2.0.2");
    }

    #[test]
    fn build_runtime_config_merges_radio_profiles_with_overrides() {
        let toml = r#"
name = "ns3-driver-merge"
duration_secs = 3

[emulation]
backend = "ns3"

[emulation.ns3]
driver_bin = "/bin/bash"
driver_args = ["-c", "echo ns3_ready; sleep 0.1"]

[emulation.ns3.radio_profiles.default_wifi]
kind = "wifi"
phy_backend = "spectrum"
standard = "802.11n"
band = "5ghz"
channel_width_mhz = 20
tx_power_dbm = 18
rx_noise_figure_db = 7
propagation = "log-distance"

[emulation.ns3.radio_profiles.sensor_wifi]
kind = "wifi"
phy_backend = "yans"
band = "2.4ghz"
channel = 1
tx_power_dbm = 10

[[nodes]]
id = "nodeA"
position = { x_m = 0.0, y_m = 0.0, z_m = 0.0 }
radio_profile = "default_wifi"

[[nodes.radios]]
id = "wifi0"
profile = "sensor_wifi"
channel = 6
tx_power_dbm = 13

[[nodes]]
id = "nodeB"
position = { x_m = 1.0, y_m = 0.0, z_m = 0.0 }
radio_profile = "default_wifi"

[[nodes.radios]]
id = "wifi0"

[[links]]
id = "ab"
medium = "wifi"
endpoints = ["nodeA:wifi0", "nodeB:wifi0"]
latency_ms = 10
bandwidth_kbps = 1000
"#;

        let scenario = Scenario::from_toml(toml).expect("valid scenario");
        let config = build_runtime_config(&scenario).expect("runtime config");
        let node_a = config
            .nodes
            .iter()
            .find(|node| node.id == "nodeA")
            .expect("missing nodeA");
        let radio = node_a
            .radios
            .iter()
            .find(|r| r.id == "wifi0")
            .expect("radio");

        assert_eq!(radio.profile.as_deref(), Some("sensor_wifi"));
        assert_eq!(radio.kind.as_deref(), Some("wifi"));
        assert_eq!(radio.phy_backend.as_deref(), Some("yans"));
        assert_eq!(radio.band.as_deref(), Some("2.4ghz"));
        assert_eq!(radio.channel, Some(6));
        assert_eq!(radio.channel_width_mhz, Some(20));
        assert_eq!(radio.tx_power_dbm, Some(13.0));
        assert_eq!(radio.rx_noise_figure_db, Some(7.0));
        assert_eq!(radio.propagation.as_deref(), Some("log-distance"));
    }

    #[tokio::test]
    async fn start_if_needed_is_noop_for_netem() {
        let toml = r#"
name = "netem"
duration_secs = 3

[[nodes]]
id = "nodeA"

[[nodes]]
id = "nodeB"

[[links]]
endpoints = ["nodeA", "nodeB"]
latency_ms = 10
bandwidth_kbps = 1000
"#;

        let scenario = Scenario::from_toml(toml).expect("valid netem scenario");
        let temp = tempfile::tempdir().expect("temp dir");

        let handle = Ns3DriverProcess::start_if_needed(&scenario, temp.path())
            .await
            .expect("start_if_needed should succeed");
        assert!(handle.is_none());
    }

    #[tokio::test]
    async fn start_waits_for_ready_marker() {
        let toml = ns3_scenario_toml("[\"-c\", \"echo ns3_ready; sleep 0.2\"]", 5);
        let scenario = Scenario::from_toml(&toml).expect("valid scenario");
        let temp = tempfile::tempdir().expect("temp dir");

        let mut handle = Ns3DriverProcess::start_if_needed(&scenario, temp.path())
            .await
            .expect("ns3 should start")
            .expect("ns3 backend should create handle");

        assert!(handle.config_path.exists());
        handle.shutdown().await.expect("shutdown");
    }

    #[tokio::test]
    async fn start_times_out_without_ready_marker() {
        let toml = ns3_scenario_toml("[\"-c\", \"sleep 2\"]", 1);
        let scenario = Scenario::from_toml(&toml).expect("valid scenario");
        let temp = tempfile::tempdir().expect("temp dir");

        let err = Ns3DriverProcess::start_if_needed(&scenario, temp.path())
            .await
            .expect_err("should fail when ready marker is missing");

        assert!(
            matches!(
                err,
                Ns3DriverError::ReadyTimeout { .. } | Ns3DriverError::ReadyMarkerNotSeen
            ),
            "unexpected error: {err}"
        );

        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    #[test]
    fn parse_event_line_parses_valid_json() {
        let event =
            parse_event_line(r#"{"type":"realtime","lag_ms":3}"#).expect("event should parse");
        assert_eq!(event.payload["type"], "realtime");
        assert_eq!(event.payload["lag_ms"], 3);
    }

    #[test]
    fn parse_event_line_ignores_ready_and_invalid_lines() {
        assert!(parse_event_line("ns3_ready").is_none());
        assert!(parse_event_line("not-json").is_none());
        assert!(parse_event_line("   ").is_none());
    }

    #[tokio::test]
    async fn start_collects_stdout_json_events() {
        let toml = ns3_scenario_toml(
            "[\"-c\", \"echo ns3_ready; echo '{\\\"type\\\":\\\"realtime\\\",\\\"lag_ms\\\":7}'; sleep 0.2\"]",
            5,
        );
        let scenario = Scenario::from_toml(&toml).expect("valid scenario");
        let temp = tempfile::tempdir().expect("temp dir");

        let mut handle = Ns3DriverProcess::start_if_needed(&scenario, temp.path())
            .await
            .expect("ns3 should start")
            .expect("handle expected");

        tokio::time::sleep(Duration::from_millis(100)).await;
        let events = handle.drain_events();
        assert!(
            events
                .iter()
                .any(|event| event.payload["type"] == "realtime"),
            "expected realtime event"
        );

        handle.shutdown().await.expect("shutdown");
    }

    #[tokio::test]
    async fn take_event_receiver_streams_events() {
        let toml = ns3_scenario_toml(
            "[\"-c\", \"echo ns3_ready; echo '{\\\"type\\\":\\\"realtime\\\",\\\"lag_ms\\\":11}'; sleep 0.2\"]",
            5,
        );
        let scenario = Scenario::from_toml(&toml).expect("valid scenario");
        let temp = tempfile::tempdir().expect("temp dir");

        let mut handle = Ns3DriverProcess::start_if_needed(&scenario, temp.path())
            .await
            .expect("ns3 should start")
            .expect("handle expected");

        let mut rx = handle
            .take_event_receiver()
            .expect("receiver should be available");

        let event = tokio::time::timeout(Duration::from_secs(1), rx.recv())
            .await
            .expect("event wait timeout")
            .expect("event channel closed early");
        assert_eq!(event.payload["type"], "realtime");
        assert_eq!(event.payload["lag_ms"], 11);

        assert!(handle.take_event_receiver().is_none());
        assert!(handle.drain_events().is_empty());

        handle.shutdown().await.expect("shutdown");
    }
}
