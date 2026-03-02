//! Full test scenario orchestration.
//!
//! Coordinates PKI generation, topology setup, link configuration,
//! event timeline execution, and teardown.

use crate::events::{EventError, EventExecutor, TestResult};
use crate::links::LinkManager;
use crate::metrics::{LogParser, MetricsLogger};
use crate::ns3_driver::Ns3DriverProcess;
use crate::pki::TestPki;
use crate::scenario::{EmulationBackend, Scenario};
use crate::status::Status;
use crate::topology::TestTopology;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::sync::Mutex;

const NODE_STARTUP_TIMEOUT: Duration = Duration::from_secs(10);
const NODE_STARTUP_POLL_INTERVAL: Duration = Duration::from_millis(100);

#[derive(Error, Debug)]
pub enum RunnerError {
    #[error("scenario error: {0}")]
    Scenario(#[from] crate::scenario::ScenarioError),

    #[error("pki error: {0}")]
    Pki(#[from] crate::pki::PkiError),

    #[error("topology error: {0}")]
    Topology(#[from] crate::topology::TopologyError),

    #[error("link error: {0}")]
    Link(#[from] crate::links::LinkError),

    #[error("event error: {0}")]
    Event(#[from] EventError),

    #[error("ns3 driver error: {0}")]
    Ns3Driver(#[from] crate::ns3_driver::Ns3DriverError),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("node startup failed: {0}")]
    NodeStartup(String),
}

pub struct TestRunner {
    keep_namespaces: bool,
}

impl std::fmt::Debug for TestRunner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TestRunner")
            .field("keep_namespaces", &self.keep_namespaces)
            .finish()
    }
}

impl TestRunner {
    pub fn new() -> Self {
        Self {
            keep_namespaces: false,
        }
    }

    pub fn keep_namespaces(mut self, keep: bool) -> Self {
        self.keep_namespaces = keep;
        self
    }

    pub async fn run_scenario(
        &self,
        scenario_path: &Path,
        output_path: &Path,
    ) -> Result<TestResult, RunnerError> {
        let scenario = Scenario::load(scenario_path)?;
        self.run(&scenario, output_path).await
    }

    pub async fn run(
        &self,
        scenario: &Scenario,
        output_path: &Path,
    ) -> Result<TestResult, RunnerError> {
        let status = Status::new();

        status.message(&format!("Running scenario: {}", scenario.name));

        tracing::debug!("creating metrics logger at {:?}", output_path);
        let metrics = Arc::new(MetricsLogger::new(output_path)?);
        metrics.log_scenario_started(&scenario.name);

        let phase = status.phase("Generating PKI");
        tracing::debug!("generating PKI");
        let pki = TestPki::generate(&scenario.nodes)?;
        phase.done();

        let phase = status.phase("Setting up network topology");
        tracing::debug!("setting up topology");
        let mut topology = TestTopology::new();
        topology.setup(scenario, &pki).await?;
        phase.done();

        let mut ns3_driver = Ns3DriverProcess::start_if_needed(scenario, pki.temp_dir()).await?;
        if let Some(driver) = ns3_driver.as_ref() {
            tracing::info!(
                config = %driver.config_path.display(),
                "ns3 driver started and ready"
            );
        }

        let phase = status.phase(&format!("Starting {} nodes", scenario.nodes.len()));
        let log_dir = output_path.parent().unwrap_or(std::path::Path::new("."));
        if let Err(err) = topology.start_nodes(&pki, scenario, log_dir).await {
            if let Some(driver) = ns3_driver.as_mut() {
                let _ = driver.shutdown().await;
            }
            return Err(err.into());
        }

        let mut links = LinkManager::new();
        if backend_uses_netem(scenario.emulation.backend) {
            links.initialize_from_topology(&topology, &scenario.links, &scenario.bridges);
            links.apply_initial_state().await?;
        }

        for node in &scenario.nodes {
            let config_path = pki.temp_dir().join(format!("{}.toml", node.id));
            if let Ok(content) = std::fs::read_to_string(&config_path) {
                tracing::debug!(node = %node.id, config = %content, "generated config");
            }
        }

        let mut running_count = 0;
        let mut not_ready_nodes = Vec::new();
        for node in &scenario.nodes {
            if wait_for_node_ready(&mut topology, &node.id, log_dir).await? {
                if let Some(instance) = topology.node_mut(&node.id) {
                    metrics.log_node_started(&node.id, &instance.overlay_ip);
                    running_count += 1;
                    tracing::info!(
                        node = %node.id,
                        overlay_ip = %instance.overlay_ip,
                        "node running"
                    );
                }
            } else {
                not_ready_nodes.push(node.id.clone());
            }
        }
        phase.done_with(&format!("{running_count} running"));

        if !not_ready_nodes.is_empty() {
            if let Some(driver) = ns3_driver.as_mut() {
                let _ = driver.shutdown().await;
            }
            if !self.keep_namespaces {
                let phase = status.phase("Cleaning up");
                topology.teardown().await?;
                phase.done();
            }
            return Err(RunnerError::NodeStartup(format!(
                "not ready: {}",
                not_ready_nodes.join(", ")
            )));
        }

        let topology = Arc::new(Mutex::new(topology));
        let links = Arc::new(Mutex::new(links));

        let node_ids: Vec<String> = scenario.nodes.iter().map(|n| n.id.clone()).collect();
        let executor = EventExecutor::new(
            Arc::clone(&topology),
            Arc::clone(&links),
            Arc::clone(&metrics),
            log_dir.to_path_buf(),
            node_ids,
        );

        let phase = status.phase(&format!(
            "Running timeline ({}s, {} events, {} assertions)",
            scenario.duration_secs,
            scenario.events.len(),
            scenario.assertions.len()
        ));
        let result = executor
            .run_timeline(
                &scenario.events,
                &scenario.assertions,
                scenario.duration_secs,
            )
            .await;
        phase.done();

        if let Some(driver) = ns3_driver.as_mut() {
            for event in driver.drain_events() {
                metrics.log_ns3_event(event.payload);
            }
            if let Err(err) = driver.shutdown().await {
                tracing::warn!(error = %err, "failed to shutdown ns3 driver cleanly");
            }
        }

        let mut topo = topology.lock().await;

        if !self.keep_namespaces {
            let phase = status.phase("Cleaning up");
            topo.teardown().await?;
            phase.done();
        }

        let result = result?;

        let mut log_parser = LogParser::new();
        let mut all_events = Vec::new();

        for node in &scenario.nodes {
            let log_path = log_dir.join(format!("{}.stdout.log", node.id));
            let events = log_parser.parse_log_file(&node.id, &log_path);
            all_events.extend(events);
        }

        all_events.sort_by_key(|e| e.timestamp);

        if let Some(first_event) = all_events.first() {
            let scenario_start = first_event.timestamp;
            metrics.log_parsed_events(&all_events, scenario_start);

            let aggregated_metrics = log_parser.compute_metrics(&all_events);
            metrics.log_metrics_summary(&aggregated_metrics);

            tracing::info!(
                discoveries = aggregated_metrics.discovery_count,
                connections = aggregated_metrics.connection_count,
                avg_handshake_ms = ?aggregated_metrics.avg_handshake_ms(),
                "avenad metrics"
            );
        }

        metrics.log_scenario_completed(result.passed, result.duration_secs);
        metrics.flush();

        Ok(result)
    }
}

fn backend_uses_netem(backend: EmulationBackend) -> bool {
    matches!(backend, EmulationBackend::Netem)
}

async fn wait_for_node_ready(
    topology: &mut TestTopology,
    node_id: &str,
    log_dir: &Path,
) -> Result<bool, RunnerError> {
    let log_path = log_dir.join(format!("{}.stdout.log", node_id));
    let deadline = Instant::now() + NODE_STARTUP_TIMEOUT;

    loop {
        let process_exited = {
            let Some(instance) = topology.node_mut(node_id) else {
                return Ok(false);
            };

            let Some(proc) = instance.avenad_process.as_mut() else {
                return Ok(false);
            };

            match proc.try_wait() {
                Ok(Some(status)) => {
                    tracing::error!(
                        node = %node_id,
                        status = ?status,
                        log = %log_path.display(),
                        "avenad exited before startup readiness"
                    );
                    true
                }
                Ok(None) => false,
                Err(e) => return Err(RunnerError::Io(e)),
            }
        };

        let log_contents = std::fs::read_to_string(&log_path).unwrap_or_default();
        if node_startup_failed(&log_contents) {
            tracing::error!(
                node = %node_id,
                log = %log_path.display(),
                "avenad reported startup failure"
            );
            return Ok(false);
        }
        if node_startup_ready(&log_contents) {
            return Ok(true);
        }
        if process_exited {
            return Ok(false);
        }

        if Instant::now() >= deadline {
            tracing::error!(
                node = %node_id,
                log = %log_path.display(),
                timeout_secs = NODE_STARTUP_TIMEOUT.as_secs(),
                "timed out waiting for node startup readiness"
            );
            return Ok(false);
        }

        tokio::time::sleep(NODE_STARTUP_POLL_INTERVAL).await;
    }
}

fn node_startup_ready(log: &str) -> bool {
    log.contains("Discovery service initialized")
        || log.contains("Handshake listener bound")
        || log.contains("Avenad running. Press Ctrl+C to stop.")
}

fn node_startup_failed(log: &str) -> bool {
    log.contains("Failed to initialize avenad")
}

impl Default for TestRunner {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scenario::EmulationBackend;

    #[test]
    fn test_runner_builder() {
        let runner = TestRunner::new().keep_namespaces(true);
        assert!(runner.keep_namespaces);
    }

    #[test]
    fn node_startup_ready_detects_success_markers() {
        let log = "INFO avenad: Loaded configuration\nINFO avenad: Discovery service initialized\n";
        assert!(node_startup_ready(log));

        let log = "INFO avenad: Handshake listener bound\n";
        assert!(node_startup_ready(log));
    }

    #[test]
    fn node_startup_ready_ignores_early_non_ready_logs() {
        let log = "INFO avenad: Loaded configuration\nINFO avenad: Tunnel backend created\n";
        assert!(!node_startup_ready(log));
    }

    #[test]
    fn node_startup_failed_detects_init_failure_marker() {
        let log = "ERROR avenad: Failed to initialize avenad: tunnel error\n";
        assert!(node_startup_failed(log));
    }

    #[test]
    fn backend_uses_netem_only_for_netem_backend() {
        assert!(backend_uses_netem(EmulationBackend::Netem));
        assert!(!backend_uses_netem(EmulationBackend::Ns3));
    }
}
