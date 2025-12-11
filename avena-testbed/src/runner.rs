//! Full test scenario orchestration.
//!
//! Coordinates PKI generation, topology setup, link configuration,
//! event timeline execution, and teardown.

use crate::events::{EventError, EventExecutor, TestResult};
use crate::links::LinkManager;
use crate::metrics::{LogParser, MetricsLogger};
use crate::pki::TestPki;
use crate::scenario::Scenario;
use crate::topology::TestTopology;
use std::path::Path;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::Mutex;

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

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
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
        tracing::debug!("creating metrics logger at {:?}", output_path);
        let metrics = Arc::new(MetricsLogger::new(output_path)?);
        metrics.log_scenario_started(&scenario.name);

        tracing::debug!("generating PKI");
        let pki = TestPki::generate(&scenario.nodes)?;

        tracing::debug!("setting up topology");
        let mut topology = TestTopology::new();
        topology.setup(scenario, &pki).await?;

        let log_dir = output_path.parent().unwrap_or(std::path::Path::new("."));
        topology.start_nodes(&pki, scenario, log_dir).await?;

        let mut links = LinkManager::new();
        links.initialize_from_topology(&topology, &scenario.links, &scenario.bridges);
        links.apply_initial_state().await?;

        for node in &scenario.nodes {
            let config_path = pki.temp_dir().join(format!("{}.toml", node.id));
            if let Ok(content) = std::fs::read_to_string(&config_path) {
                tracing::debug!(node = %node.id, config = %content, "generated config");
            }
        }

        tokio::time::sleep(std::time::Duration::from_secs(2)).await;

        for node in &scenario.nodes {
            if let Some(instance) = topology.node_mut(&node.id) {
                metrics.log_node_started(&node.id, &instance.overlay_ip);

                if let Some(ref mut proc) = instance.avenad_process {
                    match proc.try_wait() {
                        Ok(Some(status)) => {
                            let log_path = log_dir.join(format!("{}.stdout.log", node.id));
                            tracing::error!(
                                node = %node.id,
                                status = ?status,
                                log = %log_path.display(),
                                "avenad exited prematurely - check log file"
                            );
                        }
                        Ok(None) => {
                            tracing::info!(
                                node = %node.id,
                                overlay_ip = %instance.overlay_ip,
                                "node running"
                            );
                        }
                        Err(e) => {
                            tracing::error!(node = %node.id, error = %e, "failed to check process");
                        }
                    }
                }
            }
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

        let result = executor
            .run_timeline(&scenario.events, &scenario.assertions, scenario.duration_secs)
            .await;

        let mut topo = topology.lock().await;

        if !self.keep_namespaces {
            topo.teardown().await?;
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

impl Default for TestRunner {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_runner_builder() {
        let runner = TestRunner::new().keep_namespaces(true);
        assert!(runner.keep_namespaces);
    }
}
