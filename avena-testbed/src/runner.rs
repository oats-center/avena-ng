//! Full test scenario orchestration.
//!
//! Coordinates PKI generation, topology setup, link configuration,
//! event timeline execution, and teardown.

use crate::events::{EventError, EventExecutor, TestResult};
use crate::links::LinkManager;
use crate::metrics::MetricsLogger;
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
        let metrics = Arc::new(MetricsLogger::new(output_path)?);
        metrics.log_scenario_started(&scenario.name);

        let pki = TestPki::generate(&scenario.nodes)?;

        let mut topology = TestTopology::new();
        topology.setup(scenario, &pki).await?;

        let mut links = LinkManager::new();
        links.initialize_from_topology(&topology, &scenario.links);
        links.apply_initial_state().await?;

        topology.start_nodes(&pki, scenario).await?;

        for node in &scenario.nodes {
            if let Some(instance) = topology.node(&node.id) {
                metrics.log_node_started(&node.id, &instance.overlay_ip);
            }
        }

        let topology = Arc::new(Mutex::new(topology));
        let links = Arc::new(Mutex::new(links));

        let executor = EventExecutor::new(
            Arc::clone(&topology),
            Arc::clone(&links),
            Arc::clone(&metrics),
        );

        let result = executor
            .run_timeline(&scenario.events, &scenario.assertions, scenario.duration_secs)
            .await;

        let mut topo = topology.lock().await;

        if !self.keep_namespaces {
            topo.teardown().await?;
        }

        let result = result?;
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
