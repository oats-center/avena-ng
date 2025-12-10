//! Timeline event execution and assertion checking.
//!
//! Executes scheduled events (link changes, node start/stop) and checks
//! assertions at specified times during scenario execution.

use crate::links::{LinkError, LinkManager};
use crate::metrics::MetricsLogger;
use crate::scenario::{AssertCondition, Assertion, Event, EventAction};
use crate::topology::{TestTopology, TopologyError};
use std::sync::Arc;
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::sync::Mutex;

#[derive(Error, Debug)]
pub enum EventError {
    #[error("topology error: {0}")]
    Topology(#[from] TopologyError),

    #[error("link error: {0}")]
    Link(#[from] LinkError),

    #[error("assertion failed at {at_secs}s: {message}")]
    AssertionFailed { at_secs: f64, message: String },

    #[error("unknown link reference: {0}")]
    UnknownLink(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Debug)]
pub struct TestResult {
    pub passed: bool,
    pub assertions_run: usize,
    pub assertions_passed: usize,
    pub events_executed: usize,
    pub duration_secs: f64,
}

pub struct EventExecutor {
    topology: Arc<Mutex<TestTopology>>,
    links: Arc<Mutex<LinkManager>>,
    metrics: Arc<MetricsLogger>,
}

impl std::fmt::Debug for EventExecutor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EventExecutor").finish_non_exhaustive()
    }
}

impl EventExecutor {
    pub fn new(
        topology: Arc<Mutex<TestTopology>>,
        links: Arc<Mutex<LinkManager>>,
        metrics: Arc<MetricsLogger>,
    ) -> Self {
        Self {
            topology,
            links,
            metrics,
        }
    }

    pub async fn run_timeline(
        &self,
        events: &[Event],
        assertions: &[Assertion],
        duration_secs: u64,
    ) -> Result<TestResult, EventError> {
        let start = Instant::now();
        let mut event_iter = events.iter().peekable();
        let mut assert_iter = assertions.iter().peekable();

        let mut events_executed = 0;
        let mut assertions_run = 0;
        let mut assertions_passed = 0;

        loop {
            let elapsed = start.elapsed().as_secs_f64();

            if elapsed >= duration_secs as f64 {
                break;
            }

            while event_iter
                .peek()
                .is_some_and(|e| e.at_secs <= elapsed)
            {
                let event = event_iter.next().unwrap();
                self.execute_event(event).await?;
                events_executed += 1;
            }

            while assert_iter
                .peek()
                .is_some_and(|a| a.at_secs <= elapsed)
            {
                let assertion = assert_iter.next().unwrap();
                assertions_run += 1;
                match self.check_assertion(assertion).await {
                    Ok(()) => {
                        assertions_passed += 1;
                        self.metrics.log_assertion_result(assertion, true);
                    }
                    Err(e) => {
                        self.metrics.log_assertion_result(assertion, false);
                        return Err(e);
                    }
                }
            }

            if event_iter.peek().is_none() && assert_iter.peek().is_none() {
                tokio::time::sleep(Duration::from_millis(100)).await;
                if start.elapsed().as_secs_f64() >= duration_secs as f64 {
                    break;
                }
            } else {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }

        Ok(TestResult {
            passed: assertions_passed == assertions_run,
            assertions_run,
            assertions_passed,
            events_executed,
            duration_secs: start.elapsed().as_secs_f64(),
        })
    }

    async fn execute_event(&self, event: &Event) -> Result<(), EventError> {
        match &event.action {
            EventAction::DisconnectLink { link } => {
                let mut links = self.links.lock().await;
                let link_id = links
                    .link_id_from_ref(link)
                    .ok_or_else(|| EventError::UnknownLink(link.clone()))?;
                links.set_link_enabled(&link_id, false).await?;
                self.metrics.log_link_changed(&link_id, false);
            }
            EventAction::ConnectLink { link } => {
                let mut links = self.links.lock().await;
                let link_id = links
                    .link_id_from_ref(link)
                    .ok_or_else(|| EventError::UnknownLink(link.clone()))?;
                links.set_link_enabled(&link_id, true).await?;
                self.metrics.log_link_changed(&link_id, true);
            }
            EventAction::ModifyLink {
                link,
                latency_ms,
                loss_percent,
            } => {
                let mut links = self.links.lock().await;
                let link_id = links
                    .link_id_from_ref(link)
                    .ok_or_else(|| EventError::UnknownLink(link.clone()))?;
                links.modify_link(&link_id, *latency_ms, *loss_percent).await?;
            }
            EventAction::StopNode { node } => {
                let mut topology = self.topology.lock().await;
                topology.stop_node(node).await?;
            }
            EventAction::StartNode { node } => {
                let topology = self.topology.lock().await;
                topology.start_node(node).await?;
            }
        }
        Ok(())
    }

    async fn check_assertion(&self, assertion: &Assertion) -> Result<(), EventError> {
        match &assertion.condition {
            AssertCondition::NodesConnected { nodes } => {
                self.check_nodes_connected(nodes, assertion.at_secs).await
            }
            AssertCondition::Ping { from, to, timeout_ms } => {
                self.check_ping(from, to, *timeout_ms, assertion.at_secs).await
            }
            AssertCondition::PeerCount { node, count } => {
                self.check_peer_count(node, *count, assertion.at_secs).await
            }
        }
    }

    async fn check_nodes_connected(&self, nodes: &[String], at_secs: f64) -> Result<(), EventError> {
        let topology = self.topology.lock().await;

        for i in 0..nodes.len() {
            for j in (i + 1)..nodes.len() {
                let from = &nodes[i];
                let to = &nodes[j];

                let to_node = topology
                    .node(to)
                    .ok_or_else(|| TopologyError::NodeNotFound(to.clone()))?;
                let overlay_ip = to_node.overlay_ip;

                let output = topology
                    .exec_in_node(from, &["ping", "-c", "1", "-W", "2", &overlay_ip.to_string()])
                    .await?;

                if !output.status.success() {
                    return Err(EventError::AssertionFailed {
                        at_secs,
                        message: format!("nodes {from} and {to} are not connected"),
                    });
                }
            }
        }
        Ok(())
    }

    async fn check_ping(
        &self,
        from: &str,
        to: &str,
        timeout_ms: u32,
        at_secs: f64,
    ) -> Result<(), EventError> {
        let topology = self.topology.lock().await;

        let to_node = topology
            .node(to)
            .ok_or_else(|| TopologyError::NodeNotFound(to.to_string()))?;
        let overlay_ip = to_node.overlay_ip;

        let timeout_secs = (timeout_ms as f64 / 1000.0).ceil() as u32;
        let timeout_arg = timeout_secs.max(1).to_string();

        let output = topology
            .exec_in_node(from, &["ping", "-c", "1", "-W", &timeout_arg, &overlay_ip.to_string()])
            .await?;

        if !output.status.success() {
            return Err(EventError::AssertionFailed {
                at_secs,
                message: format!("ping from {from} to {to} failed"),
            });
        }
        Ok(())
    }

    async fn check_peer_count(&self, node: &str, expected: usize, at_secs: f64) -> Result<(), EventError> {
        let topology = self.topology.lock().await;

        let output = topology
            .exec_in_node(node, &["wg", "show", &format!("wg-{node}"), "peers"])
            .await?;

        if !output.status.success() {
            return Err(EventError::AssertionFailed {
                at_secs,
                message: format!("failed to get peer count for node {node}"),
            });
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let peer_count = stdout.lines().filter(|l| !l.is_empty()).count();

        if peer_count != expected {
            return Err(EventError::AssertionFailed {
                at_secs,
                message: format!(
                    "node {node} has {peer_count} peers, expected {expected}"
                ),
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_result_default() {
        let result = TestResult {
            passed: true,
            assertions_run: 5,
            assertions_passed: 5,
            events_executed: 10,
            duration_secs: 60.0,
        };
        assert!(result.passed);
        assert_eq!(result.assertions_run, result.assertions_passed);
    }
}
