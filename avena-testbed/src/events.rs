//! Timeline event execution and assertion checking.
//!
//! Executes scheduled events (link changes, node start/stop) and checks
//! assertions at specified times during scenario execution.

use crate::links::{LinkError, LinkManager};
use crate::metrics::{AvenadEventType, LogParser, MetricsLogger};
use crate::scenario::{AssertCondition, Assertion, Event, EventAction};
use crate::topology::{TestTopology, TopologyError};
use std::collections::HashMap;
use std::future::Future;
use std::path::PathBuf;
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

#[derive(Debug, Default)]
struct EventTracker {
    connection_counts: HashMap<String, usize>,
    log_positions: HashMap<String, u64>,
}

#[derive(Debug, Clone)]
struct LinkConvergenceState {
    link_id: String,
    node_a: String,
    node_b: String,
    underlay_up_ms: u64,
    baseline_connections_a: usize,
    baseline_connections_b: usize,
    first_peer_connected_ms: Option<u64>,
    first_overlay_ping_ms: Option<u64>,
}

#[derive(Debug, Clone)]
enum ExecutedEvent {
    LinkConnected { link_id: String },
}

const ASSERTION_PING_ATTEMPTS: usize = 5;
const ASSERTION_PING_RETRY_DELAY: Duration = Duration::from_millis(300);

impl EventTracker {
    fn update_from_logs(&mut self, node_ids: &[String], log_dir: &PathBuf) {
        let mut parser = LogParser::new();

        for node_id in node_ids {
            let log_path = log_dir.join(format!("{}.stdout.log", node_id));
            let pos = self.log_positions.entry(node_id.clone()).or_insert(0);

            let content = match std::fs::read_to_string(&log_path) {
                Ok(c) => c,
                Err(_) => continue,
            };

            let new_content = if (*pos as usize) < content.len() {
                &content[*pos as usize..]
            } else {
                continue;
            };

            *pos = content.len() as u64;

            let events = parser.parse_log_content(node_id, new_content);
            for event in events {
                if matches!(event.event_type, AvenadEventType::PeerConnected { .. }) {
                    *self.connection_counts.entry(node_id.clone()).or_insert(0) += 1;
                }
            }
        }
    }
}

fn link_nodes_from_link_id(link_id: &str) -> Option<(String, String)> {
    let (a, b) = link_id.split_once('-')?;
    Some((a.to_string(), b.to_string()))
}

fn same_unordered_pair(a1: &str, b1: &str, a2: &str, b2: &str) -> bool {
    (a1 == a2 && b1 == b2) || (a1 == b2 && b1 == a2)
}

pub struct EventExecutor {
    topology: Arc<Mutex<TestTopology>>,
    links: Arc<Mutex<LinkManager>>,
    metrics: Arc<MetricsLogger>,
    log_dir: PathBuf,
    node_ids: Vec<String>,
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
        log_dir: PathBuf,
        node_ids: Vec<String>,
    ) -> Self {
        Self {
            topology,
            links,
            metrics,
            log_dir,
            node_ids,
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

        let mut pending_assertions: Vec<&Assertion> = assertions.iter().collect();
        let mut ready_assertions: Vec<&Assertion> = Vec::new();

        let mut events_executed = 0;
        let mut assertions_run = 0;
        let mut assertions_passed = 0;

        let mut tracker = EventTracker::default();
        let mut link_convergence: HashMap<String, LinkConvergenceState> = HashMap::new();
        let mut latest_link_up: Option<String> = None;

        loop {
            let elapsed = start.elapsed().as_secs_f64();

            if elapsed >= duration_secs as f64 {
                break;
            }

            while event_iter.peek().is_some_and(|e| e.at_secs <= elapsed) {
                let event = event_iter.next().unwrap();
                if let Some(executed) = self.execute_event(event).await? {
                    match executed {
                        ExecutedEvent::LinkConnected { link_id } => {
                            if let Some((node_a, node_b)) = link_nodes_from_link_id(&link_id) {
                                let baseline_connections_a =
                                    *tracker.connection_counts.get(&node_a).unwrap_or(&0);
                                let baseline_connections_b =
                                    *tracker.connection_counts.get(&node_b).unwrap_or(&0);
                                link_convergence.insert(
                                    link_id.clone(),
                                    LinkConvergenceState {
                                        link_id: link_id.clone(),
                                        node_a,
                                        node_b,
                                        underlay_up_ms: (elapsed * 1000.0) as u64,
                                        baseline_connections_a,
                                        baseline_connections_b,
                                        first_peer_connected_ms: None,
                                        first_overlay_ping_ms: None,
                                    },
                                );
                                latest_link_up = Some(link_id);
                            }
                        }
                    }
                }
                events_executed += 1;
            }

            tracker.update_from_logs(&self.node_ids, &self.log_dir);

            let elapsed_ms = (elapsed * 1000.0) as u64;
            for state in link_convergence.values_mut() {
                if state.first_peer_connected_ms.is_some() {
                    continue;
                }

                let connected_a = *tracker
                    .connection_counts
                    .get(&state.node_a)
                    .unwrap_or(&0)
                    > state.baseline_connections_a;
                let connected_b = *tracker
                    .connection_counts
                    .get(&state.node_b)
                    .unwrap_or(&0)
                    > state.baseline_connections_b;

                if connected_a || connected_b {
                    state.first_peer_connected_ms = Some(elapsed_ms);
                    let value_ms = elapsed_ms.saturating_sub(state.underlay_up_ms);
                    self.metrics.log_convergence_metric(
                        "underlay_up_to_first_peer_connected_ms",
                        &state.link_id,
                        &state.node_a,
                        &state.node_b,
                        state.underlay_up_ms,
                        elapsed_ms,
                        value_ms,
                    );
                }
            }

            let mut still_pending = Vec::new();
            for assertion in pending_assertions.drain(..) {
                if should_run_assertion(assertion, elapsed, &tracker) {
                    ready_assertions.push(assertion);
                } else {
                    still_pending.push(assertion);
                }
            }
            pending_assertions = still_pending;

            ready_assertions.sort_by(|a, b| a.at_secs.partial_cmp(&b.at_secs).unwrap());

            for assertion in ready_assertions.drain(..) {
                assertions_run += 1;
                match self.check_assertion(assertion).await {
                    Ok(()) => {
                        if let AssertCondition::Ping { from, to, .. } = &assertion.condition {
                            let selected_link = link_convergence
                                .iter()
                                .find_map(|(link_id, state)| {
                                    if same_unordered_pair(&state.node_a, &state.node_b, from, to) {
                                        Some(link_id.clone())
                                    } else {
                                        None
                                    }
                                })
                                .or_else(|| latest_link_up.clone());

                            if let Some(link_id) = selected_link {
                                if let Some(state) = link_convergence.get_mut(&link_id) {
                                    if state.first_overlay_ping_ms.is_none() {
                                        state.first_overlay_ping_ms = Some(elapsed_ms);
                                        let value_ms =
                                            elapsed_ms.saturating_sub(state.underlay_up_ms);
                                        self.metrics.log_convergence_metric(
                                            "underlay_up_to_first_successful_overlay_ping_ms",
                                            &state.link_id,
                                            from,
                                            to,
                                            state.underlay_up_ms,
                                            elapsed_ms,
                                            value_ms,
                                        );
                                    }
                                }
                            }
                        }

                        if let AssertCondition::NodesConnected { nodes } = &assertion.condition {
                            if nodes.len() >= 2 {
                                let from = &nodes[0];
                                let to = &nodes[1];
                                if let Some((_, state)) = link_convergence.iter_mut().find(|(_, s)| {
                                    same_unordered_pair(&s.node_a, &s.node_b, from, to)
                                }) {
                                    if state.first_peer_connected_ms.is_none() {
                                        state.first_peer_connected_ms = Some(elapsed_ms);
                                        let value_ms =
                                            elapsed_ms.saturating_sub(state.underlay_up_ms);
                                        self.metrics.log_convergence_metric(
                                            "underlay_up_to_first_peer_connected_ms",
                                            &state.link_id,
                                            from,
                                            to,
                                            state.underlay_up_ms,
                                            elapsed_ms,
                                            value_ms,
                                        );
                                    }
                                }
                            }
                        }

                        assertions_passed += 1;
                        self.metrics.log_assertion_result(assertion, true);
                        tracing::debug!(
                            condition = ?assertion.condition,
                            elapsed_secs = elapsed,
                            deadline_secs = assertion.at_secs,
                            "assertion passed"
                        );
                    }
                    Err(e) => {
                        self.metrics.log_assertion_result(assertion, false);
                        return Err(e);
                    }
                }
            }

            if event_iter.peek().is_none() && pending_assertions.is_empty() {
                break;
            }

            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        Ok(TestResult {
            passed: assertions_passed == assertions_run,
            assertions_run,
            assertions_passed,
            events_executed,
            duration_secs: start.elapsed().as_secs_f64(),
        })
    }

    async fn execute_event(&self, event: &Event) -> Result<Option<ExecutedEvent>, EventError> {
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
                return Ok(Some(ExecutedEvent::LinkConnected { link_id }));
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
                links
                    .modify_link(&link_id, *latency_ms, *loss_percent)
                    .await?;
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
        Ok(None)
    }

    async fn check_assertion(&self, assertion: &Assertion) -> Result<(), EventError> {
        match &assertion.condition {
            AssertCondition::NodesConnected { nodes } => {
                self.check_nodes_connected(nodes, assertion.at_secs).await
            }
            AssertCondition::Ping {
                from,
                to,
                timeout_ms,
            } => {
                self.check_ping(from, to, *timeout_ms, assertion.at_secs)
                    .await
            }
            AssertCondition::PeerCount { node, count } => {
                self.check_peer_count(node, *count, assertion.at_secs).await
            }
        }
    }

    async fn check_nodes_connected(
        &self,
        nodes: &[String],
        at_secs: f64,
    ) -> Result<(), EventError> {
        if nodes.len() >= 2 {
            let from = &nodes[0];
            let underlay_ip = {
                let topology = self.topology.lock().await;
                topology.node(&nodes[1]).and_then(|to_node| {
                    to_node
                        .underlay_ips
                        .first()
                        .map(|(_, underlay_ip)| *underlay_ip)
                })
            };

            if let Some(underlay_ip) = underlay_ip {
                let underlay_ip_str = underlay_ip.to_string();
                let output = {
                    let topology = self.topology.lock().await;
                    topology
                        .exec_in_node(from, &["ping", "-c", "1", "-W", "1", &underlay_ip_str])
                        .await?
                };
                tracing::debug!(
                    from = %from,
                    to_underlay = %underlay_ip,
                    success = output.status.success(),
                    "underlay connectivity check"
                );
            }
        }

        for i in 0..nodes.len() {
            for j in (i + 1)..nodes.len() {
                let from = &nodes[i];
                let to = &nodes[j];

                let overlay_ip = {
                    let topology = self.topology.lock().await;
                    let to_node = topology
                        .node(to)
                        .ok_or_else(|| TopologyError::NodeNotFound(to.clone()))?;
                    to_node.overlay_ip
                };

                let ip_str = overlay_ip.to_string();
                let connected = retry_until_success::<_, _, EventError>(
                    ASSERTION_PING_ATTEMPTS,
                    ASSERTION_PING_RETRY_DELAY,
                    |attempt| {
                        let ip_str = ip_str.clone();
                        async move {
                            let output = {
                                let topology = self.topology.lock().await;
                                topology
                                    .exec_in_node(
                                        from,
                                        &["ping", "-6", "-c", "1", "-W", "2", &ip_str],
                                    )
                                    .await?
                            };

                            if !output.status.success() {
                                tracing::debug!(
                                    from = %from,
                                    to = %to,
                                    overlay_ip = %ip_str,
                                    attempt = attempt + 1,
                                    stderr = %String::from_utf8_lossy(&output.stderr),
                                    stdout = %String::from_utf8_lossy(&output.stdout),
                                    "ping probe failed"
                                );
                            }

                            Ok(output.status.success())
                        }
                    },
                )
                .await?;

                if !connected {
                    return Err(EventError::AssertionFailed {
                        at_secs,
                        message: format!(
                            "nodes {from} and {to} are not connected after {ASSERTION_PING_ATTEMPTS} probes"
                        ),
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
        let overlay_ip = {
            let topology = self.topology.lock().await;
            let to_node = topology
                .node(to)
                .ok_or_else(|| TopologyError::NodeNotFound(to.to_string()))?;
            to_node.overlay_ip
        };

        let timeout_secs = (timeout_ms as f64 / 1000.0).ceil() as u32;
        let timeout_arg = timeout_secs.max(1).to_string();

        let ip_str = overlay_ip.to_string();
        let connected = retry_until_success::<_, _, EventError>(
            ASSERTION_PING_ATTEMPTS,
            ASSERTION_PING_RETRY_DELAY,
            |attempt| {
                let timeout_arg = timeout_arg.clone();
                let ip_str = ip_str.clone();
                async move {
                    let output = {
                        let topology = self.topology.lock().await;
                        topology
                            .exec_in_node(
                                from,
                                &["ping", "-6", "-c", "1", "-W", &timeout_arg, &ip_str],
                            )
                            .await?
                    };

                    if !output.status.success() {
                        tracing::debug!(
                            from = %from,
                            to = %to,
                            overlay_ip = %ip_str,
                            attempt = attempt + 1,
                            stderr = %String::from_utf8_lossy(&output.stderr),
                            stdout = %String::from_utf8_lossy(&output.stdout),
                            "explicit ping probe failed"
                        );
                    }

                    Ok(output.status.success())
                }
            },
        )
        .await?;

        if !connected {
            let route_output = {
                let topology = self.topology.lock().await;
                topology
                    .exec_in_node(from, &["ip", "-6", "route"])
                    .await
                    .ok()
            };
            if let Some(output) = route_output {
                tracing::debug!(
                    from = %from,
                    route_stdout = %String::from_utf8_lossy(&output.stdout),
                    route_stderr = %String::from_utf8_lossy(&output.stderr),
                    "route table snapshot on ping failure"
                );
            }

            let wg_output = {
                let topology = self.topology.lock().await;
                topology
                    .exec_in_node(from, &["wg", "show", &format!("wg-{from}")])
                    .await
                    .ok()
            };
            if let Some(output) = wg_output {
                tracing::debug!(
                    from = %from,
                    wg_stdout = %String::from_utf8_lossy(&output.stdout),
                    wg_stderr = %String::from_utf8_lossy(&output.stderr),
                    "wireguard snapshot on ping failure"
                );
            }

            return Err(EventError::AssertionFailed {
                at_secs,
                message: format!(
                    "ping from {from} to {to} failed after {ASSERTION_PING_ATTEMPTS} probes"
                ),
            });
        }
        Ok(())
    }

    async fn check_peer_count(
        &self,
        node: &str,
        expected: usize,
        at_secs: f64,
    ) -> Result<(), EventError> {
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
                message: format!("node {node} has {peer_count} peers, expected {expected}"),
            });
        }
        Ok(())
    }
}

fn should_run_assertion(assertion: &Assertion, elapsed_secs: f64, _tracker: &EventTracker) -> bool {
    elapsed_secs >= assertion.at_secs
}

async fn retry_until_success<F, Fut, E>(
    attempts: usize,
    delay: Duration,
    mut operation: F,
) -> Result<bool, E>
where
    F: FnMut(usize) -> Fut,
    Fut: Future<Output = Result<bool, E>>,
{
    if attempts == 0 {
        return Ok(false);
    }

    for attempt in 0..attempts {
        if operation(attempt).await? {
            return Ok(true);
        }

        if attempt + 1 < attempts {
            tokio::time::sleep(delay).await;
        }
    }

    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scenario::AssertCondition;

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

    #[test]
    fn assertion_not_ready_before_scheduled_time_even_when_requirements_met() {
        let assertion = Assertion {
            at_secs: 15.0,
            condition: AssertCondition::NodesConnected {
                nodes: vec!["nodeA".to_string(), "nodeB".to_string()],
            },
        };

        let mut tracker = EventTracker::default();
        tracker.connection_counts.insert("nodeA".to_string(), 1);
        tracker.connection_counts.insert("nodeB".to_string(), 1);

        assert!(!should_run_assertion(&assertion, 2.0, &tracker));
    }

    #[test]
    fn assertion_ready_once_scheduled_time_is_reached() {
        let assertion = Assertion {
            at_secs: 15.0,
            condition: AssertCondition::Ping {
                from: "nodeA".to_string(),
                to: "nodeB".to_string(),
                timeout_ms: 1000,
            },
        };

        let tracker = EventTracker::default();

        assert!(should_run_assertion(&assertion, 15.0, &tracker));
        assert!(should_run_assertion(&assertion, 20.0, &tracker));
    }

    #[tokio::test]
    async fn retry_until_success_handles_transient_failures() {
        use std::cell::Cell;

        let remaining_failures = Cell::new(2usize);

        let ok = retry_until_success(4, Duration::ZERO, |_| {
            let should_succeed = remaining_failures.get() == 0;
            if !should_succeed {
                remaining_failures.set(remaining_failures.get() - 1);
            }
            std::future::ready(Ok::<bool, ()>(should_succeed))
        })
        .await
        .unwrap();

        assert!(ok);
    }

    #[tokio::test]
    async fn retry_until_success_stops_after_attempt_budget() {
        use std::cell::Cell;

        let calls = Cell::new(0usize);

        let ok = retry_until_success(3, Duration::ZERO, |_| {
            calls.set(calls.get() + 1);
            std::future::ready(Ok::<bool, ()>(false))
        })
        .await
        .unwrap();

        assert!(!ok);
        assert_eq!(calls.get(), 3);
    }
}
