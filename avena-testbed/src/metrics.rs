//! Structured jsonl event logging for testbed execution.
//!
//! Logs scenario events, node lifecycle, peer connections, and assertion
//! results to a jsonl file for post-hoc analysis.

use crate::scenario::Assertion;
use serde::Serialize;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::net::Ipv6Addr;
use std::path::Path;
use std::sync::Mutex;
use std::time::Instant;

#[derive(Debug, Serialize)]
pub struct MetricEvent {
    pub timestamp_ms: u64,
    pub event_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub node: Option<String>,
    pub data: serde_json::Value,
}

pub struct MetricsLogger {
    output: Mutex<BufWriter<File>>,
    start: Instant,
}

impl std::fmt::Debug for MetricsLogger {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MetricsLogger").finish_non_exhaustive()
    }
}

impl MetricsLogger {
    pub fn new(output_path: &Path) -> std::io::Result<Self> {
        let file = File::create(output_path)?;
        let output = BufWriter::new(file);
        Ok(Self {
            output: Mutex::new(output),
            start: Instant::now(),
        })
    }

    pub fn log(&self, event: MetricEvent) {
        if let Ok(json) = serde_json::to_string(&event) {
            if let Ok(mut output) = self.output.lock() {
                let _ = writeln!(output, "{json}");
            }
        }
    }

    fn elapsed_ms(&self) -> u64 {
        self.start.elapsed().as_millis() as u64
    }

    pub fn log_scenario_started(&self, name: &str) {
        self.log(MetricEvent {
            timestamp_ms: self.elapsed_ms(),
            event_type: "scenario_started".to_string(),
            node: None,
            data: serde_json::json!({ "name": name }),
        });
    }

    pub fn log_scenario_completed(&self, passed: bool, duration_secs: f64) {
        self.log(MetricEvent {
            timestamp_ms: self.elapsed_ms(),
            event_type: "scenario_completed".to_string(),
            node: None,
            data: serde_json::json!({
                "passed": passed,
                "duration_secs": duration_secs
            }),
        });
    }

    pub fn log_node_started(&self, node: &str, overlay_ip: &Ipv6Addr) {
        self.log(MetricEvent {
            timestamp_ms: self.elapsed_ms(),
            event_type: "node_started".to_string(),
            node: Some(node.to_string()),
            data: serde_json::json!({ "overlay_ip": overlay_ip.to_string() }),
        });
    }

    pub fn log_node_stopped(&self, node: &str) {
        self.log(MetricEvent {
            timestamp_ms: self.elapsed_ms(),
            event_type: "node_stopped".to_string(),
            node: Some(node.to_string()),
            data: serde_json::json!({}),
        });
    }

    pub fn log_peer_discovered(&self, node: &str, peer: &str) {
        self.log(MetricEvent {
            timestamp_ms: self.elapsed_ms(),
            event_type: "peer_discovered".to_string(),
            node: Some(node.to_string()),
            data: serde_json::json!({ "peer": peer }),
        });
    }

    pub fn log_peer_connected(&self, node: &str, peer: &str, handshake_ms: u64) {
        self.log(MetricEvent {
            timestamp_ms: self.elapsed_ms(),
            event_type: "peer_connected".to_string(),
            node: Some(node.to_string()),
            data: serde_json::json!({
                "peer": peer,
                "handshake_ms": handshake_ms
            }),
        });
    }

    pub fn log_link_changed(&self, link: &str, enabled: bool) {
        self.log(MetricEvent {
            timestamp_ms: self.elapsed_ms(),
            event_type: "link_changed".to_string(),
            node: None,
            data: serde_json::json!({
                "link": link,
                "enabled": enabled
            }),
        });
    }

    pub fn log_assertion_result(&self, assertion: &Assertion, passed: bool) {
        let condition_type = match &assertion.condition {
            crate::scenario::AssertCondition::NodesConnected { .. } => "NodesConnected",
            crate::scenario::AssertCondition::Ping { .. } => "Ping",
            crate::scenario::AssertCondition::PeerCount { .. } => "PeerCount",
        };

        self.log(MetricEvent {
            timestamp_ms: self.elapsed_ms(),
            event_type: "assertion_result".to_string(),
            node: None,
            data: serde_json::json!({
                "condition": condition_type,
                "at_secs": assertion.at_secs,
                "passed": passed
            }),
        });
    }

    pub fn log_avenad_event(&self, node: &str, event_json: &str) {
        if let Ok(data) = serde_json::from_str::<serde_json::Value>(event_json) {
            self.log(MetricEvent {
                timestamp_ms: self.elapsed_ms(),
                event_type: "avenad_event".to_string(),
                node: Some(node.to_string()),
                data,
            });
        }
    }

    pub fn flush(&self) {
        if let Ok(mut output) = self.output.lock() {
            let _ = output.flush();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn test_metrics_logger_writes_jsonl() {
        let temp = NamedTempFile::new().unwrap();
        let logger = MetricsLogger::new(temp.path()).unwrap();

        logger.log_scenario_started("test-scenario");
        logger.log_node_started("gateway", &"fd00::1".parse().unwrap());
        logger.log_link_changed("gateway-sensor", true);
        logger.flush();

        let content = std::fs::read_to_string(temp.path()).unwrap();
        let lines: Vec<&str> = content.lines().collect();

        assert_eq!(lines.len(), 3);
        assert!(lines[0].contains("scenario_started"));
        assert!(lines[1].contains("node_started"));
        assert!(lines[2].contains("link_changed"));
    }
}
