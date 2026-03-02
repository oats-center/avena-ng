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
            crate::scenario::AssertCondition::TunnelInterfaceCount { .. } => "TunnelInterfaceCount",
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

    pub fn log_convergence_metric(
        &self,
        metric: &str,
        link: &str,
        from: &str,
        to: &str,
        underlay_up_ms: u64,
        observed_ms: u64,
        value_ms: u64,
    ) {
        self.log(MetricEvent {
            timestamp_ms: self.elapsed_ms(),
            event_type: "convergence_metric".to_string(),
            node: None,
            data: serde_json::json!({
                "metric": metric,
                "link": link,
                "from": from,
                "to": to,
                "underlay_up_ms": underlay_up_ms,
                "observed_ms": observed_ms,
                "value_ms": value_ms
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

    pub fn log_ns3_event(&self, data: serde_json::Value) {
        self.log(MetricEvent {
            timestamp_ms: self.elapsed_ms(),
            event_type: "ns3_event".to_string(),
            node: None,
            data,
        });
    }

    pub fn flush(&self) {
        if let Ok(mut output) = self.output.lock() {
            let _ = output.flush();
        }
    }

    pub fn log_parsed_events(
        &self,
        events: &[ParsedAvenadEvent],
        scenario_start: chrono::DateTime<chrono::Utc>,
    ) {
        for event in events {
            let timestamp_ms = event
                .timestamp
                .signed_duration_since(scenario_start)
                .num_milliseconds()
                .max(0) as u64;

            let (event_type, data) = match &event.event_type {
                AvenadEventType::PeerDiscovered { peer_id, endpoint } => (
                    "peer_discovered",
                    serde_json::json!({
                        "peer_id": peer_id,
                        "endpoint": endpoint
                    }),
                ),
                AvenadEventType::HandshakeStarted { peer_id } => (
                    "handshake_started",
                    serde_json::json!({
                        "peer_id": peer_id
                    }),
                ),
                AvenadEventType::PeerConnected { peer_id } => (
                    "peer_connected",
                    serde_json::json!({
                        "peer_id": peer_id
                    }),
                ),
                AvenadEventType::PeerDisconnected { peer_id, reason } => (
                    "peer_disconnected",
                    serde_json::json!({
                        "peer_id": peer_id,
                        "reason": reason
                    }),
                ),
                AvenadEventType::Unknown { message } => (
                    "unknown_event",
                    serde_json::json!({
                        "message": message
                    }),
                ),
            };

            self.log(MetricEvent {
                timestamp_ms,
                event_type: event_type.to_string(),
                node: Some(event.node.clone()),
                data,
            });
        }
    }

    pub fn log_metrics_summary(&self, metrics: &AvenadMetrics) {
        self.log(MetricEvent {
            timestamp_ms: self.elapsed_ms(),
            event_type: "metrics_summary".to_string(),
            node: None,
            data: serde_json::json!({
                "discovery_count": metrics.discovery_count,
                "connection_count": metrics.connection_count,
                "disconnection_count": metrics.disconnection_count,
                "handshake_attempts": metrics.handshake_attempts,
                "avg_handshake_ms": metrics.avg_handshake_ms(),
                "handshake_times_ms": metrics.handshake_times_ms
            }),
        });
    }
}

#[derive(Debug, Clone)]
pub struct ParsedAvenadEvent {
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub node: String,
    pub event_type: AvenadEventType,
}

#[derive(Debug, Clone)]
pub enum AvenadEventType {
    PeerDiscovered { peer_id: String, endpoint: String },
    HandshakeStarted { peer_id: String },
    PeerConnected { peer_id: String },
    PeerDisconnected { peer_id: String, reason: String },
    Unknown { message: String },
}

#[derive(Debug)]
pub struct LogParser {
    scenario_start: Option<chrono::DateTime<chrono::Utc>>,
}

impl LogParser {
    pub fn new() -> Self {
        Self {
            scenario_start: None,
        }
    }

    pub fn parse_log_file(&mut self, node_id: &str, path: &Path) -> Vec<ParsedAvenadEvent> {
        let content = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(_) => return Vec::new(),
        };

        self.parse_log_content(node_id, &content)
    }

    pub fn parse_log_content(&mut self, node_id: &str, content: &str) -> Vec<ParsedAvenadEvent> {
        let mut events = Vec::new();

        for line in content.lines() {
            if let Some(event) = self.parse_line(node_id, line) {
                if self.scenario_start.is_none() {
                    self.scenario_start = Some(event.timestamp);
                }
                events.push(event);
            }
        }

        events
    }

    fn parse_line(&self, node_id: &str, line: &str) -> Option<ParsedAvenadEvent> {
        let stripped = strip_ansi_codes(line);

        let timestamp = parse_timestamp(&stripped)?;

        if stripped.contains("Peer discovered") {
            let peer_id = extract_field(&stripped, "peer_id=")?;
            let endpoint = extract_field(&stripped, "endpoint=").unwrap_or_default();
            return Some(ParsedAvenadEvent {
                timestamp,
                node: node_id.to_string(),
                event_type: AvenadEventType::PeerDiscovered { peer_id, endpoint },
            });
        }

        if stripped.contains("Peer connected") {
            let peer_id = extract_field(&stripped, "peer_id=")?;
            return Some(ParsedAvenadEvent {
                timestamp,
                node: node_id.to_string(),
                event_type: AvenadEventType::PeerConnected { peer_id },
            });
        }

        if stripped.contains("Starting handshake") || stripped.contains("Initiating handshake") {
            let peer_id = extract_field(&stripped, "peer_id=")
                .or_else(|| extract_field(&stripped, "peer="))?;
            return Some(ParsedAvenadEvent {
                timestamp,
                node: node_id.to_string(),
                event_type: AvenadEventType::HandshakeStarted { peer_id },
            });
        }

        if stripped.contains("Peer disconnected") || stripped.contains("peer timed out") {
            let peer_id = extract_field(&stripped, "peer_id=")
                .or_else(|| extract_field(&stripped, "peer="))
                .unwrap_or_default();
            let reason = if stripped.contains("timed out") {
                "timeout".to_string()
            } else {
                "disconnected".to_string()
            };
            return Some(ParsedAvenadEvent {
                timestamp,
                node: node_id.to_string(),
                event_type: AvenadEventType::PeerDisconnected { peer_id, reason },
            });
        }

        None
    }

    pub fn compute_metrics(&self, events: &[ParsedAvenadEvent]) -> AvenadMetrics {
        let mut metrics = AvenadMetrics::default();

        let mut discovery_times: std::collections::HashMap<
            (String, String),
            chrono::DateTime<chrono::Utc>,
        > = std::collections::HashMap::new();

        for event in events {
            match &event.event_type {
                AvenadEventType::PeerDiscovered { peer_id, .. } => {
                    metrics.discovery_count += 1;
                    let key = (event.node.clone(), peer_id.clone());
                    discovery_times.entry(key).or_insert(event.timestamp);
                }
                AvenadEventType::PeerConnected { peer_id } => {
                    metrics.connection_count += 1;
                    let key = (event.node.clone(), peer_id.clone());
                    if let Some(disc_time) = discovery_times.get(&key) {
                        let handshake_duration = event.timestamp.signed_duration_since(*disc_time);
                        let ms = handshake_duration.num_milliseconds() as u64;
                        metrics.handshake_times_ms.push(ms);
                    }
                }
                AvenadEventType::HandshakeStarted { .. } => {
                    metrics.handshake_attempts += 1;
                }
                AvenadEventType::PeerDisconnected { .. } => {
                    metrics.disconnection_count += 1;
                }
                AvenadEventType::Unknown { .. } => {}
            }
        }

        if let Some(first) = events.first() {
            metrics.first_event_time = Some(first.timestamp);
        }
        if let Some(last) = events.last() {
            metrics.last_event_time = Some(last.timestamp);
        }

        metrics
    }
}

impl Default for LogParser {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Default)]
pub struct AvenadMetrics {
    pub discovery_count: u32,
    pub connection_count: u32,
    pub disconnection_count: u32,
    pub handshake_attempts: u32,
    pub handshake_times_ms: Vec<u64>,
    pub first_event_time: Option<chrono::DateTime<chrono::Utc>>,
    pub last_event_time: Option<chrono::DateTime<chrono::Utc>>,
}

impl AvenadMetrics {
    pub fn avg_handshake_ms(&self) -> Option<f64> {
        if self.handshake_times_ms.is_empty() {
            return None;
        }
        let sum: u64 = self.handshake_times_ms.iter().sum();
        Some(sum as f64 / self.handshake_times_ms.len() as f64)
    }
}

fn strip_ansi_codes(s: &str) -> String {
    let re = regex::Regex::new(r"\x1b\[[0-9;]*m").expect("valid regex");
    re.replace_all(s, "").to_string()
}

fn parse_timestamp(line: &str) -> Option<chrono::DateTime<chrono::Utc>> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.is_empty() {
        return None;
    }

    let ts_str = parts[0];
    chrono::DateTime::parse_from_rfc3339(ts_str)
        .ok()
        .map(|dt| dt.with_timezone(&chrono::Utc))
}

fn extract_field(line: &str, prefix: &str) -> Option<String> {
    let start = line.find(prefix)? + prefix.len();
    let rest = &line[start..];
    let end = rest
        .find(|c: char| c.is_whitespace() || c == ',' || c == ']' || c == ')')
        .unwrap_or(rest.len());
    let value = rest[..end].to_string();
    if value.is_empty() {
        None
    } else {
        Some(value)
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
        logger.log_convergence_metric(
            "underlay_up_to_first_peer_connected_ms",
            "gateway-sensor",
            "gateway",
            "sensor",
            100,
            250,
            150,
        );
        logger.log_ns3_event(serde_json::json!({"type":"realtime","lag_ms":5}));
        logger.flush();

        let content = std::fs::read_to_string(temp.path()).unwrap();
        let lines: Vec<&str> = content.lines().collect();

        assert_eq!(lines.len(), 5);
        assert!(lines[0].contains("scenario_started"));
        assert!(lines[1].contains("node_started"));
        assert!(lines[2].contains("link_changed"));
        assert!(lines[3].contains("convergence_metric"));
        assert!(lines[4].contains("ns3_event"));
    }

    #[test]
    fn test_log_parser_peer_discovered() {
        let mut parser = LogParser::new();
        let log_line = "2025-12-10T21:41:10.488939Z INFO avenad: Peer discovered peer_id=z57vi6qy3xekktr2fvzev3nzfm endpoint=10.1.0.2:51820";
        let events = parser.parse_log_content("nodeA", log_line);

        assert_eq!(events.len(), 1);
        match &events[0].event_type {
            AvenadEventType::PeerDiscovered { peer_id, endpoint } => {
                assert_eq!(peer_id, "z57vi6qy3xekktr2fvzev3nzfm");
                assert_eq!(endpoint, "10.1.0.2:51820");
            }
            _ => panic!("Expected PeerDiscovered event"),
        }
    }

    #[test]
    fn test_log_parser_peer_connected() {
        let mut parser = LogParser::new();
        let log_line = "2025-12-10T21:41:10.584018Z INFO avenad: Peer connected via incoming handshake peer_id=z57vi6qy3xekktr2fvzev3nzfm";
        let events = parser.parse_log_content("nodeA", log_line);

        assert_eq!(events.len(), 1);
        match &events[0].event_type {
            AvenadEventType::PeerConnected { peer_id } => {
                assert_eq!(peer_id, "z57vi6qy3xekktr2fvzev3nzfm");
            }
            _ => panic!("Expected PeerConnected event"),
        }
    }

    #[test]
    fn test_log_parser_with_ansi_codes() {
        let mut parser = LogParser::new();
        let log_line = "\x1b[2m2025-12-10T21:41:10.488939Z\x1b[0m \x1b[32m INFO\x1b[0m \x1b[2mavenad\x1b[0m\x1b[2m:\x1b[0m Peer discovered \x1b[3mpeer_id\x1b[0m\x1b[2m=\x1b[0mz57vi endpoint=10.1.0.2:51820";
        let events = parser.parse_log_content("nodeA", log_line);

        assert_eq!(events.len(), 1);
        match &events[0].event_type {
            AvenadEventType::PeerDiscovered { peer_id, .. } => {
                assert_eq!(peer_id, "z57vi");
            }
            _ => panic!("Expected PeerDiscovered event"),
        }
    }

    #[test]
    fn test_compute_handshake_metrics() {
        let parser = LogParser::new();
        let events = vec![
            ParsedAvenadEvent {
                timestamp: chrono::DateTime::parse_from_rfc3339("2025-12-10T21:41:10.000Z")
                    .unwrap()
                    .with_timezone(&chrono::Utc),
                node: "nodeA".to_string(),
                event_type: AvenadEventType::PeerDiscovered {
                    peer_id: "peer1".to_string(),
                    endpoint: "10.0.0.1:51820".to_string(),
                },
            },
            ParsedAvenadEvent {
                timestamp: chrono::DateTime::parse_from_rfc3339("2025-12-10T21:41:10.100Z")
                    .unwrap()
                    .with_timezone(&chrono::Utc),
                node: "nodeA".to_string(),
                event_type: AvenadEventType::PeerConnected {
                    peer_id: "peer1".to_string(),
                },
            },
        ];

        let metrics = parser.compute_metrics(&events);
        assert_eq!(metrics.discovery_count, 1);
        assert_eq!(metrics.connection_count, 1);
        assert_eq!(metrics.handshake_times_ms, vec![100]);
        assert_eq!(metrics.avg_handshake_ms(), Some(100.0));
    }
}
