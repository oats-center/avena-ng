use crate::scenario::{AssertCondition, Assertion, Scenario, TelemetryConfig};
use crate::telemetry::{subject_for_ns3_payload, TELEMETRY_SCHEMA_VERSION};
use async_nats::jetstream;
use async_nats::jetstream::stream::{
    Config as JetStreamConfig, DiscardPolicy, RetentionPolicy, StorageType,
};
use futures::StreamExt;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::task::JoinHandle;

const NATS_URL_ENV: &str = "AVENA_NATS_URL";
const DEFAULT_JETSTREAM_MAX_AGE_SECS: u64 = 7 * 24 * 60 * 60;
const STARTUP_METRIC_SUBJECT: &str = "metrics.startup";

#[derive(Error, Debug)]
pub enum TelemetryBusError {
    #[error("failed to connect to nats server '{url}': {source}")]
    Connect {
        url: String,
        source: async_nats::ConnectError,
    },

    #[error("failed to subscribe to nats subject '{subject}': {source}")]
    Subscribe {
        subject: String,
        source: async_nats::SubscribeError,
    },

    #[error("failed to serialize telemetry envelope: {0}")]
    Serialize(#[from] serde_json::Error),

    #[error("failed to publish telemetry event to subject '{subject}': {source}")]
    Publish {
        subject: String,
        source: async_nats::error::Error<async_nats::client::PublishErrorKind>,
    },

    #[error("failed to ensure JetStream stream '{stream}': {message}")]
    JetStream { stream: String, message: String },
}

#[derive(Debug)]
pub struct TelemetryBus {
    run_id: String,
    start: Instant,
    client: Option<async_nats::Client>,
    jetstream_stream: Option<String>,
    peer_connected_counts: Arc<Mutex<HashMap<String, usize>>>,
    _subscriber_task: Option<JoinHandle<()>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryEnvelope {
    pub v: u8,
    pub subject: String,
    pub ts_ms: u64,
    pub run_id: String,
    pub source: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub radio: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peer: Option<String>,
    pub data: Value,
}

impl TelemetryBus {
    #[must_use]
    pub fn disabled(run_id: impl Into<String>) -> Self {
        Self {
            run_id: run_id.into(),
            start: Instant::now(),
            client: None,
            jetstream_stream: None,
            peer_connected_counts: Arc::new(Mutex::new(HashMap::new())),
            _subscriber_task: None,
        }
    }

    pub async fn from_env(run_id: impl Into<String>) -> Result<Self, TelemetryBusError> {
        let run_id = run_id.into();
        match std::env::var(NATS_URL_ENV) {
            Ok(url) if !url.trim().is_empty() => {
                let client = async_nats::connect(&url).await.map_err(|source| {
                    TelemetryBusError::Connect {
                        url: url.clone(),
                        source,
                    }
                })?;
                let jetstream_stream = Some(ensure_jetstream_stream(&client, &run_id).await?);

                let run_subject = telemetry_run_subject_pattern(&run_id);
                let subscriber = client
                    .subscribe(run_subject.clone())
                    .await
                    .map_err(|source| TelemetryBusError::Subscribe {
                        subject: run_subject,
                        source,
                    })?;

                let peer_connected_counts = Arc::new(Mutex::new(HashMap::new()));
                let counts_for_task = Arc::clone(&peer_connected_counts);
                let run_id_for_task = run_id.clone();
                let client_for_task = client.clone();
                let subscriber_task = tokio::spawn(async move {
                    let mut subscriber = subscriber;
                    let mut startup_state = StartupMetricState::default();
                    while let Some(message) = subscriber.next().await {
                        if let Ok(envelope) =
                            serde_json::from_slice::<TelemetryEnvelope>(&message.payload)
                        {
                            record_peer_connected_subject(&counts_for_task, &envelope.subject);
                            let metrics = process_startup_metrics(
                                &mut startup_state,
                                &envelope,
                                &run_id_for_task,
                            );
                            for metric in metrics {
                                if let Err(err) =
                                    publish_envelope_with_client(&client_for_task, &metric).await
                                {
                                    tracing::warn!(error = %err, subject = %metric.subject, "failed to publish startup metric telemetry");
                                }
                            }
                        } else {
                            record_peer_connected_subject(
                                &counts_for_task,
                                message.subject.as_str(),
                            );
                        }
                    }
                });

                Ok(Self {
                    run_id,
                    start: Instant::now(),
                    client: Some(client),
                    jetstream_stream,
                    peer_connected_counts,
                    _subscriber_task: Some(subscriber_task),
                })
            }
            _ => Ok(Self::disabled(run_id)),
        }
    }

    pub async fn from_config(
        run_id: impl Into<String>,
        telemetry: &TelemetryConfig,
    ) -> Result<Self, TelemetryBusError> {
        let run_id = run_id.into();
        if !telemetry.publish_nats {
            return Ok(Self::disabled(run_id));
        }

        let nats_url = telemetry
            .nats_url
            .as_ref()
            .map(|url| url.trim().to_string())
            .filter(|url| !url.is_empty())
            .or_else(|| std::env::var(NATS_URL_ENV).ok());

        match nats_url {
            Some(url) => {
                let client = async_nats::connect(&url).await.map_err(|source| {
                    TelemetryBusError::Connect {
                        url: url.clone(),
                        source,
                    }
                })?;
                let jetstream_stream = Some(ensure_jetstream_stream(&client, &run_id).await?);

                let run_subject = telemetry_run_subject_pattern(&run_id);
                let subscriber = client
                    .subscribe(run_subject.clone())
                    .await
                    .map_err(|source| TelemetryBusError::Subscribe {
                        subject: run_subject,
                        source,
                    })?;

                let peer_connected_counts = Arc::new(Mutex::new(HashMap::new()));
                let counts_for_task = Arc::clone(&peer_connected_counts);
                let run_id_for_task = run_id.clone();
                let client_for_task = client.clone();
                let subscriber_task = tokio::spawn(async move {
                    let mut subscriber = subscriber;
                    let mut startup_state = StartupMetricState::default();
                    while let Some(message) = subscriber.next().await {
                        if let Ok(envelope) =
                            serde_json::from_slice::<TelemetryEnvelope>(&message.payload)
                        {
                            record_peer_connected_subject(&counts_for_task, &envelope.subject);
                            let metrics = process_startup_metrics(
                                &mut startup_state,
                                &envelope,
                                &run_id_for_task,
                            );
                            for metric in metrics {
                                if let Err(err) =
                                    publish_envelope_with_client(&client_for_task, &metric).await
                                {
                                    tracing::warn!(error = %err, subject = %metric.subject, "failed to publish startup metric telemetry");
                                }
                            }
                        } else {
                            record_peer_connected_subject(
                                &counts_for_task,
                                message.subject.as_str(),
                            );
                        }
                    }
                });

                Ok(Self {
                    run_id,
                    start: Instant::now(),
                    client: Some(client),
                    jetstream_stream,
                    peer_connected_counts,
                    _subscriber_task: Some(subscriber_task),
                })
            }
            None => Ok(Self::disabled(run_id)),
        }
    }

    #[must_use]
    pub fn peer_connected_count(&self, node_id: &str) -> usize {
        self.peer_connected_counts
            .lock()
            .ok()
            .and_then(|counts| counts.get(node_id).copied())
            .unwrap_or(0)
    }

    #[must_use]
    pub fn build_ns3_envelope(&self, payload: &Value) -> TelemetryEnvelope {
        let subject = subject_for_ns3_payload(&self.run_id, payload);
        TelemetryEnvelope {
            v: TELEMETRY_SCHEMA_VERSION,
            subject,
            ts_ms: self.start.elapsed().as_millis() as u64,
            run_id: self.run_id.clone(),
            source: "ns3".to_string(),
            node: payload
                .get("node")
                .and_then(Value::as_str)
                .map(str::to_string),
            radio: payload
                .get("radio")
                .and_then(Value::as_str)
                .map(str::to_string),
            peer: payload
                .get("peer")
                .or_else(|| payload.get("peer_id"))
                .and_then(Value::as_str)
                .map(str::to_string),
            data: payload.clone(),
        }
    }

    #[must_use]
    pub fn build_scenario_inventory_envelope(&self, scenario: &Scenario) -> TelemetryEnvelope {
        let subject = format!("avena.v1.{}.scenario", self.run_id);
        let node_inventory: Vec<Value> = scenario
            .nodes
            .iter()
            .map(|node| {
                serde_json::json!({
                    "id": node.id,
                    "radio_profile": node.radio_profile,
                    "radios": node.radios.iter().map(|radio| radio.id.clone()).collect::<Vec<_>>(),
                })
            })
            .collect();

        let links: Vec<Value> = scenario
            .links
            .iter()
            .map(|link| {
                serde_json::json!({
                    "id": link.resolved_link_id(),
                    "endpoints": [link.endpoints.0.clone(), link.endpoints.1.clone()],
                    "medium": link.medium,
                })
            })
            .collect();

        let bridges: Vec<Value> = scenario
            .bridges
            .iter()
            .map(|bridge| {
                serde_json::json!({
                    "id": bridge.id,
                    "members": bridge.nodes,
                    "medium": bridge.medium,
                })
            })
            .collect();

        TelemetryEnvelope {
            v: TELEMETRY_SCHEMA_VERSION,
            subject,
            ts_ms: self.start.elapsed().as_millis() as u64,
            run_id: self.run_id.clone(),
            source: "testbed".to_string(),
            node: None,
            radio: None,
            peer: None,
            data: serde_json::json!({
                "name": scenario.name,
                "duration_secs": scenario.duration_secs,
                "backend": format!("{:?}", scenario.emulation.backend).to_lowercase(),
                "nodes": node_inventory,
                "links": links,
                "bridges": bridges,
            }),
        }
    }

    #[must_use]
    pub fn build_assertion_result_envelope(
        &self,
        assertion: &Assertion,
        passed: bool,
    ) -> TelemetryEnvelope {
        let subject = format!("avena.v1.{}.testbed.assertion_result", self.run_id);
        let condition = assertion_type_name(&assertion.condition);
        TelemetryEnvelope {
            v: TELEMETRY_SCHEMA_VERSION,
            subject,
            ts_ms: self.start.elapsed().as_millis() as u64,
            run_id: self.run_id.clone(),
            source: "testbed".to_string(),
            node: None,
            radio: None,
            peer: None,
            data: serde_json::json!({
                "at_secs": assertion.at_secs,
                "condition": condition,
                "passed": passed,
            }),
        }
    }

    #[must_use]
    pub fn build_scenario_started_envelope(&self, scenario_name: &str) -> TelemetryEnvelope {
        let subject = format!("avena.v1.{}.testbed.scenario_started", self.run_id);
        TelemetryEnvelope {
            v: TELEMETRY_SCHEMA_VERSION,
            subject,
            ts_ms: self.start.elapsed().as_millis() as u64,
            run_id: self.run_id.clone(),
            source: "testbed".to_string(),
            node: None,
            radio: None,
            peer: None,
            data: serde_json::json!({
                "name": scenario_name,
            }),
        }
    }

    #[must_use]
    pub fn build_scenario_completed_envelope(
        &self,
        scenario_name: &str,
        passed: bool,
        duration_secs: f64,
    ) -> TelemetryEnvelope {
        let subject = format!("avena.v1.{}.testbed.scenario_completed", self.run_id);
        TelemetryEnvelope {
            v: TELEMETRY_SCHEMA_VERSION,
            subject,
            ts_ms: self.start.elapsed().as_millis() as u64,
            run_id: self.run_id.clone(),
            source: "testbed".to_string(),
            node: None,
            radio: None,
            peer: None,
            data: serde_json::json!({
                "name": scenario_name,
                "passed": passed,
                "duration_secs": duration_secs,
            }),
        }
    }

    pub async fn publish_ns3_payload(&self, payload: &Value) -> Result<(), TelemetryBusError> {
        let envelope = self.build_ns3_envelope(payload);
        self.publish_envelope(envelope).await
    }

    pub async fn publish_scenario_inventory(
        &self,
        scenario: &Scenario,
    ) -> Result<(), TelemetryBusError> {
        let envelope = self.build_scenario_inventory_envelope(scenario);
        self.publish_envelope(envelope).await
    }

    pub async fn publish_assertion_result(
        &self,
        assertion: &Assertion,
        passed: bool,
    ) -> Result<(), TelemetryBusError> {
        let envelope = self.build_assertion_result_envelope(assertion, passed);
        self.publish_envelope(envelope).await
    }

    pub async fn publish_scenario_started(
        &self,
        scenario_name: &str,
    ) -> Result<(), TelemetryBusError> {
        let envelope = self.build_scenario_started_envelope(scenario_name);
        self.publish_envelope(envelope).await
    }

    pub async fn publish_scenario_completed(
        &self,
        scenario_name: &str,
        passed: bool,
        duration_secs: f64,
    ) -> Result<(), TelemetryBusError> {
        let envelope = self.build_scenario_completed_envelope(scenario_name, passed, duration_secs);
        self.publish_envelope(envelope).await
    }

    async fn publish_envelope(&self, envelope: TelemetryEnvelope) -> Result<(), TelemetryBusError> {
        if let Some(client) = &self.client {
            let body = serde_json::to_vec(&envelope)?;
            client
                .publish(envelope.subject.clone(), body.into())
                .await
                .map_err(|source| TelemetryBusError::Publish {
                    subject: envelope.subject.clone(),
                    source,
                })?;
        }
        self.record_inbound_envelope(&envelope);
        Ok(())
    }

    #[must_use]
    pub fn jetstream_stream(&self) -> Option<&str> {
        self.jetstream_stream.as_deref()
    }

    pub(crate) fn record_inbound_envelope(&self, envelope: &TelemetryEnvelope) {
        record_peer_connected_subject(&self.peer_connected_counts, &envelope.subject);
    }
}

fn assertion_type_name(condition: &AssertCondition) -> &'static str {
    match condition {
        AssertCondition::NodesConnected { .. } => "NodesConnected",
        AssertCondition::Ping { .. } => "Ping",
        AssertCondition::PeerCount { .. } => "PeerCount",
        AssertCondition::TunnelInterfaceCount { .. } => "TunnelInterfaceCount",
    }
}

fn node_id_from_overlay_subject(subject: &str) -> Option<&str> {
    let parts: Vec<&str> = subject.split('.').collect();
    if parts.len() < 7 {
        return None;
    }

    if parts[0] != "avena"
        || parts[1] != "v1"
        || parts[3] != "node"
        || parts[5] != "overlay"
        || parts[6] != "peer_connected"
    {
        return None;
    }

    Some(parts[4])
}

fn record_peer_connected_subject(counts: &Arc<Mutex<HashMap<String, usize>>>, subject: &str) {
    if let Some(node_id) = node_id_from_overlay_subject(subject) {
        if let Ok(mut counts) = counts.lock() {
            *counts.entry(node_id.to_string()).or_insert(0) += 1;
        }
    }
}

#[derive(Debug, Default)]
struct StartupMetricState {
    l2_ready_ms: HashMap<String, u64>,
    emitted_discovered: HashSet<String>,
    emitted_connected: HashSet<String>,
}

fn process_startup_metrics(
    state: &mut StartupMetricState,
    envelope: &TelemetryEnvelope,
    run_id: &str,
) -> Vec<TelemetryEnvelope> {
    if let Some(node_id) = l2_ready_node_from_envelope(envelope) {
        state.l2_ready_ms.entry(node_id).or_insert(envelope.ts_ms);
        return Vec::new();
    }

    let Some((node_id, overlay_event)) = overlay_node_and_event(&envelope.subject) else {
        return Vec::new();
    };

    let Some(l2_ready_ms) = state.l2_ready_ms.get(node_id).copied() else {
        return Vec::new();
    };

    let metric_name = match overlay_event {
        "peer_discovered" => {
            if !state.emitted_discovered.insert(node_id.to_string()) {
                return Vec::new();
            }
            "l2_ready_to_peer_discovered_ms"
        }
        "peer_connected" => {
            if !state.emitted_connected.insert(node_id.to_string()) {
                return Vec::new();
            }
            "l2_ready_to_peer_connected_ms"
        }
        _ => return Vec::new(),
    };

    vec![build_startup_metric_envelope(
        run_id,
        node_id,
        metric_name,
        l2_ready_ms,
        envelope.ts_ms,
    )]
}

fn l2_ready_node_from_envelope(envelope: &TelemetryEnvelope) -> Option<String> {
    if !envelope.subject.contains(".ns3.") {
        return None;
    }

    let node = envelope.data.get("node").and_then(Value::as_str)?;
    let event_type = envelope.data.get("type").and_then(Value::as_str);
    let event_name = envelope.data.get("event").and_then(Value::as_str);

    let is_l2_ready = matches!(
        (event_type, event_name),
        (
            Some("l2"),
            Some("assoc_complete" | "peering_complete" | "l2_ready")
        )
    ) || matches!(
        event_name,
        Some("assoc_complete" | "peering_complete" | "l2_ready")
    );

    if is_l2_ready {
        Some(node.to_string())
    } else {
        None
    }
}

fn overlay_node_and_event(subject: &str) -> Option<(&str, &str)> {
    let parts: Vec<&str> = subject.split('.').collect();
    if parts.len() < 7 {
        return None;
    }

    if parts[0] != "avena" || parts[1] != "v1" || parts[3] != "node" || parts[5] != "overlay" {
        return None;
    }

    Some((parts[4], parts[6]))
}

fn build_startup_metric_envelope(
    run_id: &str,
    node_id: &str,
    metric: &str,
    l2_ready_ms: u64,
    observed_ms: u64,
) -> TelemetryEnvelope {
    TelemetryEnvelope {
        v: TELEMETRY_SCHEMA_VERSION,
        subject: format!("avena.v1.{run_id}.{STARTUP_METRIC_SUBJECT}"),
        ts_ms: observed_ms,
        run_id: run_id.to_string(),
        source: "testbed".to_string(),
        node: Some(node_id.to_string()),
        radio: None,
        peer: None,
        data: serde_json::json!({
            "node": node_id,
            "metric": metric,
            "l2_ready_ms": l2_ready_ms,
            "observed_ms": observed_ms,
            "value_ms": observed_ms.saturating_sub(l2_ready_ms),
        }),
    }
}

async fn publish_envelope_with_client(
    client: &async_nats::Client,
    envelope: &TelemetryEnvelope,
) -> Result<(), TelemetryBusError> {
    let body = serde_json::to_vec(envelope)?;
    client
        .publish(envelope.subject.clone(), body.into())
        .await
        .map_err(|source| TelemetryBusError::Publish {
            subject: envelope.subject.clone(),
            source,
        })?;
    Ok(())
}

fn telemetry_run_subject_pattern(run_id: &str) -> String {
    format!("avena.v1.{run_id}.>")
}

fn jetstream_stream_name(run_id: &str) -> String {
    let mut token: String = run_id
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '_' || ch == '-' {
                ch.to_ascii_uppercase()
            } else {
                '_'
            }
        })
        .collect();

    while token.contains("__") {
        token = token.replace("__", "_");
    }

    token = token.trim_matches('_').to_string();
    if token.is_empty() {
        token = "RUN".to_string();
    }

    let mut name = format!("AVENA_{token}");
    if name.len() > 128 {
        name.truncate(128);
    }
    name
}

async fn ensure_jetstream_stream(
    client: &async_nats::Client,
    run_id: &str,
) -> Result<String, TelemetryBusError> {
    let stream = jetstream_stream_name(run_id);
    let subject = telemetry_run_subject_pattern(run_id);
    let ctx = jetstream::new(client.clone());

    if ctx.get_stream(stream.clone()).await.is_ok() {
        return Ok(stream);
    }

    let config = JetStreamConfig {
        name: stream.clone(),
        subjects: vec![subject],
        retention: RetentionPolicy::Limits,
        discard: DiscardPolicy::Old,
        max_age: Duration::from_secs(DEFAULT_JETSTREAM_MAX_AGE_SECS),
        storage: StorageType::File,
        ..Default::default()
    };

    ctx.create_stream(config)
        .await
        .map_err(|err| TelemetryBusError::JetStream {
            stream: stream.clone(),
            message: err.to_string(),
        })?;

    Ok(stream)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scenario::Scenario;

    #[test]
    fn build_ns3_envelope_sets_expected_fields() {
        let bus = TelemetryBus::disabled("run123");
        let payload = serde_json::json!({"type":"realtime","lag_ms":4});

        let envelope = bus.build_ns3_envelope(&payload);
        assert_eq!(envelope.v, TELEMETRY_SCHEMA_VERSION);
        assert_eq!(envelope.run_id, "run123");
        assert_eq!(envelope.source, "ns3");
        assert_eq!(envelope.subject, "avena.v1.run123.ns3.realtime");
        assert_eq!(envelope.data, payload);
    }

    #[tokio::test]
    async fn publish_is_noop_when_bus_is_disabled() {
        let bus = TelemetryBus::disabled("run123");
        let payload = serde_json::json!({"type":"realtime"});

        bus.publish_ns3_payload(&payload)
            .await
            .expect("disabled bus should not fail");
    }

    #[test]
    fn envelope_subject_uses_payload_subject_when_valid() {
        let bus = TelemetryBus::disabled("run123");
        let payload = serde_json::json!({"subject":"avena.v1.custom.ns3.l2","foo":"bar"});

        let envelope = bus.build_ns3_envelope(&payload);
        assert_eq!(envelope.subject, "avena.v1.custom.ns3.l2");
    }

    #[tokio::test]
    async fn from_config_prefers_scenario_url_over_env() {
        unsafe {
            std::env::set_var("AVENA_NATS_URL", "nats://127.0.0.1:9999");
        }

        let config = crate::scenario::TelemetryConfig {
            publish_nats: false,
            nats_url: Some("nats://127.0.0.1:4222".to_string()),
        };

        let bus = TelemetryBus::from_config("run123", &config)
            .await
            .expect("from_config should not fail when disabled");

        let payload = serde_json::json!({"type":"realtime"});
        bus.publish_ns3_payload(&payload)
            .await
            .expect("disabled bus should remain no-op");

        unsafe {
            std::env::remove_var("AVENA_NATS_URL");
        }
    }

    #[test]
    fn build_scenario_inventory_envelope_has_expected_subject() {
        let scenario = Scenario::from_toml(
            r#"
name = "inventory"
duration_secs = 10

[[nodes]]
id = "nodeA"

[[nodes]]
id = "nodeB"

[[links]]
endpoints = ["nodeA", "nodeB"]
latency_ms = 10
bandwidth_kbps = 1000
"#,
        )
        .expect("valid scenario");

        let bus = TelemetryBus::disabled("run123");
        let envelope = bus.build_scenario_inventory_envelope(&scenario);
        assert_eq!(envelope.subject, "avena.v1.run123.scenario");
        assert_eq!(envelope.source, "testbed");
        assert_eq!(envelope.data["name"], "inventory");
    }

    #[test]
    fn build_assertion_result_envelope_has_expected_subject() {
        let scenario = Scenario::from_toml(
            r#"
name = "assertions"
duration_secs = 10

[[nodes]]
id = "nodeA"

[[nodes]]
id = "nodeB"

[[links]]
endpoints = ["nodeA", "nodeB"]
latency_ms = 10
bandwidth_kbps = 1000

[[assertions]]
at_secs = 4.0
condition = { type = "Ping", from = "nodeA", to = "nodeB", timeout_ms = 2000 }
"#,
        )
        .expect("valid scenario");

        let assertion = &scenario.assertions[0];
        let bus = TelemetryBus::disabled("run123");
        let envelope = bus.build_assertion_result_envelope(assertion, true);
        assert_eq!(envelope.subject, "avena.v1.run123.testbed.assertion_result");
        assert_eq!(envelope.data["passed"], true);
        assert_eq!(envelope.data["condition"], "Ping");
    }

    #[test]
    fn overlay_subject_parser_extracts_node_id_for_peer_connected() {
        let node =
            node_id_from_overlay_subject("avena.v1.run123.node.alpha.overlay.peer_connected");
        assert_eq!(node, Some("alpha"));

        assert_eq!(
            node_id_from_overlay_subject("avena.v1.run123.node.alpha.overlay.peer_discovered"),
            None
        );
        assert_eq!(node_id_from_overlay_subject("invalid"), None);
    }

    #[test]
    fn record_inbound_envelope_updates_peer_connected_counts() {
        let bus = TelemetryBus::disabled("run123");

        let connected = TelemetryEnvelope {
            v: TELEMETRY_SCHEMA_VERSION,
            subject: "avena.v1.run123.node.nodeA.overlay.peer_connected".to_string(),
            ts_ms: 42,
            run_id: "run123".to_string(),
            source: "avenad".to_string(),
            node: Some("nodeA".to_string()),
            radio: None,
            peer: Some("nodeB".to_string()),
            data: serde_json::json!({"peer":"nodeB"}),
        };
        bus.record_inbound_envelope(&connected);
        bus.record_inbound_envelope(&connected);

        let discovered = TelemetryEnvelope {
            v: TELEMETRY_SCHEMA_VERSION,
            subject: "avena.v1.run123.node.nodeA.overlay.peer_discovered".to_string(),
            ts_ms: 43,
            run_id: "run123".to_string(),
            source: "avenad".to_string(),
            node: Some("nodeA".to_string()),
            radio: None,
            peer: Some("nodeB".to_string()),
            data: serde_json::json!({"peer":"nodeB"}),
        };
        bus.record_inbound_envelope(&discovered);

        assert_eq!(bus.peer_connected_count("nodeA"), 2);
        assert_eq!(bus.peer_connected_count("nodeB"), 0);
    }

    #[test]
    fn build_scenario_started_envelope_has_expected_subject() {
        let bus = TelemetryBus::disabled("run123");
        let envelope = bus.build_scenario_started_envelope("demo");
        assert_eq!(envelope.subject, "avena.v1.run123.testbed.scenario_started");
        assert_eq!(envelope.source, "testbed");
        assert_eq!(envelope.data["name"], "demo");
    }

    #[test]
    fn build_scenario_completed_envelope_has_expected_subject() {
        let bus = TelemetryBus::disabled("run123");
        let envelope = bus.build_scenario_completed_envelope("demo", true, 12.5);
        assert_eq!(
            envelope.subject,
            "avena.v1.run123.testbed.scenario_completed"
        );
        assert_eq!(envelope.data["name"], "demo");
        assert_eq!(envelope.data["passed"], true);
    }

    #[test]
    fn process_startup_metrics_emits_discovered_and_connected_once() {
        let mut state = StartupMetricState::default();
        let l2 = TelemetryEnvelope {
            v: TELEMETRY_SCHEMA_VERSION,
            subject: "avena.v1.run123.ns3.l2".to_string(),
            ts_ms: 100,
            run_id: "run123".to_string(),
            source: "ns3".to_string(),
            node: Some("nodeA".to_string()),
            radio: Some("wifi0".to_string()),
            peer: None,
            data: serde_json::json!({"type":"l2","event":"assoc_complete","node":"nodeA"}),
        };
        assert!(process_startup_metrics(&mut state, &l2, "run123").is_empty());

        let discovered = TelemetryEnvelope {
            v: TELEMETRY_SCHEMA_VERSION,
            subject: "avena.v1.run123.node.nodeA.overlay.peer_discovered".to_string(),
            ts_ms: 150,
            run_id: "run123".to_string(),
            source: "avenad".to_string(),
            node: Some("nodeA".to_string()),
            radio: None,
            peer: Some("nodeB".to_string()),
            data: serde_json::json!({"peer_id":"nodeB"}),
        };
        let metrics = process_startup_metrics(&mut state, &discovered, "run123");
        assert_eq!(metrics.len(), 1);
        assert_eq!(metrics[0].data["metric"], "l2_ready_to_peer_discovered_ms");
        assert_eq!(metrics[0].data["value_ms"], 50);

        let connected = TelemetryEnvelope {
            v: TELEMETRY_SCHEMA_VERSION,
            subject: "avena.v1.run123.node.nodeA.overlay.peer_connected".to_string(),
            ts_ms: 180,
            run_id: "run123".to_string(),
            source: "avenad".to_string(),
            node: Some("nodeA".to_string()),
            radio: None,
            peer: Some("nodeB".to_string()),
            data: serde_json::json!({"peer_id":"nodeB"}),
        };
        let metrics = process_startup_metrics(&mut state, &connected, "run123");
        assert_eq!(metrics.len(), 1);
        assert_eq!(metrics[0].data["metric"], "l2_ready_to_peer_connected_ms");
        assert_eq!(metrics[0].data["value_ms"], 80);

        assert!(process_startup_metrics(&mut state, &connected, "run123").is_empty());
    }

    #[test]
    fn overlay_node_and_event_parses_expected_subject_shape() {
        let parsed = overlay_node_and_event("avena.v1.run123.node.alpha.overlay.peer_connected");
        assert_eq!(parsed, Some(("alpha", "peer_connected")));
        assert_eq!(overlay_node_and_event("avena.v1.run123.ns3.l2"), None);
    }

    #[test]
    fn telemetry_run_subject_pattern_uses_run_scope() {
        assert_eq!(telemetry_run_subject_pattern("run123"), "avena.v1.run123.>");
    }

    #[test]
    fn jetstream_stream_name_is_ascii_upper_and_stable() {
        assert_eq!(jetstream_stream_name("run-abc_123"), "AVENA_RUN-ABC_123");
        assert_eq!(
            jetstream_stream_name("run id.with spaces"),
            "AVENA_RUN_ID_WITH_SPACES"
        );
    }
}
