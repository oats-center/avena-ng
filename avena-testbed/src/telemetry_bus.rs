use crate::telemetry::{subject_for_ns3_payload, TELEMETRY_SCHEMA_VERSION};
use crate::scenario::{AssertCondition, Assertion, Scenario, TelemetryConfig};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::time::Instant;
use thiserror::Error;

const NATS_URL_ENV: &str = "AVENA_NATS_URL";

#[derive(Error, Debug)]
pub enum TelemetryBusError {
    #[error("failed to connect to nats server '{url}': {source}")]
    Connect {
        url: String,
        source: async_nats::ConnectError,
    },

    #[error("failed to serialize telemetry envelope: {0}")]
    Serialize(#[from] serde_json::Error),

    #[error("failed to publish telemetry event to subject '{subject}': {source}")]
    Publish {
        subject: String,
        source: async_nats::error::Error<async_nats::client::PublishErrorKind>,
    },
}

#[derive(Debug)]
pub struct TelemetryBus {
    run_id: String,
    start: Instant,
    client: Option<async_nats::Client>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryEnvelope {
    pub v: u8,
    pub subject: String,
    pub ts_ms: u64,
    pub run_id: String,
    pub source: String,
    pub data: Value,
}

impl TelemetryBus {
    #[must_use]
    pub fn disabled(run_id: impl Into<String>) -> Self {
        Self {
            run_id: run_id.into(),
            start: Instant::now(),
            client: None,
        }
    }

    pub async fn from_env(run_id: impl Into<String>) -> Result<Self, TelemetryBusError> {
        let run_id = run_id.into();
        match std::env::var(NATS_URL_ENV) {
            Ok(url) if !url.trim().is_empty() => {
                let client = async_nats::connect(&url)
                    .await
                    .map_err(|source| TelemetryBusError::Connect {
                        url: url.clone(),
                        source,
                    })?;
                Ok(Self {
                    run_id,
                    start: Instant::now(),
                    client: Some(client),
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
                let client = async_nats::connect(&url)
                    .await
                    .map_err(|source| TelemetryBusError::Connect {
                        url: url.clone(),
                        source,
                    })?;

                Ok(Self {
                    run_id,
                    start: Instant::now(),
                    client: Some(client),
                })
            }
            None => Ok(Self::disabled(run_id)),
        }
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
            data: serde_json::json!({
                "at_secs": assertion.at_secs,
                "condition": condition,
                "passed": passed,
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
        Ok(())
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
        assert_eq!(
            envelope.subject,
            "avena.v1.run123.testbed.assertion_result"
        );
        assert_eq!(envelope.data["passed"], true);
        assert_eq!(envelope.data["condition"], "Ping");
    }
}
