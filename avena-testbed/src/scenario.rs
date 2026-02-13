use serde::Deserialize;
use std::path::Path;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ScenarioError {
    #[error("failed to read scenario file: {0}")]
    Io(#[from] std::io::Error),
    #[error("failed to parse scenario TOML: {0}")]
    Parse(#[from] toml::de::Error),
    #[error("invalid scenario: {0}")]
    Validation(String),
}

#[derive(Debug, Clone, Deserialize)]
pub struct Scenario {
    pub name: String,
    pub description: Option<String>,
    pub duration_secs: u64,
    pub nodes: Vec<NodeConfig>,
    #[serde(default)]
    pub links: Vec<LinkConfig>,
    #[serde(default)]
    pub bridges: Vec<BridgeConfig>,
    #[serde(default)]
    pub events: Vec<Event>,
    #[serde(default)]
    pub assertions: Vec<Assertion>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct BridgeConfig {
    pub id: String,
    pub nodes: Vec<String>,
    #[serde(default)]
    pub latency_ms: u32,
    #[serde(default = "default_bridge_bandwidth")]
    pub bandwidth_kbps: u32,
    #[serde(default)]
    pub loss_percent: f32,
}

fn default_bridge_bandwidth() -> u32 {
    1_000_000
}

#[derive(Debug, Clone, Deserialize)]
pub struct NodeConfig {
    pub id: String,
    #[serde(default)]
    pub capabilities: Vec<String>,
    pub start_delay_secs: Option<f64>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct LinkConfig {
    #[serde(default)]
    pub id: Option<String>,
    pub endpoints: (String, String),
    pub latency_ms: u32,
    pub bandwidth_kbps: u32,
    #[serde(default)]
    pub loss_percent: f32,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
}

fn default_enabled() -> bool {
    true
}

impl LinkConfig {
    pub fn resolved_link_id(&self) -> String {
        self.id
            .clone()
            .unwrap_or_else(|| format!("{}-{}", self.endpoints.0, self.endpoints.1))
    }
}

fn normalized_link_pair(a: &str, b: &str) -> (String, String) {
    if a <= b {
        (a.to_string(), b.to_string())
    } else {
        (b.to_string(), a.to_string())
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct Event {
    pub at_secs: f64,
    pub action: EventAction,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type")]
pub enum EventAction {
    DisconnectLink {
        link: String,
    },
    ConnectLink {
        link: String,
    },
    ModifyLink {
        link: String,
        latency_ms: Option<u32>,
        loss_percent: Option<f32>,
    },
    StopNode {
        node: String,
    },
    StartNode {
        node: String,
    },
}

#[derive(Debug, Clone, Deserialize)]
pub struct Assertion {
    pub at_secs: f64,
    pub condition: AssertCondition,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type")]
pub enum AssertCondition {
    NodesConnected {
        nodes: Vec<String>,
    },
    Ping {
        from: String,
        to: String,
        timeout_ms: u32,
    },
    PeerCount {
        node: String,
        count: usize,
    },
    TunnelInterfaceCount {
        node: String,
        count: usize,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RequiredEvent {
    pub node: String,
    pub event_type: RequiredEventType,
    pub count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum RequiredEventType {
    PeerConnected,
}

impl AssertCondition {
    pub fn required_events(&self) -> Vec<RequiredEvent> {
        match self {
            AssertCondition::PeerCount { node, count } => {
                vec![RequiredEvent {
                    node: node.clone(),
                    event_type: RequiredEventType::PeerConnected,
                    count: *count,
                }]
            }
            AssertCondition::TunnelInterfaceCount { node, .. } => {
                vec![RequiredEvent {
                    node: node.clone(),
                    event_type: RequiredEventType::PeerConnected,
                    count: 1,
                }]
            }
            AssertCondition::Ping { from, to, .. } => {
                vec![
                    RequiredEvent {
                        node: from.clone(),
                        event_type: RequiredEventType::PeerConnected,
                        count: 1,
                    },
                    RequiredEvent {
                        node: to.clone(),
                        event_type: RequiredEventType::PeerConnected,
                        count: 1,
                    },
                ]
            }
            AssertCondition::NodesConnected { nodes } => nodes
                .iter()
                .map(|node| RequiredEvent {
                    node: node.clone(),
                    event_type: RequiredEventType::PeerConnected,
                    count: 1,
                })
                .collect(),
        }
    }
}

impl Scenario {
    pub fn load(path: &Path) -> Result<Self, ScenarioError> {
        let content = std::fs::read_to_string(path)?;
        Self::from_toml(&content)
    }

    pub fn from_toml(content: &str) -> Result<Self, ScenarioError> {
        let scenario: Scenario = toml::from_str(content)?;
        scenario.validate()?;
        Ok(scenario)
    }

    fn validate(&self) -> Result<(), ScenarioError> {
        if self.nodes.is_empty() {
            return Err(ScenarioError::Validation(
                "at least one node required".into(),
            ));
        }

        let node_ids: std::collections::HashSet<_> = self.nodes.iter().map(|n| &n.id).collect();

        if node_ids.len() != self.nodes.len() {
            return Err(ScenarioError::Validation("duplicate node IDs".into()));
        }

        for link in &self.links {
            if !node_ids.contains(&link.endpoints.0) {
                return Err(ScenarioError::Validation(format!(
                    "link references unknown node: {}",
                    link.endpoints.0
                )));
            }
            if !node_ids.contains(&link.endpoints.1) {
                return Err(ScenarioError::Validation(format!(
                    "link references unknown node: {}",
                    link.endpoints.1
                )));
            }
        }

        self.validate_link_identity_rules()?;

        for bridge in &self.bridges {
            for node in &bridge.nodes {
                if !node_ids.contains(node) {
                    return Err(ScenarioError::Validation(format!(
                        "bridge '{}' references unknown node: {}",
                        bridge.id, node
                    )));
                }
            }
        }

        for event in &self.events {
            if event.at_secs < 0.0 || event.at_secs > self.duration_secs as f64 {
                return Err(ScenarioError::Validation(format!(
                    "event at_secs {} outside scenario duration",
                    event.at_secs
                )));
            }
            self.validate_event_action(&event.action, &node_ids)?;
        }

        for assertion in &self.assertions {
            if assertion.at_secs < 0.0 || assertion.at_secs > self.duration_secs as f64 {
                return Err(ScenarioError::Validation(format!(
                    "assertion at_secs {} outside scenario duration",
                    assertion.at_secs
                )));
            }
            self.validate_assertion(&assertion.condition, &node_ids)?;
        }

        Ok(())
    }

    fn validate_event_action(
        &self,
        action: &EventAction,
        node_ids: &std::collections::HashSet<&String>,
    ) -> Result<(), ScenarioError> {
        match action {
            EventAction::DisconnectLink { link } | EventAction::ConnectLink { link } => {
                self.validate_link_ref(link)?;
            }
            EventAction::ModifyLink { link, .. } => {
                self.validate_link_ref(link)?;
            }
            EventAction::StopNode { node } | EventAction::StartNode { node } => {
                if !node_ids.contains(node) {
                    return Err(ScenarioError::Validation(format!(
                        "event references unknown node: {node}"
                    )));
                }
            }
        }
        Ok(())
    }

    fn validate_link_ref(&self, link_ref: &str) -> Result<(), ScenarioError> {
        if self
            .links
            .iter()
            .any(|link| link.resolved_link_id() == link_ref)
        {
            return Ok(());
        }

        let Some((node_a, node_b)) = link_ref.split_once('-') else {
            return Err(ScenarioError::Validation(format!(
                "event references unknown link: {link_ref}"
            )));
        };

        let matching_links = self
            .links
            .iter()
            .filter(|link| {
                let (a, b) = (&link.endpoints.0, &link.endpoints.1);
                (a == node_a && b == node_b) || (a == node_b && b == node_a)
            })
            .count();

        match matching_links {
            1 => Ok(()),
            n if n > 1 => Err(ScenarioError::Validation(format!(
                "event link reference '{link_ref}' is ambiguous; use an explicit link id"
            ))),
            _ => Err(ScenarioError::Validation(format!(
                "event references unknown link: {link_ref}"
            ))),
        }
    }

    fn validate_link_identity_rules(&self) -> Result<(), ScenarioError> {
        let mut resolved_ids = std::collections::HashSet::new();
        let mut pair_stats: std::collections::HashMap<(String, String), (usize, usize)> =
            std::collections::HashMap::new();

        for link in &self.links {
            if let Some(id) = &link.id {
                if id.trim().is_empty() {
                    return Err(ScenarioError::Validation(
                        "link id must not be empty".to_string(),
                    ));
                }
            }

            let resolved_id = link.resolved_link_id();
            if !resolved_ids.insert(resolved_id.clone()) {
                return Err(ScenarioError::Validation(format!(
                    "duplicate link id: {resolved_id}"
                )));
            }

            let pair = normalized_link_pair(&link.endpoints.0, &link.endpoints.1);
            let entry = pair_stats.entry(pair).or_insert((0, 0));
            entry.0 += 1;
            if link.id.is_some() {
                entry.1 += 1;
            }
        }

        for ((node_a, node_b), (total, explicit_count)) in pair_stats {
            if total > 1 && explicit_count < total {
                return Err(ScenarioError::Validation(format!(
                    "parallel links between '{node_a}' and '{node_b}' require explicit unique link ids"
                )));
            }
        }

        Ok(())
    }

    fn validate_assertion(
        &self,
        condition: &AssertCondition,
        node_ids: &std::collections::HashSet<&String>,
    ) -> Result<(), ScenarioError> {
        match condition {
            AssertCondition::NodesConnected { nodes } => {
                for node in nodes {
                    if !node_ids.contains(node) {
                        return Err(ScenarioError::Validation(format!(
                            "assertion references unknown node: {node}"
                        )));
                    }
                }
            }
            AssertCondition::Ping { from, to, .. } => {
                if !node_ids.contains(from) {
                    return Err(ScenarioError::Validation(format!(
                        "assertion references unknown node: {from}"
                    )));
                }
                if !node_ids.contains(to) {
                    return Err(ScenarioError::Validation(format!(
                        "assertion references unknown node: {to}"
                    )));
                }
            }
            AssertCondition::PeerCount { node, .. } => {
                if !node_ids.contains(node) {
                    return Err(ScenarioError::Validation(format!(
                        "assertion references unknown node: {node}"
                    )));
                }
            }
            AssertCondition::TunnelInterfaceCount { node, .. } => {
                if !node_ids.contains(node) {
                    return Err(ScenarioError::Validation(format!(
                        "assertion references unknown node: {node}"
                    )));
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_minimal_scenario() {
        let toml = r#"
name = "minimal"
duration_secs = 10

[[nodes]]
id = "nodeA"

[[nodes]]
id = "nodeB"

[[links]]
endpoints = ["nodeA", "nodeB"]
latency_ms = 10
bandwidth_kbps = 1000
"#;
        let scenario = Scenario::from_toml(toml).unwrap();
        assert_eq!(scenario.name, "minimal");
        assert_eq!(scenario.nodes.len(), 2);
        assert_eq!(scenario.links.len(), 1);
    }

    #[test]
    fn test_parse_full_scenario() {
        let toml = r#"
name = "full-test"
description = "A comprehensive test scenario"
duration_secs = 60

[[nodes]]
id = "gateway"
capabilities = ["relay", "gateway"]

[[nodes]]
id = "sensor"
capabilities = []
start_delay_secs = 5.0

[[links]]
endpoints = ["gateway", "sensor"]
latency_ms = 10
bandwidth_kbps = 1000
loss_percent = 0.1
enabled = true

[[events]]
at_secs = 10.0
action = { type = "DisconnectLink", link = "gateway-sensor" }

[[events]]
at_secs = 20.0
action = { type = "ConnectLink", link = "gateway-sensor" }

[[assertions]]
at_secs = 25.0
condition = { type = "Ping", from = "gateway", to = "sensor", timeout_ms = 1000 }
"#;
        let scenario = Scenario::from_toml(toml).unwrap();
        assert_eq!(scenario.name, "full-test");
        assert_eq!(scenario.events.len(), 2);
        assert_eq!(scenario.assertions.len(), 1);
    }

    #[test]
    fn test_validation_duplicate_node_ids() {
        let toml = r#"
name = "bad"
duration_secs = 10

[[nodes]]
id = "same"

[[nodes]]
id = "same"

[[links]]
endpoints = ["same", "same"]
latency_ms = 10
bandwidth_kbps = 1000
"#;
        let result = Scenario::from_toml(toml);
        assert!(result.is_err());
    }

    #[test]
    fn test_validation_unknown_node_in_link() {
        let toml = r#"
name = "bad"
duration_secs = 10

[[nodes]]
id = "nodeA"

[[links]]
endpoints = ["nodeA", "unknown"]
latency_ms = 10
bandwidth_kbps = 1000
"#;
        let result = Scenario::from_toml(toml);
        assert!(result.is_err());
    }

    #[test]
    fn test_validation_event_outside_duration() {
        let toml = r#"
name = "bad"
duration_secs = 10

[[nodes]]
id = "nodeA"

[[nodes]]
id = "nodeB"

[[links]]
endpoints = ["nodeA", "nodeB"]
latency_ms = 10
bandwidth_kbps = 1000

[[events]]
at_secs = 100.0
action = { type = "DisconnectLink", link = "nodeA-nodeB" }
"#;
        let result = Scenario::from_toml(toml);
        assert!(result.is_err());
    }

    #[test]
    fn duplicate_parallel_links_without_explicit_ids_fail() {
        let toml = r#"
name = "parallel-bad"
duration_secs = 10

[[nodes]]
id = "nodeA"

[[nodes]]
id = "nodeB"

[[links]]
endpoints = ["nodeA", "nodeB"]
latency_ms = 10
bandwidth_kbps = 1000

[[links]]
endpoints = ["nodeB", "nodeA"]
latency_ms = 20
bandwidth_kbps = 1000
"#;

        let err = Scenario::from_toml(toml).unwrap_err();
        assert!(
            err.to_string().contains("require explicit unique link ids"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn duplicate_parallel_links_with_explicit_ids_pass() {
        let toml = r#"
name = "parallel-good"
duration_secs = 10

[[nodes]]
id = "nodeA"

[[nodes]]
id = "nodeB"

[[links]]
id = "ab-wifi"
endpoints = ["nodeA", "nodeB"]
latency_ms = 10
bandwidth_kbps = 1000

[[links]]
id = "ab-cell"
endpoints = ["nodeA", "nodeB"]
latency_ms = 20
bandwidth_kbps = 1000

[[events]]
at_secs = 5.0
action = { type = "DisconnectLink", link = "ab-wifi" }
"#;

        assert!(Scenario::from_toml(toml).is_ok());
    }

    #[test]
    fn endpoint_ref_is_rejected_when_parallel_links_exist() {
        let toml = r#"
name = "parallel-ambiguous"
duration_secs = 10

[[nodes]]
id = "nodeA"

[[nodes]]
id = "nodeB"

[[links]]
id = "ab-wifi"
endpoints = ["nodeA", "nodeB"]
latency_ms = 10
bandwidth_kbps = 1000

[[links]]
id = "ab-cell"
endpoints = ["nodeA", "nodeB"]
latency_ms = 20
bandwidth_kbps = 1000

[[events]]
at_secs = 5.0
action = { type = "DisconnectLink", link = "nodeA-nodeB" }
"#;

        let err = Scenario::from_toml(toml).unwrap_err();
        assert!(
            err.to_string().contains("ambiguous"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn duplicate_resolved_link_ids_fail() {
        let toml = r#"
name = "dup-id"
duration_secs = 10

[[nodes]]
id = "nodeA"

[[nodes]]
id = "nodeB"

[[links]]
id = "dup"
endpoints = ["nodeA", "nodeB"]
latency_ms = 10
bandwidth_kbps = 1000

[[links]]
id = "dup"
endpoints = ["nodeA", "nodeB"]
latency_ms = 20
bandwidth_kbps = 1000
"#;

        let err = Scenario::from_toml(toml).unwrap_err();
        assert!(
            err.to_string().contains("duplicate link id"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn parse_tunnel_interface_count_assertion() {
        let toml = r#"
name = "ifcount"
duration_secs = 20

[[nodes]]
id = "nodeA"

[[nodes]]
id = "nodeB"

[[links]]
endpoints = ["nodeA", "nodeB"]
latency_ms = 10
bandwidth_kbps = 1000

[[assertions]]
at_secs = 10.0
condition = { type = "TunnelInterfaceCount", node = "nodeA", count = 1 }
"#;

        assert!(Scenario::from_toml(toml).is_ok());
    }
}
