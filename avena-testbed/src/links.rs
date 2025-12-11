//! Link shaping using tc/netem.
//!
//! Manages link parameters (latency, bandwidth, loss) and enables/disables
//! links by bringing veth interfaces up/down.

use crate::scenario::{BridgeConfig, LinkConfig};
use crate::topology::TestTopology;
use std::collections::HashMap;
use thiserror::Error;
use tokio::process::Command;

#[derive(Error, Debug)]
pub enum LinkError {
    #[error("link not found: {0}")]
    NotFound(String),

    #[error("command failed: {cmd}: {message}")]
    CommandFailed { cmd: String, message: String },

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("node has no running process: {0}")]
    NodeNotRunning(String),
}

#[derive(Debug, Clone)]
pub struct LinkState {
    pub link_id: String,
    pub latency_ms: u32,
    pub bandwidth_kbps: u32,
    pub loss_percent: f32,
    pub enabled: bool,
    pub pid_a: Option<u32>,
    pub pid_b: Option<u32>,
    pub veth_a: String,
    pub veth_b: String,
}

#[derive(Debug, Clone)]
pub struct BridgeState {
    pub bridge_id: String,
    pub bridge_name: String,
    pub latency_ms: u32,
    pub bandwidth_kbps: u32,
    pub loss_percent: f32,
}

#[derive(Debug)]
pub struct LinkManager {
    links: HashMap<String, LinkState>,
    bridges: HashMap<String, BridgeState>,
}

impl LinkManager {
    pub fn new() -> Self {
        Self {
            links: HashMap::new(),
            bridges: HashMap::new(),
        }
    }

    pub fn initialize_from_topology(
        &mut self,
        topology: &TestTopology,
        link_configs: &[LinkConfig],
        bridge_configs: &[BridgeConfig],
    ) {
        for config in link_configs {
            let link_id = format!("{}-{}", config.endpoints.0, config.endpoints.1);

            if let Some(veth_pair) = topology.veth_pair(&link_id) {
                let node_a = topology.node(&config.endpoints.0);
                let node_b = topology.node(&config.endpoints.1);

                if let (Some(a), Some(b)) = (node_a, node_b) {
                    self.links.insert(
                        link_id.clone(),
                        LinkState {
                            link_id,
                            latency_ms: config.latency_ms,
                            bandwidth_kbps: config.bandwidth_kbps,
                            loss_percent: config.loss_percent,
                            enabled: config.enabled,
                            pid_a: a.pid,
                            pid_b: b.pid,
                            veth_a: veth_pair.veth_a.clone(),
                            veth_b: veth_pair.veth_b.clone(),
                        },
                    );
                }
            }
        }

        for config in bridge_configs {
            if let Some(bridge) = topology.bridge(&config.id) {
                self.bridges.insert(
                    config.id.clone(),
                    BridgeState {
                        bridge_id: config.id.clone(),
                        bridge_name: bridge.bridge_name.clone(),
                        latency_ms: config.latency_ms,
                        bandwidth_kbps: config.bandwidth_kbps,
                        loss_percent: config.loss_percent,
                    },
                );
            }
        }
    }

    pub fn update_pids(&mut self, topology: &TestTopology) {
        for state in self.links.values_mut() {
            let parts: Vec<&str> = state.link_id.split('-').collect();
            if parts.len() == 2 {
                if let Some(node_a) = topology.node(parts[0]) {
                    state.pid_a = node_a.pid;
                }
                if let Some(node_b) = topology.node(parts[1]) {
                    state.pid_b = node_b.pid;
                }
            }
        }
    }

    pub async fn apply_initial_state(&self) -> Result<(), LinkError> {
        for state in self.links.values() {
            if state.pid_a.is_some() && state.pid_b.is_some() {
                self.apply_netem(state).await?;
                if !state.enabled {
                    self.set_link_enabled_internal(state, false).await?;
                }
            }
        }

        for state in self.bridges.values() {
            self.apply_netem_to_bridge(state).await?;
        }

        Ok(())
    }

    async fn apply_netem_to_bridge(&self, state: &BridgeState) -> Result<(), LinkError> {
        if state.latency_ms == 0 && state.loss_percent == 0.0 {
            return Ok(());
        }

        let delay_arg = format!("{}ms", state.latency_ms);
        let loss_arg = format!("{}%", state.loss_percent);

        self.run_cmd(&[
            "tc", "qdisc", "add", "dev", &state.bridge_name, "root", "netem",
            "delay", &delay_arg, "loss", &loss_arg,
        ]).await
    }

    async fn run_cmd(&self, args: &[&str]) -> Result<(), LinkError> {
        let output = Command::new(args[0]).args(&args[1..]).output().await?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(LinkError::CommandFailed {
                cmd: args.join(" "),
                message: stderr.to_string(),
            });
        }

        Ok(())
    }

    pub async fn set_link_enabled(&mut self, link_id: &str, enabled: bool) -> Result<(), LinkError> {
        let state = self
            .links
            .get(link_id)
            .ok_or_else(|| LinkError::NotFound(link_id.to_string()))?
            .clone();

        self.set_link_enabled_internal(&state, enabled).await?;

        if let Some(s) = self.links.get_mut(link_id) {
            s.enabled = enabled;
        }
        Ok(())
    }

    pub async fn modify_link(
        &mut self,
        link_id: &str,
        latency_ms: Option<u32>,
        loss_percent: Option<f32>,
    ) -> Result<(), LinkError> {
        {
            let state = self
                .links
                .get_mut(link_id)
                .ok_or_else(|| LinkError::NotFound(link_id.to_string()))?;

            if let Some(lat) = latency_ms {
                state.latency_ms = lat;
            }
            if let Some(loss) = loss_percent {
                state.loss_percent = loss;
            }
        }

        let state = self.links.get(link_id).unwrap().clone();
        self.update_netem(&state).await?;
        Ok(())
    }

    pub fn link(&self, link_id: &str) -> Option<&LinkState> {
        self.links.get(link_id)
    }

    pub fn link_id_from_ref(&self, link_ref: &str) -> Option<String> {
        if self.links.contains_key(link_ref) {
            return Some(link_ref.to_string());
        }

        let parts: Vec<&str> = link_ref.split('-').collect();
        if parts.len() == 2 {
            let reversed = format!("{}-{}", parts[1], parts[0]);
            if self.links.contains_key(&reversed) {
                return Some(reversed);
            }
        }

        None
    }

    async fn apply_netem(&self, state: &LinkState) -> Result<(), LinkError> {
        if let Some(pid_a) = state.pid_a {
            self.apply_netem_to_veth(pid_a, &state.veth_a, state.latency_ms, state.loss_percent)
                .await?;
        }
        if let Some(pid_b) = state.pid_b {
            self.apply_netem_to_veth(pid_b, &state.veth_b, state.latency_ms, state.loss_percent)
                .await?;
        }
        Ok(())
    }

    async fn apply_netem_to_veth(
        &self,
        pid: u32,
        veth: &str,
        latency_ms: u32,
        loss_percent: f32,
    ) -> Result<(), LinkError> {
        let delay_arg = format!("{}ms", latency_ms);
        let loss_arg = format!("{}%", loss_percent);

        self.run_in_ns(
            pid,
            &[
                "tc", "qdisc", "add", "dev", veth, "root", "netem", "delay", &delay_arg, "loss",
                &loss_arg,
            ],
        )
        .await
    }

    async fn update_netem(&self, state: &LinkState) -> Result<(), LinkError> {
        if let Some(pid_a) = state.pid_a {
            self.update_netem_on_veth(pid_a, &state.veth_a, state.latency_ms, state.loss_percent)
                .await?;
        }
        if let Some(pid_b) = state.pid_b {
            self.update_netem_on_veth(pid_b, &state.veth_b, state.latency_ms, state.loss_percent)
                .await?;
        }
        Ok(())
    }

    async fn update_netem_on_veth(
        &self,
        pid: u32,
        veth: &str,
        latency_ms: u32,
        loss_percent: f32,
    ) -> Result<(), LinkError> {
        let delay_arg = format!("{}ms", latency_ms);
        let loss_arg = format!("{}%", loss_percent);

        self.run_in_ns(
            pid,
            &[
                "tc", "qdisc", "change", "dev", veth, "root", "netem", "delay", &delay_arg, "loss",
                &loss_arg,
            ],
        )
        .await
    }

    async fn set_link_enabled_internal(
        &self,
        state: &LinkState,
        enabled: bool,
    ) -> Result<(), LinkError> {
        let action = if enabled { "up" } else { "down" };

        if let Some(pid_a) = state.pid_a {
            self.run_in_ns(pid_a, &["ip", "link", "set", &state.veth_a, action])
                .await?;
        }
        if let Some(pid_b) = state.pid_b {
            self.run_in_ns(pid_b, &["ip", "link", "set", &state.veth_b, action])
                .await?;
        }

        Ok(())
    }

    async fn run_in_ns(&self, pid: u32, args: &[&str]) -> Result<(), LinkError> {
        let pid_str = pid.to_string();
        let mut cmd_args = vec!["-t", &pid_str, "-n", "-m"];
        cmd_args.extend(args);

        let output = Command::new("nsenter").args(&cmd_args).output().await?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(LinkError::CommandFailed {
                cmd: format!("nsenter {}", cmd_args.join(" ")),
                message: stderr.to_string(),
            });
        }

        Ok(())
    }
}

impl Default for LinkManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_link_manager_new() {
        let manager = LinkManager::new();
        assert!(manager.links.is_empty());
    }
}
