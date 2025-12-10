//! Network namespace management for testbed nodes.
//!
//! Creates isolated network namespaces for each node, connects them with veth
//! pairs, and manages avenad process lifecycle within each namespace.

use crate::pki::{NodePaths, TestPki};
use crate::scenario::{NodeConfig, Scenario};
use avena_overlay::{
    AvenadConfig, DaemonDiscoveryConfig, NetworkConfig, StaticPeerConfig, TunnelMode,
};
use std::collections::{HashMap, HashSet};
use std::net::Ipv6Addr;
use std::path::PathBuf;
use std::process::Stdio;
use thiserror::Error;
use tokio::process::{Child, Command};

#[derive(Error, Debug)]
pub enum TopologyError {
    #[error("command failed: {cmd}: {message}")]
    CommandFailed { cmd: String, message: String },

    #[error("node not found: {0}")]
    NodeNotFound(String),

    #[error("link not found: {0}")]
    LinkNotFound(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("toml serialization error: {0}")]
    Toml(#[from] toml::ser::Error),
}

#[derive(Debug)]
pub struct VethPair {
    pub link_id: String,
    pub veth_a: String,
    pub veth_b: String,
    pub node_a: String,
    pub node_b: String,
}

#[derive(Debug)]
pub struct NodeInstance {
    pub id: String,
    pub netns: String,
    pub overlay_ip: Ipv6Addr,
    pub config_path: PathBuf,
    pub avenad_process: Option<Child>,
    pub underlay_ips: Vec<(String, std::net::Ipv4Addr)>,
}

pub struct TestTopology {
    nodes: HashMap<String, NodeInstance>,
    veth_pairs: Vec<VethPair>,
    namespace_prefix: String,
}

impl std::fmt::Debug for TestTopology {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TestTopology")
            .field("nodes", &self.nodes.keys().collect::<Vec<_>>())
            .field("veth_pairs", &self.veth_pairs)
            .field("namespace_prefix", &self.namespace_prefix)
            .finish()
    }
}

impl TestTopology {
    pub fn new() -> Self {
        let id = std::process::id();
        Self {
            nodes: HashMap::new(),
            veth_pairs: Vec::new(),
            namespace_prefix: format!("avena-test-{id}"),
        }
    }

    pub async fn setup(&mut self, scenario: &Scenario, pki: &TestPki) -> Result<(), TopologyError> {
        let network = NetworkConfig::default();
        let mut subnet_counter = 1u8;

        for node_config in &scenario.nodes {
            let netns = format!("{}-{}", self.namespace_prefix, node_config.id);
            self.create_namespace(&netns).await?;

            let keypair = pki
                .node_keypair(&node_config.id)
                .ok_or_else(|| TopologyError::NodeNotFound(node_config.id.clone()))?;
            let overlay_ip = network.device_address(&keypair.device_id());

            self.nodes.insert(
                node_config.id.clone(),
                NodeInstance {
                    id: node_config.id.clone(),
                    netns,
                    overlay_ip,
                    config_path: PathBuf::new(),
                    avenad_process: None,
                    underlay_ips: Vec::new(),
                },
            );
        }

        for link_config in &scenario.links {
            let (node_a, node_b) = &link_config.endpoints;
            let link_id = format!("{}-{}", node_a, node_b);

            let veth_a = format!("v{}a", subnet_counter);
            let veth_b = format!("v{}b", subnet_counter);

            self.create_veth_pair(&veth_a, &veth_b).await?;

            let netns_a = self
                .nodes
                .get(node_a)
                .ok_or_else(|| TopologyError::NodeNotFound(node_a.clone()))?
                .netns
                .clone();
            let netns_b = self
                .nodes
                .get(node_b)
                .ok_or_else(|| TopologyError::NodeNotFound(node_b.clone()))?
                .netns
                .clone();

            self.move_veth_to_namespace(&veth_a, &netns_a).await?;
            self.move_veth_to_namespace(&veth_b, &netns_b).await?;

            let ip_a = std::net::Ipv4Addr::new(10, subnet_counter, 0, 1);
            let ip_b = std::net::Ipv4Addr::new(10, subnet_counter, 0, 2);

            self.configure_veth_in_namespace(&netns_a, &veth_a, ip_a)
                .await?;
            self.configure_veth_in_namespace(&netns_b, &veth_b, ip_b)
                .await?;

            if let Some(node) = self.nodes.get_mut(node_a) {
                node.underlay_ips.push((veth_a.clone(), ip_a));
            }
            if let Some(node) = self.nodes.get_mut(node_b) {
                node.underlay_ips.push((veth_b.clone(), ip_b));
            }

            self.veth_pairs.push(VethPair {
                link_id,
                veth_a,
                veth_b,
                node_a: node_a.clone(),
                node_b: node_b.clone(),
            });

            subnet_counter = subnet_counter.wrapping_add(1);
        }

        Ok(())
    }

    pub async fn start_nodes(
        &mut self,
        pki: &TestPki,
        scenario: &Scenario,
    ) -> Result<(), TopologyError> {
        for node_config in &scenario.nodes {
            let node_paths = pki
                .write_node_files(&node_config.id)
                .map_err(|e| TopologyError::Io(std::io::Error::other(e.to_string())))?;

            let (config, netns) = {
                let node = self
                    .nodes
                    .get(&node_config.id)
                    .ok_or_else(|| TopologyError::NodeNotFound(node_config.id.clone()))?;
                let config =
                    self.generate_node_config(node_config, &node_paths, node, scenario)?;
                (config, node.netns.clone())
            };

            let config_path = pki.temp_dir().join(format!("{}.toml", node_config.id));
            let config_str = toml::to_string_pretty(&config)?;
            std::fs::write(&config_path, &config_str)?;

            let child = self.spawn_avenad_in_namespace(&netns, &config_path)?;

            let node = self
                .nodes
                .get_mut(&node_config.id)
                .ok_or_else(|| TopologyError::NodeNotFound(node_config.id.clone()))?;
            node.config_path = config_path;
            node.avenad_process = Some(child);
        }

        Ok(())
    }

    pub async fn teardown(&mut self) -> Result<(), TopologyError> {
        for node in self.nodes.values_mut() {
            if let Some(ref mut process) = node.avenad_process {
                let _ = process.kill().await;
            }
        }

        for node in self.nodes.values() {
            let _ = self.delete_namespace(&node.netns).await;
        }

        self.nodes.clear();
        self.veth_pairs.clear();

        Ok(())
    }

    pub async fn stop_node(&mut self, node_id: &str) -> Result<(), TopologyError> {
        let node = self
            .nodes
            .get_mut(node_id)
            .ok_or_else(|| TopologyError::NodeNotFound(node_id.to_string()))?;

        if let Some(ref mut process) = node.avenad_process {
            process.kill().await?;
            node.avenad_process = None;
        }
        Ok(())
    }

    pub async fn start_node(&self, node_id: &str) -> Result<(), TopologyError> {
        let node = self
            .nodes
            .get(node_id)
            .ok_or_else(|| TopologyError::NodeNotFound(node_id.to_string()))?;

        if node.avenad_process.is_some() {
            return Ok(());
        }

        let _child = self.spawn_avenad_in_namespace(&node.netns, &node.config_path)?;
        Ok(())
    }

    pub async fn exec_in_node(
        &self,
        node_id: &str,
        cmd: &[&str],
    ) -> Result<std::process::Output, TopologyError> {
        let node = self
            .nodes
            .get(node_id)
            .ok_or_else(|| TopologyError::NodeNotFound(node_id.to_string()))?;

        let output = Command::new("ip")
            .args(["netns", "exec", &node.netns])
            .args(cmd)
            .output()
            .await?;

        Ok(output)
    }

    pub fn node(&self, id: &str) -> Option<&NodeInstance> {
        self.nodes.get(id)
    }

    pub fn veth_pair(&self, link_id: &str) -> Option<&VethPair> {
        self.veth_pairs.iter().find(|v| v.link_id == link_id)
    }

    fn generate_node_config(
        &self,
        node_config: &NodeConfig,
        node_paths: &NodePaths,
        _node: &NodeInstance,
        scenario: &Scenario,
    ) -> Result<AvenadConfig, TopologyError> {
        let static_peers = self.build_static_peers(&node_config.id, scenario);

        Ok(AvenadConfig {
            interface_name: format!("wg-{}", node_config.id),
            tunnel_mode: TunnelMode::Userspace,
            network: NetworkConfig::default(),
            listen_port: 51820,
            listen_address: None,
            keypair_path: Some(node_paths.key_path.clone()),
            trusted_root_cert: node_paths.root_cert_path.clone(),
            device_cert: node_paths.cert_path.clone(),
            discovery: DaemonDiscoveryConfig {
                enable_mdns: false,
                mdns_interface: None,
                static_peers,
            },
            persistent_keepalive: 5,
            dead_peer_timeout_secs: 30,
        })
    }

    fn build_static_peers(&self, node_id: &str, scenario: &Scenario) -> Vec<StaticPeerConfig> {
        let mut peers = Vec::new();

        for link in &scenario.links {
            let (a, b) = &link.endpoints;
            let peer_id = if a == node_id {
                b
            } else if b == node_id {
                a
            } else {
                continue;
            };

            if let Some(peer_node) = self.nodes.get(peer_id) {
                for (_, ip) in &peer_node.underlay_ips {
                    peers.push(StaticPeerConfig {
                        device_id: None,
                        endpoint: format!("{}:51820", ip),
                        capabilities: HashSet::new(),
                    });
                }
            }
        }

        peers
    }

    async fn create_namespace(&self, name: &str) -> Result<(), TopologyError> {
        self.run_cmd("ip", &["netns", "add", name]).await?;
        self.run_cmd("ip", &["netns", "exec", name, "ip", "link", "set", "lo", "up"])
            .await?;
        Ok(())
    }

    async fn delete_namespace(&self, name: &str) -> Result<(), TopologyError> {
        self.run_cmd("ip", &["netns", "del", name]).await
    }

    async fn create_veth_pair(&self, veth_a: &str, veth_b: &str) -> Result<(), TopologyError> {
        self.run_cmd(
            "ip",
            &[
                "link", "add", veth_a, "type", "veth", "peer", "name", veth_b,
            ],
        )
        .await
    }

    async fn move_veth_to_namespace(&self, veth: &str, netns: &str) -> Result<(), TopologyError> {
        self.run_cmd("ip", &["link", "set", veth, "netns", netns])
            .await
    }

    async fn configure_veth_in_namespace(
        &self,
        netns: &str,
        veth: &str,
        ip: std::net::Ipv4Addr,
    ) -> Result<(), TopologyError> {
        let addr = format!("{}/24", ip);
        self.run_cmd(
            "ip",
            &["netns", "exec", netns, "ip", "addr", "add", &addr, "dev", veth],
        )
        .await?;
        self.run_cmd(
            "ip",
            &["netns", "exec", netns, "ip", "link", "set", veth, "up"],
        )
        .await?;
        Ok(())
    }

    fn spawn_avenad_in_namespace(
        &self,
        netns: &str,
        config_path: &PathBuf,
    ) -> Result<Child, TopologyError> {
        let avenad_path = std::env::current_exe()?
            .parent()
            .expect("exe should have parent")
            .join("avenad");

        let child = Command::new("ip")
            .args(["netns", "exec", netns])
            .arg(&avenad_path)
            .arg("-c")
            .arg(config_path)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;

        Ok(child)
    }

    async fn run_cmd(&self, cmd: &str, args: &[&str]) -> Result<(), TopologyError> {
        let output = Command::new(cmd).args(args).output().await?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(TopologyError::CommandFailed {
                cmd: format!("{} {}", cmd, args.join(" ")),
                message: stderr.to_string(),
            });
        }

        Ok(())
    }
}

impl Default for TestTopology {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_topology_new() {
        let topo = TestTopology::new();
        assert!(topo.nodes.is_empty());
        assert!(topo.veth_pairs.is_empty());
        assert!(topo.namespace_prefix.starts_with("avena-test-"));
    }
}
