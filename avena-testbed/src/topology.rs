//! Network namespace management for testbed nodes using unshare.
//!
//! Uses unshare to create isolated network+mount namespaces for each node,
//! connects them with veth pairs, and manages avenad process lifecycle.

use crate::pki::{NodePaths, TestPki};
use crate::scenario::{NodeConfig, Scenario};
use avena_overlay::{
    AvenadConfig, DaemonDiscoveryConfig, NetworkConfig, RoutingConfig, StaticPeerConfig, TunnelMode,
};
use std::collections::HashMap;
use std::net::Ipv6Addr;
use std::path::PathBuf;
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
pub struct BridgeInstance {
    pub id: String,
    pub bridge_name: String,
    pub veth_pairs: Vec<(String, String)>,
}

#[derive(Debug)]
pub struct NodeInstance {
    pub id: String,
    pub pid: Option<u32>,
    pub overlay_ip: Ipv6Addr,
    pub config_path: PathBuf,
    pub avenad_process: Option<Child>,
    pub underlay_ips: Vec<(String, std::net::Ipv4Addr)>,
}

pub struct TestTopology {
    nodes: HashMap<String, NodeInstance>,
    veth_pairs: Vec<VethPair>,
    bridges: Vec<BridgeInstance>,
}

impl std::fmt::Debug for TestTopology {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TestTopology")
            .field("nodes", &self.nodes.keys().collect::<Vec<_>>())
            .field("veth_pairs", &self.veth_pairs)
            .field("bridges", &self.bridges)
            .finish()
    }
}

impl TestTopology {
    pub fn new() -> Self {
        Self {
            nodes: HashMap::new(),
            veth_pairs: Vec::new(),
            bridges: Vec::new(),
        }
    }

    pub async fn setup(&mut self, scenario: &Scenario, pki: &TestPki) -> Result<(), TopologyError> {
        let network = NetworkConfig::default();
        let mut subnet_counter = 1u8;

        for node_config in &scenario.nodes {
            let keypair = pki
                .node_keypair(&node_config.id)
                .ok_or_else(|| TopologyError::NodeNotFound(node_config.id.clone()))?;
            let overlay_ip = network.device_address(&keypair.device_id());

            self.nodes.insert(
                node_config.id.clone(),
                NodeInstance {
                    id: node_config.id.clone(),
                    pid: None,
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

            let ip_a = std::net::Ipv4Addr::new(10, subnet_counter, 0, 1);
            let ip_b = std::net::Ipv4Addr::new(10, subnet_counter, 0, 2);

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

        for bridge_config in &scenario.bridges {
            self.setup_bridge(bridge_config, &mut subnet_counter)
                .await?;
        }

        Ok(())
    }

    async fn setup_bridge(
        &mut self,
        config: &crate::scenario::BridgeConfig,
        subnet_counter: &mut u8,
    ) -> Result<(), TopologyError> {
        let bridge_name = format!("br-{}", config.id);
        let subnet = *subnet_counter;
        *subnet_counter = subnet_counter.wrapping_add(1);

        self.run_cmd("ip", &["link", "add", &bridge_name, "type", "bridge"])
            .await?;
        self.run_cmd("ip", &["link", "set", &bridge_name, "up"])
            .await?;

        let mut veth_pairs = Vec::new();

        for (i, node_id) in config.nodes.iter().enumerate() {
            let veth_br = format!("vb{}n{}", subnet, i);
            let veth_ns = format!("vn{}b{}", subnet, i);

            self.create_veth_pair(&veth_br, &veth_ns).await?;
            self.run_cmd("ip", &["link", "set", &veth_br, "master", &bridge_name])
                .await?;
            self.run_cmd("ip", &["link", "set", &veth_br, "up"]).await?;

            let ip = std::net::Ipv4Addr::new(10, subnet, 0, (i + 1) as u8);
            if let Some(node) = self.nodes.get_mut(node_id) {
                node.underlay_ips.push((veth_ns.clone(), ip));
            }

            veth_pairs.push((veth_br, veth_ns));
        }

        self.bridges.push(BridgeInstance {
            id: config.id.clone(),
            bridge_name,
            veth_pairs,
        });

        Ok(())
    }

    pub async fn start_nodes(
        &mut self,
        pki: &TestPki,
        scenario: &Scenario,
        log_dir: &std::path::Path,
    ) -> Result<(), TopologyError> {
        for node_config in &scenario.nodes {
            let node_paths = pki
                .write_node_files(&node_config.id)
                .map_err(|e| TopologyError::Io(std::io::Error::other(e.to_string())))?;

            let config = {
                let node = self
                    .nodes
                    .get(&node_config.id)
                    .ok_or_else(|| TopologyError::NodeNotFound(node_config.id.clone()))?;
                let static_peers = self.static_peers_for_node(&node_config.id, pki)?;
                self.generate_node_config(node_config, &node_paths, node, static_peers)?
            };

            let config_path = pki.temp_dir().join(format!("{}.toml", node_config.id));
            let config_str = toml::to_string_pretty(&config)?;
            std::fs::write(&config_path, &config_str)?;

            tracing::debug!(node = %node_config.id, config = %config_path.display(), "spawning avenad");

            let veth_config: Vec<_> = {
                let node = self.nodes.get(&node_config.id).unwrap();
                node.underlay_ips
                    .iter()
                    .enumerate()
                    .map(|(i, (veth, ip))| (veth.clone(), *ip, (i + 1) as u8))
                    .collect()
            };

            let (child, inner_pid) = self
                .spawn_node_in_namespace(
                    &node_config.id,
                    &config_path,
                    log_dir,
                    &veth_config,
                    pki.temp_dir(),
                )
                .await?;

            tracing::debug!(node = %node_config.id, pid = inner_pid, "avenad spawned");

            let node = self
                .nodes
                .get_mut(&node_config.id)
                .ok_or_else(|| TopologyError::NodeNotFound(node_config.id.clone()))?;
            node.config_path = config_path;
            node.pid = Some(inner_pid);
            node.avenad_process = Some(child);
        }

        Ok(())
    }

    pub async fn teardown(&mut self) -> Result<(), TopologyError> {
        for node in self.nodes.values_mut() {
            if let Some(pid) = node.pid {
                let _ = Command::new("nsenter")
                    .args([
                        "-t",
                        &pid.to_string(),
                        "-n",
                        "-m",
                        "pkill",
                        "-f",
                        "wireguard-go -f",
                    ])
                    .output()
                    .await;
            }
            if let Some(ref mut process) = node.avenad_process {
                let _ = process.kill().await;
            }
        }

        for veth in &self.veth_pairs {
            let _ = self.run_cmd("ip", &["link", "del", &veth.veth_a]).await;
        }

        for bridge in &self.bridges {
            for (veth_br, _) in &bridge.veth_pairs {
                let _ = self.run_cmd("ip", &["link", "del", veth_br]).await;
            }
            let _ = self
                .run_cmd("ip", &["link", "del", &bridge.bridge_name])
                .await;
        }

        self.nodes.clear();
        self.veth_pairs.clear();
        self.bridges.clear();

        Ok(())
    }

    pub async fn stop_node(&mut self, node_id: &str) -> Result<(), TopologyError> {
        let node = self
            .nodes
            .get_mut(node_id)
            .ok_or_else(|| TopologyError::NodeNotFound(node_id.to_string()))?;

        if let Some(ref mut process) = node.avenad_process {
            if let Some(pid) = node.pid {
                let _ = Command::new("nsenter")
                    .args([
                        "-t",
                        &pid.to_string(),
                        "-n",
                        "-m",
                        "pkill",
                        "-f",
                        "wireguard-go -f",
                    ])
                    .output()
                    .await;
            }
            process.kill().await?;
            node.avenad_process = None;
            node.pid = None;
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

        tracing::warn!(node = %node_id, "start_node after stop not fully implemented with unshare");
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

        let pid = node.pid.ok_or_else(|| TopologyError::CommandFailed {
            cmd: cmd.join(" "),
            message: "node has no running process".into(),
        })?;

        let output = Command::new("nsenter")
            .args(["-t", &pid.to_string(), "-n", "-m"])
            .args(cmd)
            .output()
            .await?;

        Ok(output)
    }

    pub fn node(&self, id: &str) -> Option<&NodeInstance> {
        self.nodes.get(id)
    }

    pub fn node_mut(&mut self, id: &str) -> Option<&mut NodeInstance> {
        self.nodes.get_mut(id)
    }

    pub fn veth_pair(&self, link_id: &str) -> Option<&VethPair> {
        self.veth_pairs.iter().find(|v| v.link_id == link_id)
    }

    pub fn bridge(&self, id: &str) -> Option<&BridgeInstance> {
        self.bridges.iter().find(|b| b.id == id)
    }

    pub fn bridges(&self) -> &[BridgeInstance] {
        &self.bridges
    }

    fn generate_node_config(
        &self,
        node_config: &NodeConfig,
        node_paths: &NodePaths,
        node: &NodeInstance,
        static_peers: Vec<StaticPeerConfig>,
    ) -> Result<AvenadConfig, TopologyError> {
        let mdns_interfaces: Vec<String> = node
            .underlay_ips
            .iter()
            .map(|(veth, _)| veth.clone())
            .collect();

        Ok(AvenadConfig {
            interface_name: format!("wg-{}", node_config.id),
            tunnel_mode: default_tunnel_mode_for_testbed(),
            network: NetworkConfig::default(),
            listen_port: 51820,
            listen_address: None,
            keypair_path: Some(node_paths.key_path.clone()),
            trusted_root_cert: node_paths.root_cert_path.clone(),
            device_cert: node_paths.cert_path.clone(),
            discovery: DaemonDiscoveryConfig {
                enable_mdns: true,
                mdns_interface: None,
                mdns_interfaces,
                static_peers,
                presence_reannounce_interval_ms: 1000,
                peer_retry_interval_ms: 250,
            },
            persistent_keepalive: 5,
            dead_peer_timeout_secs: 30,
            routing: RoutingConfig::default(),
        })
    }

    fn static_peers_for_node(
        &self,
        node_id: &str,
        pki: &TestPki,
    ) -> Result<Vec<StaticPeerConfig>, TopologyError> {
        let mut peers = Vec::new();

        for link in &self.veth_pairs {
            let (peer_node_id, peer_iface) = if link.node_a == node_id {
                (&link.node_b, &link.veth_b)
            } else if link.node_b == node_id {
                (&link.node_a, &link.veth_a)
            } else {
                continue;
            };

            let peer_node = self
                .nodes
                .get(peer_node_id)
                .ok_or_else(|| TopologyError::NodeNotFound(peer_node_id.clone()))?;
            let peer_underlay_ip = peer_node
                .underlay_ips
                .iter()
                .find(|(iface, _)| iface == peer_iface)
                .map(|(_, ip)| *ip)
                .ok_or_else(|| TopologyError::CommandFailed {
                    cmd: format!("resolve static peer underlay for {}", peer_node_id),
                    message: format!("missing underlay ip for interface {}", peer_iface),
                })?;

            let peer_keypair = pki
                .node_keypair(peer_node_id)
                .ok_or_else(|| TopologyError::NodeNotFound(peer_node_id.clone()))?;
            let endpoint = format!("{}:{}", peer_underlay_ip, 51820u16);
            peers.push(StaticPeerConfig::new(endpoint).with_device_id(peer_keypair.device_id()));
        }

        Ok(peers)
    }

    async fn create_veth_pair(&self, veth_a: &str, veth_b: &str) -> Result<(), TopologyError> {
        let _ = self.run_cmd("ip", &["link", "del", veth_a]).await;
        self.run_cmd(
            "ip",
            &[
                "link", "add", veth_a, "type", "veth", "peer", "name", veth_b,
            ],
        )
        .await
    }

    async fn spawn_node_in_namespace(
        &self,
        node_id: &str,
        config_path: &PathBuf,
        log_dir: &std::path::Path,
        veth_config: &[(String, std::net::Ipv4Addr, u8)],
        temp_dir: &std::path::Path,
    ) -> Result<(Child, u32), TopologyError> {
        let avenad_path = std::env::current_exe()?
            .parent()
            .expect("exe should have parent")
            .join("avenad");

        let stdout_path = log_dir.join(format!("{}.stdout.log", node_id));
        let stderr_path = log_dir.join(format!("{}.stderr.log", node_id));

        let stdout_file = std::fs::File::create(&stdout_path)?;
        let stderr_file = std::fs::File::create(&stderr_path)?;

        let pid_file = temp_dir.join(format!("{}.pid", node_id));
        let ready_file = temp_dir.join(format!("{}.ready", node_id));

        let mut setup_script = String::from("set -e\n");
        setup_script.push_str(&format!("echo $$ > {}\n", pid_file.display()));
        setup_script.push_str(&format!(
            "while [ ! -f {} ]; do sleep 0.05; done\n",
            ready_file.display()
        ));
        setup_script.push_str("mount -t tmpfs tmpfs /var/run\n");
        setup_script.push_str("mkdir -p /var/run/wireguard\n");
        setup_script.push_str("mkdir -p /run/avena\n");
        setup_script.push_str("ip link set lo up\n");

        for (veth, ip, ipv6_suffix) in veth_config {
            setup_script.push_str(&format!(
                "ip addr add {}/24 dev {}\n\
                 ip -6 addr add fe80::{}/64 dev {}\n\
                 ip link set {} up\n\
                 ip link set {} multicast on\n",
                ip, veth, ipv6_suffix, veth, veth, veth
            ));
        }

        setup_script.push_str(&format!(
            "exec {} {}\n",
            avenad_path.display(),
            config_path.display()
        ));

        tracing::debug!(node = %node_id, stdout = %stdout_path.display(), stderr = %stderr_path.display(), "avenad logs");

        let child = Command::new("unshare")
            .args(["--kill-child", "-rmn", "bash", "-c", &setup_script])
            .stdout(stdout_file)
            .stderr(stderr_file)
            .spawn()?;

        for _ in 0..100 {
            if pid_file.exists() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }

        let inner_pid = std::fs::read_to_string(&pid_file)
            .map_err(|e| TopologyError::Io(e))?
            .trim()
            .to_string();

        for (veth, _, _) in veth_config {
            self.run_cmd("ip", &["link", "set", veth, "netns", &inner_pid])
                .await?;
        }

        std::fs::write(&ready_file, "ready")?;

        let inner_pid_u32: u32 = inner_pid
            .parse()
            .map_err(|_| TopologyError::CommandFailed {
                cmd: "parse pid".into(),
                message: format!("invalid pid: {}", inner_pid),
            })?;

        Ok((child, inner_pid_u32))
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

#[cfg(target_os = "linux")]
fn default_tunnel_mode_for_testbed() -> TunnelMode {
    TunnelMode::Userspace
}

#[cfg(not(target_os = "linux"))]
fn default_tunnel_mode_for_testbed() -> TunnelMode {
    TunnelMode::Userspace
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
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_default_tunnel_mode_linux() {
        assert!(matches!(
            default_tunnel_mode_for_testbed(),
            TunnelMode::Userspace
        ));
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn test_default_tunnel_mode_non_linux() {
        assert!(matches!(
            default_tunnel_mode_for_testbed(),
            TunnelMode::Userspace
        ));
    }
}
