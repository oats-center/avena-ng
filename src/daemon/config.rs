use crate::discovery::StaticPeerConfig;
use crate::NetworkConfig;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::PathBuf;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TunnelMode {
    Kernel,
    Userspace,
}

impl Default for TunnelMode {
    fn default() -> Self {
        TunnelMode::Kernel
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AvenadConfig {
    #[serde(default = "default_interface_name")]
    pub interface_name: String,

    #[serde(default)]
    pub tunnel_mode: TunnelMode,

    #[serde(default)]
    pub network: NetworkConfig,

    #[serde(default = "default_listen_port")]
    pub listen_port: u16,

    #[serde(default)]
    pub listen_address: Option<SocketAddr>,

    pub keypair_path: Option<PathBuf>,

    #[serde(default)]
    pub discovery: DiscoveryConfig,

    #[serde(default = "default_keepalive")]
    pub persistent_keepalive: u16,

    #[serde(default = "default_dead_peer_timeout")]
    pub dead_peer_timeout_secs: u64,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct DiscoveryConfig {
    #[serde(default = "default_mdns_enabled")]
    pub enable_mdns: bool,

    pub mdns_interface: Option<String>,

    #[serde(default)]
    pub static_peers: Vec<StaticPeerConfig>,
}

fn default_interface_name() -> String {
    "avena0".to_string()
}

fn default_listen_port() -> u16 {
    51820
}

fn default_keepalive() -> u16 {
    25
}

fn default_dead_peer_timeout() -> u64 {
    180
}

fn default_mdns_enabled() -> bool {
    true
}

impl Default for AvenadConfig {
    fn default() -> Self {
        Self {
            interface_name: default_interface_name(),
            tunnel_mode: TunnelMode::default(),
            network: NetworkConfig::default(),
            listen_port: default_listen_port(),
            listen_address: None,
            keypair_path: None,
            discovery: DiscoveryConfig::default(),
            persistent_keepalive: default_keepalive(),
            dead_peer_timeout_secs: default_dead_peer_timeout(),
        }
    }
}

impl AvenadConfig {
    pub fn load_from_file(path: &std::path::Path) -> Result<Self, ConfigError> {
        let contents = std::fs::read_to_string(path).map_err(ConfigError::Io)?;
        toml::from_str(&contents).map_err(ConfigError::Parse)
    }

    pub fn to_discovery_config(&self) -> crate::discovery::DiscoveryConfig {
        crate::discovery::DiscoveryConfig {
            enable_mdns: self.discovery.enable_mdns,
            mdns_interface: self.discovery.mdns_interface.clone(),
            static_peers: self.discovery.static_peers.clone(),
        }
    }
}

#[derive(Debug)]
pub enum ConfigError {
    Io(std::io::Error),
    Parse(toml::de::Error),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigError::Io(e) => write!(f, "config io error: {}", e),
            ConfigError::Parse(e) => write!(f, "config parse error: {}", e),
        }
    }
}

impl std::error::Error for ConfigError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_is_valid() {
        let config = AvenadConfig::default();
        assert_eq!(config.interface_name, "avena0");
        assert_eq!(config.listen_port, 51820);
        assert_eq!(config.persistent_keepalive, 25);
    }

    #[test]
    fn parse_minimal_toml() {
        let toml = r#"
            interface_name = "wg-avena"
        "#;
        let config: AvenadConfig = toml::from_str(toml).unwrap();
        assert_eq!(config.interface_name, "wg-avena");
        assert_eq!(config.listen_port, 51820);
    }

    #[test]
    fn parse_full_toml() {
        let toml = r#"
            interface_name = "avena1"
            tunnel_mode = "userspace"
            listen_port = 51821

            [network]
            prefix = "fd00:1234:5678::"
            prefix_len = 48

            [discovery]
            enable_mdns = false
            static_peers = [
                { endpoint = "10.0.0.1:51820" }
            ]
        "#;
        let config: AvenadConfig = toml::from_str(toml).unwrap();
        assert_eq!(config.interface_name, "avena1");
        assert_eq!(config.listen_port, 51821);
        assert!(!config.discovery.enable_mdns);
        assert_eq!(config.discovery.static_peers.len(), 1);
    }
}
