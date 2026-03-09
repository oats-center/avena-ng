//! Configuration types for the `avenad` daemon.
//!
//! Settings include network prefix, discovery backends, interface name, and
//! backend selection (kernel, userspace, or prefer-kernel fallback).

use crate::crypto::{CertError, CertValidator};
use crate::discovery::StaticPeerConfig;
use crate::routing::BabeldConfig;
use crate::NetworkConfig;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::PathBuf;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TunnelMode {
    Kernel,
    Userspace,
    #[serde(rename = "prefer_kernel")]
    PreferKernel,
}

impl Default for TunnelMode {
    fn default() -> Self {
        // Prefer the kernel backend when available, but transparently fall back
        // to userspace when the WireGuard kernel module/capabilities are not
        // present (common in containers and some CI environments).
        TunnelMode::PreferKernel
    }
}

/// Runtime configuration for the avena daemon.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AvenadConfig {
    #[serde(default = "default_interface_name")]
    /// WireGuard interface name to create/manage.
    pub interface_name: String,

    #[serde(default)]
    /// Choose kernel, userspace, or prefer-kernel WireGuard backend mode.
    pub tunnel_mode: TunnelMode,

    #[serde(default)]
    /// Overlay addressing configuration.
    pub network: NetworkConfig,

    #[serde(default = "default_listen_port")]
    /// WireGuard listen port for the overlay.
    pub listen_port: u16,

    #[serde(default)]
    /// Optional explicit socket address for the TCP handshake listener.
    pub listen_address: Option<SocketAddr>,

    /// Optional path to persist the device keypair seed.
    pub keypair_path: Option<PathBuf>,

    /// Path to trusted root certificate (JWT file, single token).
    pub trusted_root_cert: PathBuf,

    /// Path to device certificate (JWT file, single token).
    pub device_cert: PathBuf,

    #[serde(default)]
    /// Peer discovery configuration (mDNS/static peers).
    pub discovery: DiscoveryConfig,

    #[serde(default = "default_keepalive")]
    /// Persistent keepalive in seconds sent to peers.
    pub persistent_keepalive: u16,

    #[serde(default = "default_dead_peer_timeout")]
    /// How long before an inactive peer is removed.
    pub dead_peer_timeout_secs: u64,

    #[serde(default)]
    /// Routing protocol configuration (babeld).
    pub routing: RoutingConfig,

    #[serde(default)]
    /// Telemetry publishing configuration (NATS).
    pub telemetry: TelemetryConfig,
}

/// Routing protocol configuration.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RoutingConfig {
    #[serde(default)]
    /// Babeld-specific configuration.
    pub babel: BabeldConfig,
}

impl Default for RoutingConfig {
    fn default() -> Self {
        Self {
            babel: BabeldConfig::default(),
        }
    }
}

/// Telemetry transport configuration.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TelemetryConfig {
    #[serde(default = "default_publish_nats")]
    /// Publish telemetry events to NATS when true.
    pub publish_nats: bool,

    #[serde(default)]
    /// Optional explicit NATS URL. Falls back to AVENA_NATS_URL when unset.
    pub nats_url: Option<String>,

    #[serde(default)]
    /// Optional run identifier used in telemetry subjects.
    pub run_id: Option<String>,

    #[serde(default)]
    /// Optional logical node identifier to use in telemetry subjects.
    pub node_id: Option<String>,

    #[serde(default = "default_babel_snapshot_interval_secs")]
    /// How often to publish Babel route/neighbour snapshots.
    pub babel_snapshot_interval_secs: u64,
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            publish_nats: default_publish_nats(),
            nats_url: None,
            run_id: None,
            node_id: None,
            babel_snapshot_interval_secs: default_babel_snapshot_interval_secs(),
        }
    }
}

/// Discovery-specific configuration embedded in `AvenadConfig`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DiscoveryConfig {
    #[serde(default = "default_mdns_enabled")]
    /// Enable mDNS advertising/browsing when true.
    pub enable_mdns: bool,

    /// Network interface to bind mDNS to (deprecated, use mdns_interfaces).
    pub mdns_interface: Option<String>,

    #[serde(default)]
    /// Network interfaces to bind mDNS to (empty = system default).
    pub mdns_interfaces: Vec<String>,

    #[serde(default)]
    /// Statically configured peer endpoints.
    pub static_peers: Vec<StaticPeerConfig>,

    #[serde(default = "default_presence_reannounce_interval_ms")]
    /// How often to re-announce local presence for discovery.
    pub presence_reannounce_interval_ms: u64,

    #[serde(default = "default_peer_retry_interval_ms")]
    /// How often to retry connecting cached discovered peers.
    pub peer_retry_interval_ms: u64,
}

impl DiscoveryConfig {
    pub fn effective_mdns_interfaces(&self) -> Vec<String> {
        if !self.mdns_interfaces.is_empty() {
            self.mdns_interfaces.clone()
        } else if let Some(ref iface) = self.mdns_interface {
            vec![iface.clone()]
        } else {
            Vec::new()
        }
    }
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self {
            enable_mdns: default_mdns_enabled(),
            mdns_interface: None,
            mdns_interfaces: Vec::new(),
            static_peers: Vec::new(),
            presence_reannounce_interval_ms: default_presence_reannounce_interval_ms(),
            peer_retry_interval_ms: default_peer_retry_interval_ms(),
        }
    }
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

fn default_publish_nats() -> bool {
    true
}

fn default_babel_snapshot_interval_secs() -> u64 {
    1
}

fn default_mdns_enabled() -> bool {
    true
}

fn default_presence_reannounce_interval_ms() -> u64 {
    1000
}

fn default_peer_retry_interval_ms() -> u64 {
    250
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
            trusted_root_cert: PathBuf::from("/etc/avena/root.cert"),
            device_cert: PathBuf::from("/etc/avena/device.cert"),
            discovery: DiscoveryConfig::default(),
            persistent_keepalive: default_keepalive(),
            dead_peer_timeout_secs: default_dead_peer_timeout(),
            routing: RoutingConfig::default(),
            telemetry: TelemetryConfig::default(),
        }
    }
}

impl AvenadConfig {
    pub fn load_from_file(path: &std::path::Path) -> Result<Self, ConfigError> {
        let contents = std::fs::read_to_string(path).map_err(ConfigError::Io)?;
        toml::from_str(&contents).map_err(ConfigError::Parse)
    }

    pub fn load_crypto(&self) -> Result<(CertValidator, String), ConfigError> {
        let root_jwt = std::fs::read_to_string(&self.trusted_root_cert)
            .map_err(ConfigError::Io)?
            .trim()
            .to_string();

        let device_cert = std::fs::read_to_string(&self.device_cert)
            .map_err(ConfigError::Io)?
            .trim()
            .to_string();

        let validator = CertValidator::new(&root_jwt).map_err(ConfigError::Cert)?;
        validator
            .validate_cert(&device_cert)
            .map_err(ConfigError::Cert)?;

        Ok((validator, device_cert))
    }

    pub fn to_discovery_config(&self) -> crate::discovery::DiscoveryConfig {
        crate::discovery::DiscoveryConfig {
            enable_mdns: self.discovery.enable_mdns,
            mdns_interfaces: self.discovery.effective_mdns_interfaces(),
            static_peers: self.discovery.static_peers.clone(),
        }
    }
}

#[derive(Debug)]
pub enum ConfigError {
    Io(std::io::Error),
    Parse(toml::de::Error),
    Json(serde_json::Error),
    Cert(CertError),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigError::Io(e) => write!(f, "config io error: {}", e),
            ConfigError::Parse(e) => write!(f, "config parse error: {}", e),
            ConfigError::Json(e) => write!(f, "json parse error: {}", e),
            ConfigError::Cert(e) => write!(f, "certificate error: {}", e),
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
        assert_eq!(config.discovery.presence_reannounce_interval_ms, 1000);
        assert_eq!(config.discovery.peer_retry_interval_ms, 250);
        assert_eq!(
            config.trusted_root_cert,
            PathBuf::from("/etc/avena/root.cert")
        );
        assert_eq!(config.device_cert, PathBuf::from("/etc/avena/device.cert"));
        assert!(config.telemetry.publish_nats);
        assert_eq!(config.telemetry.babel_snapshot_interval_secs, 1);
    }

    #[test]
    fn telemetry_defaults_are_safe() {
        let telemetry = TelemetryConfig::default();
        assert!(telemetry.publish_nats);
        assert!(telemetry.nats_url.is_none());
        assert!(telemetry.run_id.is_none());
        assert!(telemetry.node_id.is_none());
        assert_eq!(telemetry.babel_snapshot_interval_secs, 1);
    }

    #[test]
    fn parse_minimal_toml() {
        let toml = r#"
            interface_name = "wg-avena"
            trusted_root_cert = "/tmp/root.cert"
            device_cert = "/tmp/device.cert"
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
            trusted_root_cert = "/etc/avena/root.cert"
            device_cert = "/etc/avena/device.cert"

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
        assert_eq!(config.discovery.presence_reannounce_interval_ms, 1000);
        assert_eq!(config.discovery.peer_retry_interval_ms, 250);
    }

    #[test]
    fn parse_prefer_kernel_tunnel_mode() {
        let toml = r#"
            interface_name = "avena1"
            tunnel_mode = "prefer_kernel"
            trusted_root_cert = "/etc/avena/root.cert"
            device_cert = "/etc/avena/device.cert"
        "#;
        let config: AvenadConfig = toml::from_str(toml).unwrap();
        assert!(matches!(config.tunnel_mode, TunnelMode::PreferKernel));
    }
}
