//! WireGuard backend abstraction shared by kernel and userspace implementations.

use async_trait::async_trait;
use ipnet::IpNet;
use std::net::SocketAddr;
use std::time::SystemTime;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum TunnelError {
    #[error("interface creation failed: {0}")]
    InterfaceCreation(String),

    #[error("interface not found: {0}")]
    InterfaceNotFound(String),

    #[error("peer operation failed: {0}")]
    PeerOperation(String),

    #[error("peer not found")]
    PeerNotFound,

    #[error("wireguard error: {0}")]
    Wireguard(String),

    #[error("permission denied: {0}")]
    PermissionDenied(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// Configuration for a single WireGuard peer.
#[derive(Clone, Debug)]
pub struct PeerConfig {
    pub wireguard_pubkey: [u8; 32],
    pub psk: Option<[u8; 32]>,
    pub allowed_ips: Vec<IpNet>,
    pub endpoint: Option<SocketAddr>,
    pub persistent_keepalive: Option<u16>,
}

impl PeerConfig {
    /// Create a minimal peer config with a mandatory public key.
    pub fn new(wireguard_pubkey: [u8; 32]) -> Self {
        Self {
            wireguard_pubkey,
            psk: None,
            allowed_ips: Vec::new(),
            endpoint: None,
            persistent_keepalive: None,
        }
    }

    /// Attach a preshared key used for this peer.
    pub fn with_psk(mut self, psk: [u8; 32]) -> Self {
        self.psk = Some(psk);
        self
    }

    /// Set allowed IP prefixes for this peer.
    pub fn with_allowed_ips(mut self, allowed_ips: Vec<IpNet>) -> Self {
        self.allowed_ips = allowed_ips;
        self
    }

    /// Set the peer's reachable endpoint.
    pub fn with_endpoint(mut self, endpoint: SocketAddr) -> Self {
        self.endpoint = Some(endpoint);
        self
    }

    /// Enable persistent keepalive packets.
    pub fn with_keepalive(mut self, interval: u16) -> Self {
        self.persistent_keepalive = Some(interval);
        self
    }
}

/// Basic counters and timestamps for a configured peer.
#[derive(Clone, Debug, Default)]
pub struct PeerStats {
    pub last_handshake: Option<SystemTime>,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}

#[async_trait]
/// Abstraction over kernel and userspace WireGuard implementations.
pub trait TunnelBackend: Send + Sync {
    async fn ensure_interface(&self, name: &str) -> Result<(), TunnelError>;
    async fn set_private_key(&self, private_key: &[u8; 32]) -> Result<(), TunnelError>;
    async fn add_peer(&self, peer: &PeerConfig) -> Result<(), TunnelError>;
    async fn remove_peer(&self, pubkey: &[u8; 32]) -> Result<(), TunnelError>;
    async fn update_endpoint(
        &self,
        pubkey: &[u8; 32],
        endpoint: SocketAddr,
    ) -> Result<(), TunnelError>;
    async fn peer_stats(&self, pubkey: &[u8; 32]) -> Result<PeerStats, TunnelError>;
    async fn listen_port(&self) -> Result<u16, TunnelError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv6Addr, SocketAddrV6};

    #[test]
    fn peer_config_builder_pattern() {
        let pubkey = [1u8; 32];
        let psk = [2u8; 32];
        let endpoint = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 51820, 0, 0));
        let allowed: IpNet = "fd00::/64".parse().unwrap();

        let config = PeerConfig::new(pubkey)
            .with_psk(psk)
            .with_endpoint(endpoint)
            .with_allowed_ips(vec![allowed.clone()])
            .with_keepalive(25);

        assert_eq!(config.wireguard_pubkey, pubkey);
        assert_eq!(config.psk, Some(psk));
        assert_eq!(config.endpoint, Some(endpoint));
        assert_eq!(config.allowed_ips, vec![allowed]);
        assert_eq!(config.persistent_keepalive, Some(25));
    }

    #[test]
    fn peer_config_minimal() {
        let pubkey = [3u8; 32];
        let config = PeerConfig::new(pubkey);

        assert_eq!(config.wireguard_pubkey, pubkey);
        assert!(config.psk.is_none());
        assert!(config.allowed_ips.is_empty());
        assert!(config.endpoint.is_none());
        assert!(config.persistent_keepalive.is_none());
    }

    #[test]
    fn peer_stats_default() {
        let stats = PeerStats::default();
        assert!(stats.last_handshake.is_none());
        assert_eq!(stats.rx_bytes, 0);
        assert_eq!(stats.tx_bytes, 0);
    }

    #[test]
    fn tunnel_error_display() {
        let err = TunnelError::InterfaceCreation("test".into());
        assert!(err.to_string().contains("test"));

        let err = TunnelError::PeerNotFound;
        assert!(err.to_string().contains("not found"));

        let err = TunnelError::PermissionDenied("CAP_NET_ADMIN required".into());
        assert!(err.to_string().contains("CAP_NET_ADMIN"));
    }
}
