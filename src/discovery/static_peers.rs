//! Static peer configuration and resolution.
//!
//! Converts user-specified endpoints into `DiscoveredPeer` records, optionally
//! tagging them with capabilities and pre-known device IDs.

use crate::DeviceId;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::net::{SocketAddr, ToSocketAddrs};
use tokio::task;
use tracing::{debug, warn};

use super::{Capability, DiscoveredPeer, DiscoverySource};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StaticPeerConfig {
    pub device_id: Option<DeviceId>,
    pub endpoint: String,
    #[serde(default)]
    pub capabilities: HashSet<Capability>,
}

impl StaticPeerConfig {
    pub fn new(endpoint: impl Into<String>) -> Self {
        Self {
            device_id: None,
            endpoint: endpoint.into(),
            capabilities: HashSet::new(),
        }
    }

    pub fn with_device_id(mut self, id: DeviceId) -> Self {
        self.device_id = Some(id);
        self
    }

    pub fn with_capabilities(mut self, caps: HashSet<Capability>) -> Self {
        self.capabilities = caps;
        self
    }

    pub fn with_capability(mut self, cap: Capability) -> Self {
        self.capabilities.insert(cap);
        self
    }

    async fn resolve(&self) -> Option<SocketAddr> {
        let endpoint = self.endpoint.clone();

        task::spawn_blocking(move || {
            endpoint
                .to_socket_addrs()
                .ok()
                .and_then(|mut addrs| addrs.next())
        })
        .await
        .ok()
        .flatten()
    }
}

#[derive(Debug)]
pub struct StaticPeers {
    peers: Vec<StaticPeerConfig>,
}

impl StaticPeers {
    pub fn from_config(peers: Vec<StaticPeerConfig>) -> Self {
        Self { peers }
    }

    pub async fn resolve(&self) -> Vec<DiscoveredPeer> {
        let mut discovered = Vec::with_capacity(self.peers.len());

        for peer_config in &self.peers {
            match peer_config.resolve().await {
                Some(endpoint) => {
                    if let Some(device_id) = peer_config.device_id {
                        debug!(
                            device_id = %device_id,
                            endpoint = %endpoint,
                            "resolved static peer"
                        );

                        discovered.push(DiscoveredPeer::new(
                            device_id,
                            endpoint,
                            peer_config.capabilities.clone(),
                            DiscoverySource::Static,
                        ));
                    } else {
                        debug!(
                            endpoint = %endpoint,
                            "resolved static peer without device_id (will need handshake to identify)"
                        );
                    }
                }
                None => {
                    warn!(
                        endpoint = %peer_config.endpoint,
                        "failed to resolve static peer endpoint"
                    );
                }
            }
        }

        discovered
    }

    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn static_peer_config_builder() {
        let mut caps = HashSet::new();
        caps.insert(Capability::Gateway);

        let config = StaticPeerConfig::new("gateway.example.com:51820")
            .with_device_id(DeviceId::from_bytes([1u8; 16]))
            .with_capabilities(caps);

        assert_eq!(config.endpoint, "gateway.example.com:51820");
        assert!(config.device_id.is_some());
        assert!(config.capabilities.contains(&Capability::Gateway));
    }

    #[test]
    fn static_peer_config_add_capability() {
        let config = StaticPeerConfig::new("192.168.1.1:51820")
            .with_capability(Capability::Relay)
            .with_capability(Capability::Gateway);

        assert!(config.capabilities.contains(&Capability::Relay));
        assert!(config.capabilities.contains(&Capability::Gateway));
        assert_eq!(config.capabilities.len(), 2);
    }

    #[tokio::test]
    async fn resolve_ip_endpoint() {
        let config = StaticPeerConfig::new("127.0.0.1:51820");
        let addr = config.resolve().await;

        assert!(addr.is_some());
        let addr = addr.unwrap();
        assert_eq!(addr.port(), 51820);
    }

    #[tokio::test]
    async fn resolve_invalid_endpoint() {
        let config = StaticPeerConfig::new("not-a-valid-endpoint");
        let addr = config.resolve().await;

        assert!(addr.is_none());
    }

    #[tokio::test]
    async fn static_peers_resolve() {
        let peers = StaticPeers::from_config(vec![
            StaticPeerConfig::new("127.0.0.1:51820")
                .with_device_id(DeviceId::from_bytes([1u8; 16])),
            StaticPeerConfig::new("127.0.0.1:51821")
                .with_device_id(DeviceId::from_bytes([2u8; 16])),
        ]);

        let discovered = peers.resolve().await;
        assert_eq!(discovered.len(), 2);

        assert_eq!(discovered[0].endpoint.port(), 51820);
        assert_eq!(discovered[1].endpoint.port(), 51821);
        assert!(matches!(discovered[0].source, DiscoverySource::Static));
    }

    #[tokio::test]
    async fn static_peers_without_device_id_not_included() {
        let peers = StaticPeers::from_config(vec![
            StaticPeerConfig::new("127.0.0.1:51820"),
        ]);

        let discovered = peers.resolve().await;
        assert_eq!(discovered.len(), 0);
    }
}
