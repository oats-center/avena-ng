//! Peer discovery across the overlay network.
//!
//! Supports static peer configuration and optional mDNS browsing/advertising.
//! Events are emitted over a broadcast channel so the daemon can react to
//! discovered or lost peers.

mod mdns;
mod static_peers;

pub use mdns::MdnsDiscovery;
pub use static_peers::{StaticPeerConfig, StaticPeers};

use crate::DeviceId;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::RwLock;
use std::time::Instant;
use thiserror::Error;
use tokio::sync::broadcast;

#[derive(Debug, Error)]
pub enum DiscoveryError {
    #[error("mDNS error: {0}")]
    Mdns(String),
    #[error("DNS resolution failed: {0}")]
    DnsResolution(#[from] std::io::Error),
    #[error("invalid peer configuration: {0}")]
    InvalidConfig(String),
    #[error("channel closed")]
    ChannelClosed,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Capability {
    Relay,
    WorkloadSpawn,
    DeviceIssue,
    Gateway,
}

impl Capability {
    pub fn as_str(&self) -> &'static str {
        match self {
            Capability::Relay => "relay",
            Capability::WorkloadSpawn => "workload-spawn",
            Capability::DeviceIssue => "device-issue",
            Capability::Gateway => "gateway",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "relay" => Some(Capability::Relay),
            "workload-spawn" => Some(Capability::WorkloadSpawn),
            "device-issue" => Some(Capability::DeviceIssue),
            "gateway" => Some(Capability::Gateway),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DiscoverySource {
    Mdns,
    Static,
    /// Reserved for mesh routing integration (Phase 5: Babel)
    Gossip,
}

#[derive(Clone, Debug)]
pub struct DiscoveredPeer {
    pub device_id: DeviceId,
    pub endpoint: SocketAddr,
    pub capabilities: HashSet<Capability>,
    pub source: DiscoverySource,
    pub discovered_at: Instant,
}

impl DiscoveredPeer {
    /// Create a record for a newly learned peer endpoint.
    pub fn new(
        device_id: DeviceId,
        endpoint: SocketAddr,
        capabilities: HashSet<Capability>,
        source: DiscoverySource,
    ) -> Self {
        Self {
            device_id,
            endpoint,
            capabilities,
            source,
            discovered_at: Instant::now(),
        }
    }

    pub fn has_capability(&self, cap: &Capability) -> bool {
        self.capabilities.contains(cap)
    }
}

#[derive(Clone, Debug)]
pub enum DiscoveryEvent {
    PeerDiscovered(DiscoveredPeer),
    PeerLost(DeviceId),
}

/// Announcement broadcast over discovery backends.
#[derive(Debug)]
pub struct LocalAnnouncement {
    pub device_id: DeviceId,
    pub wg_endpoint: SocketAddr,
    pub capabilities: HashSet<Capability>,
}

/// Runtime configuration for discovery backends.
#[derive(Debug)]
pub struct DiscoveryConfig {
    pub enable_mdns: bool,
    pub mdns_interface: Option<String>,
    pub static_peers: Vec<StaticPeerConfig>,
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self {
            enable_mdns: true,
            mdns_interface: None,
            static_peers: Vec::new(),
        }
    }
}

#[expect(missing_debug_implementations, reason = "contains broadcast channel")]
pub struct DiscoveryService {
    mdns: Option<MdnsDiscovery>,
    static_peers: StaticPeers,
    tx: broadcast::Sender<DiscoveryEvent>,
    discovered_peers: RwLock<HashMap<DeviceId, DiscoveredPeer>>,
}

impl DiscoveryService {
    /// Construct discovery service with configured static peers and optional mDNS.
    pub fn new(config: DiscoveryConfig) -> Result<Self, DiscoveryError> {
        let (tx, _) = broadcast::channel(64);

        let mdns = if config.enable_mdns {
            Some(MdnsDiscovery::new(config.mdns_interface.as_deref())?)
        } else {
            None
        };

        let static_peers = StaticPeers::from_config(config.static_peers);

        Ok(Self {
            mdns,
            static_peers,
            tx,
            discovered_peers: RwLock::new(HashMap::new()),
        })
    }

    pub fn subscribe(&self) -> broadcast::Receiver<DiscoveryEvent> {
        self.tx.subscribe()
    }

    /// Broadcast our endpoint to any discovery backends.
    pub async fn announce(&self, local: &LocalAnnouncement) -> Result<(), DiscoveryError> {
        if let Some(ref mdns) = self.mdns {
            mdns.advertise(local).await?;
        }
        Ok(())
    }

    pub async fn resolve_static_peers(&self) -> Vec<DiscoveredPeer> {
        self.static_peers.resolve().await
    }

    /// Start mDNS browsing in the background and forward events to subscribers.
    pub fn start_mdns_browse(&self) -> Result<(), DiscoveryError> {
        if let Some(ref mdns) = self.mdns {
            let mut rx = mdns.browse()?;
            let tx = self.tx.clone();

            tokio::spawn(async move {
                while let Some(peer) = rx.recv().await {
                    if tx.send(DiscoveryEvent::PeerDiscovered(peer)).is_err() {
                        break;
                    }
                }
            });
        }
        Ok(())
    }

    pub fn emit_event(&self, event: DiscoveryEvent) -> Result<(), DiscoveryError> {
        self.tx.send(event).map_err(|_| DiscoveryError::ChannelClosed)?;
        Ok(())
    }

    /// Access the mDNS helper when enabled.
    pub fn mdns(&self) -> Option<&MdnsDiscovery> {
        self.mdns.as_ref()
    }

    /// Get the most recently cached endpoint for a peer.
    pub fn get_discovered_endpoint(&self, device_id: &DeviceId) -> Option<SocketAddr> {
        self.discovered_peers
            .read()
            .ok()
            .and_then(|guard| guard.get(device_id).map(|p| p.endpoint))
    }

    /// Cache a peer record discovered through any channel.
    pub fn cache_discovered_peer(&self, peer: &DiscoveredPeer) {
        if let Ok(mut guard) = self.discovered_peers.write() {
            guard.insert(peer.device_id, peer.clone());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capability_roundtrip() {
        let caps = [
            Capability::Relay,
            Capability::WorkloadSpawn,
            Capability::DeviceIssue,
            Capability::Gateway,
        ];

        for cap in &caps {
            let s = cap.as_str();
            let parsed = Capability::from_str(s).expect("should parse");
            assert_eq!(&parsed, cap);
        }
    }

    #[test]
    fn capability_from_unknown_returns_none() {
        assert!(Capability::from_str("unknown").is_none());
    }

    #[test]
    fn discovered_peer_has_capability() {
        let mut caps = HashSet::new();
        caps.insert(Capability::Relay);
        caps.insert(Capability::Gateway);

        let peer = DiscoveredPeer::new(
            DeviceId::from_bytes([0u8; 16]),
            "127.0.0.1:51820".parse().unwrap(),
            caps,
            DiscoverySource::Static,
        );

        assert!(peer.has_capability(&Capability::Relay));
        assert!(peer.has_capability(&Capability::Gateway));
        assert!(!peer.has_capability(&Capability::WorkloadSpawn));
    }
}
