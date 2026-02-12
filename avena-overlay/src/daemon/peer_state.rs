//! In-memory bookkeeping for connected peers.

use crate::DeviceId;
use ed25519_dalek::VerifyingKey;
use std::net::{Ipv6Addr, SocketAddr};
use std::time::Instant;

/// Tracks metadata for a connected peer managed by the daemon.
#[derive(Debug)]
pub struct PeerState {
    pub device_id: DeviceId,
    pub public_key: VerifyingKey,
    pub wg_pubkey: [u8; 32],
    pub endpoint: Option<SocketAddr>,
    pub overlay_ip: Ipv6Addr,
    pub tunnel_interface: String,
    pub connected_at: Instant,
    pub last_seen: Instant,
}

impl PeerState {
    pub fn new(
        device_id: DeviceId,
        public_key: VerifyingKey,
        wg_pubkey: [u8; 32],
        overlay_ip: Ipv6Addr,
        tunnel_interface: String,
    ) -> Self {
        let now = Instant::now();
        Self {
            device_id,
            public_key,
            wg_pubkey,
            endpoint: None,
            overlay_ip,
            tunnel_interface,
            connected_at: now,
            last_seen: now,
        }
    }

    pub fn with_endpoint(mut self, endpoint: SocketAddr) -> Self {
        self.endpoint = Some(endpoint);
        self
    }

    pub fn update_last_seen(&mut self) {
        self.last_seen = Instant::now();
    }

    pub fn time_since_last_seen(&self) -> std::time::Duration {
        self.last_seen.elapsed()
    }
}
