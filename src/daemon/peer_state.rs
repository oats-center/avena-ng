use crate::DeviceId;
use ed25519_dalek::VerifyingKey;
use std::net::{Ipv6Addr, SocketAddr};
use std::time::Instant;

#[derive(Debug)]
pub struct PeerState {
    pub device_id: DeviceId,
    pub public_key: VerifyingKey,
    pub wg_pubkey: [u8; 32],
    pub endpoint: Option<SocketAddr>,
    pub overlay_ip: Ipv6Addr,
    pub connected_at: Instant,
    pub last_seen: Instant,
}

impl PeerState {
    pub fn new(
        device_id: DeviceId,
        public_key: VerifyingKey,
        wg_pubkey: [u8; 32],
        overlay_ip: Ipv6Addr,
    ) -> Self {
        let now = Instant::now();
        Self {
            device_id,
            public_key,
            wg_pubkey,
            endpoint: None,
            overlay_ip,
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
