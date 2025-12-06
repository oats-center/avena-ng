//! Userspace WireGuard backend powered by wireguard-go.
//!
//! Implements the `TunnelBackend` trait using the vendored userspace
//! implementation when the kernel module is unavailable.

use crate::tunnel::backend::{PeerConfig, PeerStats, TunnelBackend, TunnelError};
use crate::wg::{self, Host, IpAddrMask, Key, Peer as WgPeer};
use async_trait::async_trait;
use std::net::SocketAddr;
use std::sync::Mutex;

#[derive(Debug)]
pub struct UserspaceBackend {
    wg: Mutex<Option<wg::UserspaceBackend>>,
    interface_name: Mutex<Option<String>>,
}

impl UserspaceBackend {
    pub fn new() -> Self {
        Self {
            wg: Mutex::new(None),
            interface_name: Mutex::new(None),
        }
    }

    fn require_wg(&self) -> Result<(), TunnelError> {
        let guard = self
            .wg
            .lock()
            .map_err(|e| TunnelError::Wireguard(format!("lock poisoned: {}", e)))?;
        if guard.is_none() {
            return Err(TunnelError::InterfaceNotFound(
                "interface not initialized".into(),
            ));
        }
        Ok(())
    }
}

impl Default for UserspaceBackend {
    fn default() -> Self {
        Self::new()
    }
}

fn convert_peer_config(config: &PeerConfig) -> WgPeer {
    let pubkey = Key::new(config.wireguard_pubkey);
    let mut peer = WgPeer::new(pubkey);

    if let Some(psk) = &config.psk {
        peer.preshared_key = Some(Key::new(*psk));
    }

    if let Some(endpoint) = config.endpoint {
        peer.endpoint = Some(endpoint);
    }

    if let Some(keepalive) = config.persistent_keepalive {
        peer.persistent_keepalive_interval = Some(keepalive);
    }

    for ip in &config.allowed_ips {
        peer.allowed_ips.push(IpAddrMask::new(ip.addr(), ip.prefix_len()));
    }

    peer
}

#[async_trait]
impl TunnelBackend for UserspaceBackend {
    async fn ensure_interface(&self, name: &str) -> Result<(), TunnelError> {
        let mut wg_guard = self
            .wg
            .lock()
            .map_err(|e| TunnelError::Wireguard(format!("lock poisoned: {}", e)))?;
        let mut name_guard = self
            .interface_name
            .lock()
            .map_err(|e| TunnelError::Wireguard(format!("lock poisoned: {}", e)))?;

        if wg_guard.is_some() {
            if name_guard.as_deref() == Some(name) {
                return Ok(());
            }
            return Err(TunnelError::InterfaceCreation(
                "interface already exists with different name".into(),
            ));
        }

        let backend = wg::UserspaceBackend::new();
        backend
            .create_interface(name)
            .map_err(|e| TunnelError::InterfaceCreation(e.to_string()))?;

        *wg_guard = Some(backend);
        *name_guard = Some(name.to_string());
        Ok(())
    }

    async fn set_private_key(&self, private_key: &[u8; 32]) -> Result<(), TunnelError> {
        self.require_wg()?;
        let wg_guard = self
            .wg
            .lock()
            .map_err(|e| TunnelError::Wireguard(format!("lock poisoned: {}", e)))?;
        let wg = wg_guard.as_ref().unwrap();

        let current_host = wg.read_host()
            .map_err(|e| TunnelError::Wireguard(e.to_string()))?;

        let mut host = Host::default();
        host.private_key = Some(Key::new(*private_key));
        host.listen_port = current_host.listen_port;

        wg.write_host(&host)
            .map_err(|e| TunnelError::Wireguard(e.to_string()))?;

        Ok(())
    }

    async fn add_peer(&self, config: &PeerConfig) -> Result<(), TunnelError> {
        self.require_wg()?;
        let wg_guard = self
            .wg
            .lock()
            .map_err(|e| TunnelError::Wireguard(format!("lock poisoned: {}", e)))?;
        let wg = wg_guard.as_ref().unwrap();

        let peer = convert_peer_config(config);
        wg.configure_peer(&peer)
            .map_err(|e| TunnelError::PeerOperation(e.to_string()))?;

        Ok(())
    }

    async fn remove_peer(&self, pubkey: &[u8; 32]) -> Result<(), TunnelError> {
        self.require_wg()?;
        let wg_guard = self
            .wg
            .lock()
            .map_err(|e| TunnelError::Wireguard(format!("lock poisoned: {}", e)))?;
        let wg = wg_guard.as_ref().unwrap();

        let key = Key::new(*pubkey);
        wg.remove_peer(&key)
            .map_err(|e| TunnelError::PeerOperation(e.to_string()))?;

        Ok(())
    }

    async fn update_endpoint(
        &self,
        pubkey: &[u8; 32],
        endpoint: SocketAddr,
    ) -> Result<(), TunnelError> {
        self.require_wg()?;
        let wg_guard = self
            .wg
            .lock()
            .map_err(|e| TunnelError::Wireguard(format!("lock poisoned: {}", e)))?;
        let wg = wg_guard.as_ref().unwrap();

        let key = Key::new(*pubkey);
        let mut peer = WgPeer::new(key);
        peer.endpoint = Some(endpoint);

        wg.configure_peer(&peer)
            .map_err(|e| TunnelError::PeerOperation(e.to_string()))?;

        Ok(())
    }

    async fn peer_stats(&self, pubkey: &[u8; 32]) -> Result<PeerStats, TunnelError> {
        self.require_wg()?;
        let wg_guard = self
            .wg
            .lock()
            .map_err(|e| TunnelError::Wireguard(format!("lock poisoned: {}", e)))?;
        let wg = wg_guard.as_ref().unwrap();

        let key = Key::new(*pubkey);
        let stats = wg.peer_stats(&key).map_err(|e| match e {
            wg::WgError::PeerNotFound => TunnelError::PeerNotFound,
            other => TunnelError::Wireguard(other.to_string()),
        })?;

        Ok(PeerStats {
            last_handshake: stats.last_handshake,
            rx_bytes: stats.rx_bytes,
            tx_bytes: stats.tx_bytes,
        })
    }

    async fn listen_port(&self) -> Result<u16, TunnelError> {
        self.require_wg()?;
        let wg_guard = self
            .wg
            .lock()
            .map_err(|e| TunnelError::Wireguard(format!("lock poisoned: {}", e)))?;
        let wg = wg_guard.as_ref().unwrap();

        wg.listen_port()
            .map_err(|e| TunnelError::Wireguard(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn userspace_backend_creation() {
        let backend = UserspaceBackend::new();
        assert!(backend.wg.lock().unwrap().is_none());
        assert!(backend.interface_name.lock().unwrap().is_none());
    }

    #[test]
    fn userspace_backend_default() {
        let backend = UserspaceBackend::default();
        assert!(backend.wg.lock().unwrap().is_none());
    }

    #[test]
    fn convert_peer_config_minimal() {
        let pubkey = [42u8; 32];
        let config = PeerConfig::new(pubkey);
        let peer = convert_peer_config(&config);

        assert_eq!(peer.public_key.as_array(), pubkey);
        assert!(peer.preshared_key.is_none());
        assert!(peer.endpoint.is_none());
        assert!(peer.persistent_keepalive_interval.is_none());
        assert!(peer.allowed_ips.is_empty());
    }

    #[test]
    fn convert_peer_config_full() {
        let pubkey = [42u8; 32];
        let psk = [99u8; 32];
        let endpoint: SocketAddr = "[::1]:51820".parse().unwrap();
        let allowed: ipnet::IpNet = "fd00::/64".parse().unwrap();

        let config = PeerConfig::new(pubkey)
            .with_psk(psk)
            .with_endpoint(endpoint)
            .with_allowed_ips(vec![allowed])
            .with_keepalive(25);

        let peer = convert_peer_config(&config);

        assert_eq!(peer.public_key.as_array(), pubkey);
        assert_eq!(peer.preshared_key.as_ref().unwrap().as_array(), psk);
        assert_eq!(peer.endpoint, Some(endpoint));
        assert_eq!(peer.persistent_keepalive_interval, Some(25));
        assert_eq!(peer.allowed_ips.len(), 1);
    }

    #[tokio::test]
    async fn require_wg_fails_without_interface() {
        let backend = UserspaceBackend::new();
        let result = backend.require_wg();
        assert!(matches!(result, Err(TunnelError::InterfaceNotFound(_))));
    }

    #[tokio::test]
    async fn add_peer_fails_without_interface() {
        let backend = UserspaceBackend::new();
        let config = PeerConfig::new([1u8; 32]);
        let result = backend.add_peer(&config).await;
        assert!(matches!(result, Err(TunnelError::InterfaceNotFound(_))));
    }

    #[tokio::test]
    async fn remove_peer_fails_without_interface() {
        let backend = UserspaceBackend::new();
        let result = backend.remove_peer(&[1u8; 32]).await;
        assert!(matches!(result, Err(TunnelError::InterfaceNotFound(_))));
    }

    #[tokio::test]
    async fn update_endpoint_fails_without_interface() {
        let backend = UserspaceBackend::new();
        let endpoint: SocketAddr = "[::1]:51820".parse().unwrap();
        let result = backend.update_endpoint(&[1u8; 32], endpoint).await;
        assert!(matches!(result, Err(TunnelError::InterfaceNotFound(_))));
    }

    #[tokio::test]
    async fn peer_stats_fails_without_interface() {
        let backend = UserspaceBackend::new();
        let result = backend.peer_stats(&[1u8; 32]).await;
        assert!(matches!(result, Err(TunnelError::InterfaceNotFound(_))));
    }

    #[tokio::test]
    async fn listen_port_fails_without_interface() {
        let backend = UserspaceBackend::new();
        let result = backend.listen_port().await;
        assert!(matches!(result, Err(TunnelError::InterfaceNotFound(_))));
    }

    struct InterfaceGuard(String);

    impl InterfaceGuard {
        fn new() -> Self {
            use std::time::{SystemTime, UNIX_EPOCH};
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .subsec_nanos();
            Self(format!("av{:x}", nanos % 0xFFFF))
        }

        fn name(&self) -> &str {
            &self.0
        }
    }

    impl Drop for InterfaceGuard {
        fn drop(&mut self) {
            let _ = std::process::Command::new("sudo")
                .args(["ip", "link", "delete", &self.0])
                .output();
            let sock = format!("/var/run/wireguard/{}.sock", self.0);
            let _ = std::fs::remove_file(&sock);
        }
    }

    fn require_wireguard_go() {
        let result = std::process::Command::new("wireguard-go")
            .arg("--version")
            .output();
        assert!(
            result.is_ok(),
            "wireguard-go not installed. Install with: go install golang.zx2c4.com/wireguard-go@latest"
        );
    }

    #[tokio::test]
    #[ignore]
    async fn create_userspace_interface() {
        require_wireguard_go();

        let guard = InterfaceGuard::new();
        let backend = UserspaceBackend::new();

        let result = backend.ensure_interface(guard.name()).await;
        assert!(result.is_ok(), "Failed to create interface: {:?}", result);

        let port = backend.listen_port().await;
        assert!(port.is_ok(), "Failed to get listen port: {:?}", port);
    }

    #[tokio::test]
    #[ignore]
    async fn add_and_query_peer_userspace() {
        require_wireguard_go();

        let guard = InterfaceGuard::new();
        let backend = UserspaceBackend::new();

        backend.ensure_interface(guard.name()).await.expect("create interface");

        let pubkey = [42u8; 32];
        let config = PeerConfig::new(pubkey)
            .with_allowed_ips(vec!["fd00::1/128".parse().unwrap()]);

        let result = backend.add_peer(&config).await;
        assert!(result.is_ok(), "Failed to add peer: {:?}", result);

        let stats = backend.peer_stats(&pubkey).await;
        assert!(stats.is_ok(), "Failed to get peer stats: {:?}", stats);
        assert_eq!(stats.unwrap().rx_bytes, 0);
    }

    #[tokio::test]
    #[ignore]
    async fn remove_peer_userspace() {
        require_wireguard_go();

        let guard = InterfaceGuard::new();
        let backend = UserspaceBackend::new();

        backend.ensure_interface(guard.name()).await.expect("create interface");

        let pubkey = [42u8; 32];
        let config = PeerConfig::new(pubkey);

        backend.add_peer(&config).await.expect("add peer");
        let result = backend.remove_peer(&pubkey).await;
        assert!(result.is_ok(), "Failed to remove peer: {:?}", result);

        let stats = backend.peer_stats(&pubkey).await;
        assert!(matches!(stats, Err(TunnelError::PeerNotFound)));
    }

    #[tokio::test]
    #[ignore]
    async fn idempotent_ensure_interface() {
        require_wireguard_go();

        let guard = InterfaceGuard::new();
        let backend = UserspaceBackend::new();

        backend.ensure_interface(guard.name()).await.expect("first create");
        let result = backend.ensure_interface(guard.name()).await;
        assert!(result.is_ok(), "Second ensure_interface should succeed");
    }
}
