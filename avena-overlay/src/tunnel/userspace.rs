//! Userspace WireGuard backend powered by wireguard-go.
//!
//! Implements the `TunnelBackend` trait using the vendored userspace
//! implementation when the kernel module is unavailable.

use crate::tunnel::backend::{PeerConfig, PeerStats, TunnelBackend, TunnelError};
use crate::tunnel::convert::peer_config_to_wg_peer;
use crate::wg::{self, Host, Key, Peer as WgPeer};
use async_trait::async_trait;
use std::net::SocketAddr;
use std::sync::Mutex;
use tokio::task::block_in_place;

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

#[async_trait]
impl TunnelBackend for UserspaceBackend {
    async fn ensure_interface(&self, name: &str) -> Result<(), TunnelError> {
        let name = name.to_string();
        block_in_place(|| {
            let mut wg_guard = self
                .wg
                .lock()
                .map_err(|e| TunnelError::Wireguard(format!("lock poisoned: {}", e)))?;
            let mut name_guard = self
                .interface_name
                .lock()
                .map_err(|e| TunnelError::Wireguard(format!("lock poisoned: {}", e)))?;

            if wg_guard.is_some() {
                if name_guard.as_deref() == Some(&name) {
                    return Ok(());
                }
                return Err(TunnelError::InterfaceCreation(
                    "interface already exists with different name".into(),
                ));
            }

            let backend = wg::UserspaceBackend::new();
            backend
                .create_interface(&name)
                .map_err(|e| TunnelError::InterfaceCreation(e.to_string()))?;

            *wg_guard = Some(backend);
            *name_guard = Some(name);
            Ok(())
        })
    }

    async fn set_private_key(&self, private_key: &[u8; 32]) -> Result<(), TunnelError> {
        let private_key = *private_key;
        block_in_place(|| {
            self.require_wg()?;
            let wg_guard = self
                .wg
                .lock()
                .map_err(|e| TunnelError::Wireguard(format!("lock poisoned: {}", e)))?;
            let wg = wg_guard.as_ref().unwrap();

            let current_host = wg.read_host()
                .map_err(|e| TunnelError::Wireguard(e.to_string()))?;

            let mut host = Host::default();
            host.private_key = Some(Key::new(private_key));
            host.listen_port = current_host.listen_port;

            wg.write_host(&host)
                .map_err(|e| TunnelError::Wireguard(e.to_string()))?;

            Ok(())
        })
    }

    async fn add_peer(&self, config: &PeerConfig) -> Result<(), TunnelError> {
        let config = config.clone();
        block_in_place(|| {
            self.require_wg()?;
            let wg_guard = self
                .wg
                .lock()
                .map_err(|e| TunnelError::Wireguard(format!("lock poisoned: {}", e)))?;
            let wg = wg_guard.as_ref().unwrap();

            let peer = peer_config_to_wg_peer(&config);
            wg.configure_peer(&peer)
                .map_err(|e| TunnelError::PeerOperation(e.to_string()))?;

            Ok(())
        })
    }

    async fn remove_peer(&self, pubkey: &[u8; 32]) -> Result<(), TunnelError> {
        let pubkey = *pubkey;
        block_in_place(|| {
            self.require_wg()?;
            let wg_guard = self
                .wg
                .lock()
                .map_err(|e| TunnelError::Wireguard(format!("lock poisoned: {}", e)))?;
            let wg = wg_guard.as_ref().unwrap();

            let key = Key::new(pubkey);
            wg.remove_peer(&key)
                .map_err(|e| TunnelError::PeerOperation(e.to_string()))?;

            Ok(())
        })
    }

    async fn update_endpoint(
        &self,
        pubkey: &[u8; 32],
        endpoint: SocketAddr,
    ) -> Result<(), TunnelError> {
        let pubkey = *pubkey;
        block_in_place(|| {
            self.require_wg()?;
            let wg_guard = self
                .wg
                .lock()
                .map_err(|e| TunnelError::Wireguard(format!("lock poisoned: {}", e)))?;
            let wg = wg_guard.as_ref().unwrap();

            let key = Key::new(pubkey);
            let mut peer = WgPeer::new(key);
            peer.endpoint = Some(endpoint);

            wg.configure_peer(&peer)
                .map_err(|e| TunnelError::PeerOperation(e.to_string()))?;

            Ok(())
        })
    }

    async fn peer_stats(&self, pubkey: &[u8; 32]) -> Result<PeerStats, TunnelError> {
        let pubkey = *pubkey;
        block_in_place(|| {
            self.require_wg()?;
            let wg_guard = self
                .wg
                .lock()
                .map_err(|e| TunnelError::Wireguard(format!("lock poisoned: {}", e)))?;
            let wg = wg_guard.as_ref().unwrap();

            let key = Key::new(pubkey);
            let stats = wg.peer_stats(&key).map_err(|e| match e {
                wg::WgError::PeerNotFound => TunnelError::PeerNotFound,
                other => TunnelError::Wireguard(other.to_string()),
            })?;

            Ok(PeerStats {
                last_handshake: stats.last_handshake,
                rx_bytes: stats.rx_bytes,
                tx_bytes: stats.tx_bytes,
            })
        })
    }

    async fn listen_port(&self) -> Result<u16, TunnelError> {
        block_in_place(|| {
            self.require_wg()?;
            let wg_guard = self
                .wg
                .lock()
                .map_err(|e| TunnelError::Wireguard(format!("lock poisoned: {}", e)))?;
            let wg = wg_guard.as_ref().unwrap();

            wg.listen_port()
                .map_err(|e| TunnelError::Wireguard(e.to_string()))
        })
    }

    async fn set_listen_port(&self, port: u16) -> Result<(), TunnelError> {
        block_in_place(|| {
            self.require_wg()?;
            let wg_guard = self
                .wg
                .lock()
                .map_err(|e| TunnelError::Wireguard(format!("lock poisoned: {}", e)))?;
            let wg = wg_guard.as_ref().unwrap();

            let current = wg
                .read_host()
                .map_err(|e| TunnelError::Wireguard(e.to_string()))?;
            let mut host = Host::default();
            host.listen_port = port;
            host.private_key = current.private_key;
            wg.write_host(&host)
                .map_err(|e| TunnelError::Wireguard(e.to_string()))?;
            Ok(())
        })
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

    #[tokio::test]
    async fn require_wg_fails_without_interface() {
        let backend = UserspaceBackend::new();
        let result = backend.require_wg();
        assert!(matches!(result, Err(TunnelError::InterfaceNotFound(_))));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn add_peer_fails_without_interface() {
        let backend = UserspaceBackend::new();
        let config = PeerConfig::new([1u8; 32]);
        let result = backend.add_peer(&config).await;
        assert!(matches!(result, Err(TunnelError::InterfaceNotFound(_))));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn remove_peer_fails_without_interface() {
        let backend = UserspaceBackend::new();
        let result = backend.remove_peer(&[1u8; 32]).await;
        assert!(matches!(result, Err(TunnelError::InterfaceNotFound(_))));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn update_endpoint_fails_without_interface() {
        let backend = UserspaceBackend::new();
        let endpoint: SocketAddr = "[::1]:51820".parse().unwrap();
        let result = backend.update_endpoint(&[1u8; 32], endpoint).await;
        assert!(matches!(result, Err(TunnelError::InterfaceNotFound(_))));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn peer_stats_fails_without_interface() {
        let backend = UserspaceBackend::new();
        let result = backend.peer_stats(&[1u8; 32]).await;
        assert!(matches!(result, Err(TunnelError::InterfaceNotFound(_))));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
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
    #[ignore = "requires CAP_NET_ADMIN and wireguard-go"]
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
    #[ignore = "requires CAP_NET_ADMIN and wireguard-go"]
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
    #[ignore = "requires CAP_NET_ADMIN and wireguard-go"]
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
    #[ignore = "requires CAP_NET_ADMIN and wireguard-go"]
    async fn idempotent_ensure_interface() {
        require_wireguard_go();

        let guard = InterfaceGuard::new();
        let backend = UserspaceBackend::new();

        backend.ensure_interface(guard.name()).await.expect("first create");
        let result = backend.ensure_interface(guard.name()).await;
        assert!(result.is_ok(), "Second ensure_interface should succeed");
    }
}
