pub mod netlink;

use std::sync::Mutex;

use crate::wg::error::WgError;
use crate::wg::types::{Host, Key, Peer, PeerStats};

pub struct KernelBackend {
    ifname: Mutex<Option<String>>,
}

impl KernelBackend {
    pub fn new() -> Self {
        Self {
            ifname: Mutex::new(None),
        }
    }

    fn ifname(&self) -> Result<String, WgError> {
        let guard = self
            .ifname
            .lock()
            .map_err(|e| WgError::InterfaceNotFound(format!("lock poisoned: {}", e)))?;
        guard
            .clone()
            .ok_or_else(|| WgError::InterfaceNotFound("interface not initialized".into()))
    }

    pub fn create_interface(&self, name: &str) -> Result<(), WgError> {
        let mut guard = self
            .ifname
            .lock()
            .map_err(|e| WgError::InterfaceCreation(format!("lock poisoned: {}", e)))?;

        if let Some(ref existing) = *guard {
            if existing == name {
                return Ok(());
            }
            return Err(WgError::InterfaceCreation(
                "interface already exists with different name".into(),
            ));
        }

        netlink::create_interface(name)?;
        *guard = Some(name.to_string());
        Ok(())
    }

    pub fn remove_interface(&self) -> Result<(), WgError> {
        let ifname = self.ifname()?;
        netlink::delete_interface(&ifname)?;

        let mut guard = self
            .ifname
            .lock()
            .map_err(|e| WgError::InterfaceNotFound(format!("lock poisoned: {}", e)))?;
        *guard = None;
        Ok(())
    }

    pub fn read_host(&self) -> Result<Host, WgError> {
        let ifname = self.ifname()?;
        netlink::get_host(&ifname)
    }

    pub fn write_host(&self, host: &Host) -> Result<(), WgError> {
        let ifname = self.ifname()?;
        netlink::set_host(&ifname, host)
    }

    pub fn configure_peer(&self, peer: &Peer) -> Result<(), WgError> {
        let ifname = self.ifname()?;
        netlink::set_peer(&ifname, peer)
    }

    pub fn remove_peer(&self, pubkey: &Key) -> Result<(), WgError> {
        let ifname = self.ifname()?;
        netlink::delete_peer(&ifname, pubkey)
    }

    pub fn peer_stats(&self, pubkey: &Key) -> Result<PeerStats, WgError> {
        let host = self.read_host()?;
        host.peers
            .get(pubkey)
            .map(|peer| PeerStats {
                last_handshake: peer.last_handshake,
                rx_bytes: peer.rx_bytes,
                tx_bytes: peer.tx_bytes,
            })
            .ok_or(WgError::PeerNotFound)
    }

    pub fn listen_port(&self) -> Result<u16, WgError> {
        let host = self.read_host()?;
        Ok(host.listen_port)
    }
}

impl Default for KernelBackend {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backend_creation() {
        let backend = KernelBackend::new();
        assert!(backend.ifname.lock().unwrap().is_none());
    }

    #[test]
    fn backend_default() {
        let backend = KernelBackend::default();
        assert!(backend.ifname.lock().unwrap().is_none());
    }

    #[test]
    fn ifname_fails_without_interface() {
        let backend = KernelBackend::new();
        let result = backend.ifname();
        assert!(matches!(result, Err(WgError::InterfaceNotFound(_))));
    }

    #[test]
    fn read_host_fails_without_interface() {
        let backend = KernelBackend::new();
        let result = backend.read_host();
        assert!(matches!(result, Err(WgError::InterfaceNotFound(_))));
    }

    #[test]
    fn peer_stats_fails_without_interface() {
        let backend = KernelBackend::new();
        let key = Key::new([1u8; 32]);
        let result = backend.peer_stats(&key);
        assert!(matches!(result, Err(WgError::InterfaceNotFound(_))));
    }

    #[test]
    fn listen_port_fails_without_interface() {
        let backend = KernelBackend::new();
        let result = backend.listen_port();
        assert!(matches!(result, Err(WgError::InterfaceNotFound(_))));
    }
}
