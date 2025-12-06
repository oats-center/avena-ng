//! Userspace WireGuard backend driven by the `wireguard-go` executable.
//!
//! Spawns wireguard-go, communicates over its Unix control socket, and maps the
//! API into the common backend types.

mod socket;

use std::fs;
use std::io::ErrorKind;
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::process::Command;
use std::sync::Mutex;
use std::thread;
use std::time::Duration;

use crate::wg::error::WgError;
use crate::wg::types::{Host, Key, Peer, PeerStats};
use crate::wg::uapi::parse_errno;

pub use socket::socket_path;

const WIREGUARD_GO_EXECUTABLE: &str = "wireguard-go";

#[derive(Debug)]
pub struct UserspaceBackend {
    ifname: Mutex<Option<String>>,
}

impl UserspaceBackend {
    pub fn new() -> Self {
        Self {
            ifname: Mutex::new(None),
        }
    }

    fn ifname(&self) -> Result<String, WgError> {
        let guard = self.ifname.lock().map_err(|e| {
            WgError::InterfaceNotFound(format!("lock poisoned: {}", e))
        })?;
        guard.clone().ok_or_else(|| {
            WgError::InterfaceNotFound("interface not initialized".into())
        })
    }

    fn connect(&self) -> Result<socket::WgSocket, WgError> {
        let ifname = self.ifname()?;
        socket::WgSocket::connect(&ifname).map_err(|e| {
            if e.kind() == ErrorKind::NotFound {
                WgError::InterfaceNotFound(format!("socket not found for {}", ifname))
            } else {
                WgError::SocketError(e.to_string())
            }
        })
    }

    pub fn create_interface(&self, name: &str) -> Result<(), WgError> {
        let mut guard = self.ifname.lock().map_err(|e| {
            WgError::InterfaceCreation(format!("lock poisoned: {}", e))
        })?;

        if let Some(ref existing) = *guard {
            if existing == name {
                return Ok(());
            }
            return Err(WgError::InterfaceCreation(
                "interface already exists with different name".into(),
            ));
        }

        let output = Command::new(WIREGUARD_GO_EXECUTABLE)
            .arg(name)
            .output()
            .map_err(|e| WgError::ProcessError(format!("failed to run wireguard-go: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(WgError::InterfaceCreation(format!(
                "wireguard-go failed: {}",
                stderr
            )));
        }

        let sock_path = socket_path(name);
        for _ in 0..50 {
            if sock_path.exists() {
                *guard = Some(name.to_string());
                return Ok(());
            }
            thread::sleep(Duration::from_millis(20));
        }

        Err(WgError::InterfaceCreation(format!(
            "wireguard-go started but socket {} not created",
            sock_path.display()
        )))
    }

    pub fn remove_interface(&self) -> Result<(), WgError> {
        let ifname = self.ifname()?;
        let path = socket_path(&ifname);

        match UnixStream::connect(&path) {
            Ok(socket) => {
                let _ = socket.shutdown(Shutdown::Both);
                let _ = fs::remove_file(&path);
            }
            Err(e) if e.kind() == ErrorKind::NotFound => {}
            Err(e) => {
                return Err(WgError::SocketError(format!(
                    "failed to connect to socket: {}",
                    e
                )));
            }
        }

        let mut guard = self.ifname.lock().map_err(|e| {
            WgError::InterfaceNotFound(format!("lock poisoned: {}", e))
        })?;
        *guard = None;

        Ok(())
    }

    pub fn read_host(&self) -> Result<Host, WgError> {
        let mut socket = self.connect()?;
        socket.send(b"get=1\n\n")?;
        Host::parse_uapi(socket.into_reader())
    }

    pub fn write_host(&self, host: &Host) -> Result<(), WgError> {
        let mut socket = self.connect()?;
        socket.send(b"set=1\n")?;
        socket.send(host.as_uapi().as_bytes())?;
        socket.send(b"\n")?;

        let errno = parse_errno(socket.into_reader());
        if errno == 0 {
            Ok(())
        } else {
            Err(WgError::UapiError(format!("write failed with errno={}", errno)))
        }
    }

    pub fn configure_peer(&self, peer: &Peer) -> Result<(), WgError> {
        let mut socket = self.connect()?;
        socket.send(b"set=1\n")?;
        socket.send(peer.as_uapi_update().as_bytes())?;
        socket.send(b"\n")?;

        let errno = parse_errno(socket.into_reader());
        if errno == 0 {
            Ok(())
        } else {
            Err(WgError::UapiError(format!(
                "configure_peer failed with errno={}",
                errno
            )))
        }
    }

    pub fn remove_peer(&self, pubkey: &Key) -> Result<(), WgError> {
        let peer = Peer::new(pubkey.clone());
        let mut socket = self.connect()?;
        socket.send(b"set=1\n")?;
        socket.send(peer.as_uapi_remove().as_bytes())?;
        socket.send(b"\n")?;

        let errno = parse_errno(socket.into_reader());
        if errno == 0 {
            Ok(())
        } else {
            Err(WgError::UapiError(format!(
                "remove_peer failed with errno={}",
                errno
            )))
        }
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

impl Default for UserspaceBackend {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backend_creation() {
        let backend = UserspaceBackend::new();
        assert!(backend.ifname.lock().unwrap().is_none());
    }

    #[test]
    fn backend_default() {
        let backend = UserspaceBackend::default();
        assert!(backend.ifname.lock().unwrap().is_none());
    }

    #[test]
    fn ifname_fails_without_interface() {
        let backend = UserspaceBackend::new();
        let result = backend.ifname();
        assert!(matches!(result, Err(WgError::InterfaceNotFound(_))));
    }

    #[test]
    fn connect_fails_without_interface() {
        let backend = UserspaceBackend::new();
        let result = backend.connect();
        assert!(matches!(result, Err(WgError::InterfaceNotFound(_))));
    }

    #[test]
    fn read_host_fails_without_interface() {
        let backend = UserspaceBackend::new();
        let result = backend.read_host();
        assert!(matches!(result, Err(WgError::InterfaceNotFound(_))));
    }

    #[test]
    fn peer_stats_fails_without_interface() {
        let backend = UserspaceBackend::new();
        let key = Key::new([1u8; 32]);
        let result = backend.peer_stats(&key);
        assert!(matches!(result, Err(WgError::InterfaceNotFound(_))));
    }

    #[test]
    fn listen_port_fails_without_interface() {
        let backend = UserspaceBackend::new();
        let result = backend.listen_port();
        assert!(matches!(result, Err(WgError::InterfaceNotFound(_))));
    }
}
