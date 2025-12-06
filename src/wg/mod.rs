//! Thin wrappers around WireGuard kernel and userspace backends.
//!
//! The public surface exposes common types (keys, peers, stats) and selects the
//! kernel backend on Linux when available, otherwise falling back to userspace.

pub mod error;
pub mod types;
pub mod uapi;
pub mod userspace;

#[cfg(target_os = "linux")]
pub mod linux;

pub use error::WgError;
pub use types::{Host, IpAddrMask, Key, Peer, PeerStats};
pub use userspace::UserspaceBackend;

#[cfg(target_os = "linux")]
pub use linux::KernelBackend;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_types_available() {
        let _ = WgError::PeerNotFound;
        let _ = Key::new([0u8; 32]);
        let _ = Host::default();
        let _ = Peer::default();
        let _ = PeerStats::default();
    }

    #[test]
    fn userspace_backend_available() {
        let _ = UserspaceBackend::new();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn kernel_backend_available() {
        let _ = KernelBackend::new();
    }
}
