//! Avena overlay networking primitives: device identity, discovery, handshakes,
//! and `WireGuard` tunnel management for the avenad daemon.
//!
//! The crate exposes small, composable modules so the daemon can:
//! - derive deterministic device identities and overlay addresses,
//! - discover peers (mDNS or static),
//! - perform authenticated handshakes that yield `WireGuard` keys, and
//! - configure kernel or userspace `WireGuard` tunnels.
//!
//! Most types are re-exported for ergonomic use by `avenad`.

pub mod address;
pub mod crypto;
pub mod daemon;
pub mod discovery;
pub mod identity;
pub mod routing;
pub mod tunnel;
pub mod wg;

pub use address::{NetworkConfig, NetworkConfigError};
pub use crypto::{
    create_self_signed_jwt, decode_jwt_unsafe, derive_session_keys, derive_wireguard_keypair,
    issue_jwt, wireguard_pubkey, CertClaims, CertError, CertValidator, EphemeralKeypair,
    HandshakeError, HandshakeMessage, SessionKeys, WireguardKeypair,
};
pub use discovery::{
    Capability, DiscoveredPeer, DiscoveryConfig, DiscoveryError, DiscoveryEvent,
    DiscoveryService, DiscoverySource, LocalAnnouncement, MdnsDiscovery, StaticPeerConfig,
    StaticPeers,
};
pub use identity::{derive_workload_keypair, DecodeError, DeviceId, DeviceKeypair};
pub use tunnel::{KernelBackend, PeerConfig, PeerStats, TunnelBackend, TunnelError, UserspaceBackend};
pub use daemon::{AvenadConfig, ConfigError, DiscoveryConfig as DaemonDiscoveryConfig, PeerState, RoutingConfig, TunnelMode};
