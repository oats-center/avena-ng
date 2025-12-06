pub mod address;
pub mod crypto;
pub mod daemon;
pub mod discovery;
pub mod identity;
pub mod tunnel;
pub mod wg;

pub use address::NetworkConfig;
pub use crypto::{
    derive_session_keys, derive_wireguard_keypair, wireguard_pubkey, CertError, Certificate,
    CertificateChain, CertValidator, EphemeralKeypair, HandshakeError, HandshakeMessage,
    SessionKeys, WireguardKeypair,
};
pub use discovery::{
    Capability, DiscoveredPeer, DiscoveryConfig, DiscoveryError, DiscoveryEvent,
    DiscoveryService, DiscoverySource, LocalAnnouncement, MdnsDiscovery, StaticPeerConfig,
    StaticPeers,
};
pub use identity::{derive_workload_keypair, DecodeError, DeviceId, DeviceKeypair};
pub use tunnel::{KernelBackend, PeerConfig, PeerStats, TunnelBackend, TunnelError, UserspaceBackend};
pub use daemon::{AvenadConfig, PeerState, TunnelMode};
