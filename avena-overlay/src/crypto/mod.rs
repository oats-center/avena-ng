//! Cryptographic helpers for overlay handshakes and certificates.
//!
//! Exposes handshake key derivation plus lightweight certificate utilities used
//! to authenticate devices and workloads.

pub mod certs;
pub mod handshake;

pub use certs::{
    create_self_signed_jwt, decode_jwt_unsafe, issue_jwt, CertClaims, CertError, CertValidator,
};
pub use handshake::{
    derive_session_keys, derive_wireguard_keypair, wireguard_pubkey, EphemeralKeypair,
    HandshakeError, HandshakeMessage, SessionKeys, WireguardKeypair,
};
