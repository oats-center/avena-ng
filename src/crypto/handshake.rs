//! Handshake primitives for establishing per-peer WireGuard state.
//!
//! Each device holds a long-lived Ed25519 identity and a deterministic WireGuard
//! keypair derived from it. During a TCP-based handshake, peers exchange an
//! ephemeral X25519 key, advertise their stable WireGuard public key, and sign
//! the bundle so the receiver can authenticate the peer and learn which
//! interface key to configure. Per-connection WireGuard PSKs are derived from
//! the ephemeral Diffie-Hellman to keep traffic separation at the peer level.

use crate::crypto::certs::{CertError, CertValidator, CertificateChain};
use crate::identity::{DeviceId, DeviceKeypair};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, Bytes};
use sha2::Sha256;
use thiserror::Error;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zeroize::Zeroizing;

const HANDSHAKE_TIMESTAMP_VALIDITY_SECS: u64 = 60;

#[derive(Error, Debug)]
pub enum HandshakeError {
    #[error("signature verification failed")]
    InvalidSignature,
    #[error("peer ID mismatch: expected {expected}, got {actual}")]
    PeerIdMismatch { expected: DeviceId, actual: DeviceId },
    #[error("message expired: timestamp {timestamp_secs}s, now {now_secs}s")]
    Expired { timestamp_secs: u64, now_secs: u64 },
    #[error("message from the future: timestamp {timestamp_secs}s, now {now_secs}s")]
    FutureTimestamp { timestamp_secs: u64, now_secs: u64 },
    #[error("certificate validation failed: {0}")]
    CertificateInvalid(#[from] CertError),
}

/// Short-lived X25519 key used to derive session secrets during a handshake.
#[expect(missing_debug_implementations, reason = "contains secret key material")]
pub struct EphemeralKeypair {
    secret: StaticSecret,
    public: X25519PublicKey,
}

impl EphemeralKeypair {
    /// Generate a fresh ephemeral keypair for a single handshake.
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = X25519PublicKey::from(&secret);
        Self { secret, public }
    }

    /// Deterministic constructor used in tests.
    pub fn from_seed(seed: [u8; 32]) -> Self {
        let secret = StaticSecret::from(seed);
        let public = X25519PublicKey::from(&secret);
        Self { secret, public }
    }

    pub fn public_key(&self) -> &X25519PublicKey {
        &self.public
    }

    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.public.to_bytes()
    }

    pub(crate) fn diffie_hellman(&self, peer_public: &X25519PublicKey) -> [u8; 32] {
        self.secret.diffie_hellman(peer_public).to_bytes()
    }
}

/// Payload exchanged during the TCP handshake that bootstraps a WireGuard peer.
#[serde_as]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HandshakeMessage {
    /// Ephemeral X25519 public key for Diffie-Hellman.
    #[serde_as(as = "Bytes")]
    pub ephemeral_pubkey: [u8; 32],
    /// Random nonce to mix into the signed payload.
    #[serde_as(as = "Bytes")]
    pub nonce: [u8; 32],
    /// Unix timestamp (seconds) for replay protection.
    pub timestamp_secs: u64,
    /// WireGuard interface public key this node will use.
    #[serde_as(as = "Bytes")]
    pub wg_pubkey: [u8; 32],
    /// Signature over (ephemeral_pubkey || nonce || timestamp || peer_id || wg_pubkey).
    #[serde_as(as = "Bytes")]
    pub signature: [u8; 64],
    /// Certificate chain proving the sender is authorized by a trusted root.
    pub cert_chain: CertificateChain,
}

impl HandshakeMessage {
    /// Build a signed handshake payload advertising our ephemeral and WireGuard keys.
    pub fn create(
        device: &DeviceKeypair,
        ephemeral: &EphemeralKeypair,
        peer_id: &DeviceId,
        wg_pubkey: [u8; 32],
        cert_chain: &CertificateChain,
    ) -> Self {
        let mut nonce = [0u8; 32];
        rand::RngCore::fill_bytes(&mut OsRng, &mut nonce);

        let timestamp_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time before unix epoch")
            .as_secs();

        let ephemeral_pubkey = ephemeral.public_key_bytes();

        let mut message_to_sign = Vec::with_capacity(32 + 32 + 8 + 16 + 32);
        message_to_sign.extend_from_slice(&ephemeral_pubkey);
        message_to_sign.extend_from_slice(&nonce);
        message_to_sign.extend_from_slice(&timestamp_secs.to_le_bytes());
        message_to_sign.extend_from_slice(peer_id.as_bytes());
        message_to_sign.extend_from_slice(&wg_pubkey);

        let signature = device.sign(&message_to_sign);

        Self {
            ephemeral_pubkey,
            nonce,
            timestamp_secs,
            wg_pubkey,
            signature: signature.to_bytes(),
            cert_chain: cert_chain.clone(),
        }
    }

    /// Verify the handshake signature, timestamp, and certificate chain.
    pub fn verify(
        &self,
        peer_pubkey: &VerifyingKey,
        local_id: &DeviceId,
        cert_validator: &CertValidator,
    ) -> Result<(), HandshakeError> {
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time before unix epoch")
            .as_secs();

        if self.timestamp_secs > now_secs + HANDSHAKE_TIMESTAMP_VALIDITY_SECS {
            return Err(HandshakeError::FutureTimestamp {
                timestamp_secs: self.timestamp_secs,
                now_secs,
            });
        }

        if now_secs > self.timestamp_secs + HANDSHAKE_TIMESTAMP_VALIDITY_SECS {
            return Err(HandshakeError::Expired {
                timestamp_secs: self.timestamp_secs,
                now_secs,
            });
        }

        let mut message_to_verify = Vec::with_capacity(32 + 32 + 8 + 16 + 32);
        message_to_verify.extend_from_slice(&self.ephemeral_pubkey);
        message_to_verify.extend_from_slice(&self.nonce);
        message_to_verify.extend_from_slice(&self.timestamp_secs.to_le_bytes());
        message_to_verify.extend_from_slice(local_id.as_bytes());
        message_to_verify.extend_from_slice(&self.wg_pubkey);

        let signature = Signature::from_bytes(&self.signature);
        peer_pubkey
            .verify(&message_to_verify, &signature)
            .map_err(|_| HandshakeError::InvalidSignature)?;

        let peer_device_id = DeviceId::from_public_key(peer_pubkey);
        cert_validator.validate_chain_for_device(&self.cert_chain, &peer_device_id)?;

        Ok(())
    }

    pub fn ephemeral_public_key(&self) -> X25519PublicKey {
        X25519PublicKey::from(self.ephemeral_pubkey)
    }
}

/// WireGuard key material derived for a single peer connection.
///
/// The PSK matches on both ends so traffic is protected even if peers share
/// the same long-lived interface key across sessions.
#[derive(Clone)]
#[expect(missing_debug_implementations, reason = "contains secret key material")]
pub struct SessionKeys {
    pub wireguard_psk: Zeroizing<[u8; 32]>,
}

/// Stable WireGuard key material derived from a device identity.
#[derive(Clone)]
#[expect(missing_debug_implementations, reason = "contains secret key material")]
pub struct WireguardKeypair {
    pub private: Zeroizing<[u8; 32]>,
    pub public: [u8; 32],
}

const SESSION_KEY_SALT: &[u8] = b"avena-session-keys-v1";
const WG_PSK_INFO: &[u8] = b"wireguard-psk";
const WG_DEVICE_KEY_SALT: &[u8] = b"avena-wireguard-device-key-v1";
const WG_DEVICE_KEY_INFO: &[u8] = b"wireguard-interface";

/// Compute the WireGuard public key for a given private key.
pub fn wireguard_pubkey(private_key: &[u8; 32]) -> [u8; 32] {
    X25519PublicKey::from(&StaticSecret::from(*private_key)).to_bytes()
}

/// Derive a deterministic WireGuard keypair from the device's Ed25519 identity.
///
/// This keeps the interface key stable across peer connections so multiple
/// tunnels can coexist without clobbering one another.
pub fn derive_wireguard_keypair(device: &DeviceKeypair) -> WireguardKeypair {
    let hkdf = Hkdf::<Sha256>::new(Some(WG_DEVICE_KEY_SALT), &*device.to_bytes());

    let mut private = [0u8; 32];
    hkdf.expand(WG_DEVICE_KEY_INFO, &mut private)
        .expect("32 bytes is valid for HKDF-SHA256");
    let public = wireguard_pubkey(&private);

    WireguardKeypair {
        private: Zeroizing::new(private),
        public,
    }
}

/// Derive per-connection WireGuard PSK from the shared ephemeral secret.
pub fn derive_session_keys(
    local_ephemeral: &EphemeralKeypair,
    peer_ephemeral: &X25519PublicKey,
) -> SessionKeys {
    let shared_secret = local_ephemeral.diffie_hellman(peer_ephemeral);
    let hkdf = Hkdf::<Sha256>::new(Some(SESSION_KEY_SALT), &shared_secret);

    let mut wg_psk = [0u8; 32];
    hkdf.expand(WG_PSK_INFO, &mut wg_psk)
        .expect("32 bytes is valid for HKDF-SHA256");

    SessionKeys {
        wireguard_psk: Zeroizing::new(wg_psk),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::certs::Certificate;

    fn create_test_ca() -> (DeviceKeypair, Certificate) {
        let ca = DeviceKeypair::from_seed(&[1u8; 32]);
        let cert = Certificate::new_self_signed(&ca, 365);
        (ca, cert)
    }

    fn create_device_chain(
        ca: &DeviceKeypair,
        root_cert: &Certificate,
        device: &DeviceKeypair,
    ) -> CertificateChain {
        let cert = Certificate::issue(ca, device.device_id(), device.public_key(), 365);
        CertificateChain::with_intermediates(cert, vec![root_cert.clone()])
    }

    #[test]
    fn test_ephemeral_keypair_generation() {
        let kp1 = EphemeralKeypair::generate();
        let kp2 = EphemeralKeypair::generate();

        assert_ne!(kp1.public_key_bytes(), kp2.public_key_bytes());
    }

    #[test]
    fn test_handshake_message_create_and_verify() {
        let (ca, root_cert) = create_test_ca();
        let validator = CertValidator::new(root_cert.clone());

        let alice_device = DeviceKeypair::generate();
        let bob_device = DeviceKeypair::generate();
        let alice_wg = derive_wireguard_keypair(&alice_device);
        let alice_chain = create_device_chain(&ca, &root_cert, &alice_device);

        let alice_ephemeral = EphemeralKeypair::generate();
        let bob_id = bob_device.device_id();

        let message = HandshakeMessage::create(
            &alice_device,
            &alice_ephemeral,
            &bob_id,
            alice_wg.public,
            &alice_chain,
        );

        assert!(message
            .verify(&alice_device.public_key(), &bob_id, &validator)
            .is_ok());
    }

    #[test]
    fn test_handshake_message_fails_wrong_peer() {
        let (ca, root_cert) = create_test_ca();
        let validator = CertValidator::new(root_cert.clone());

        let alice_device = DeviceKeypair::generate();
        let bob_device = DeviceKeypair::generate();
        let charlie_device = DeviceKeypair::generate();
        let alice_wg = derive_wireguard_keypair(&alice_device);
        let alice_chain = create_device_chain(&ca, &root_cert, &alice_device);

        let alice_ephemeral = EphemeralKeypair::generate();
        let bob_id = bob_device.device_id();
        let charlie_id = charlie_device.device_id();

        let message = HandshakeMessage::create(
            &alice_device,
            &alice_ephemeral,
            &bob_id,
            alice_wg.public,
            &alice_chain,
        );

        assert!(message
            .verify(&alice_device.public_key(), &charlie_id, &validator)
            .is_err());
    }

    #[test]
    fn test_handshake_message_fails_wrong_signer() {
        let (ca, root_cert) = create_test_ca();
        let validator = CertValidator::new(root_cert.clone());

        let alice_device = DeviceKeypair::generate();
        let bob_device = DeviceKeypair::generate();
        let alice_wg = derive_wireguard_keypair(&alice_device);
        let alice_chain = create_device_chain(&ca, &root_cert, &alice_device);

        let alice_ephemeral = EphemeralKeypair::generate();
        let bob_id = bob_device.device_id();

        let message = HandshakeMessage::create(
            &alice_device,
            &alice_ephemeral,
            &bob_id,
            alice_wg.public,
            &alice_chain,
        );

        assert!(message
            .verify(&bob_device.public_key(), &bob_id, &validator)
            .is_err());
    }

    #[test]
    fn test_handshake_rejects_untrusted_cert() {
        let (_ca, root_cert) = create_test_ca();
        let validator = CertValidator::new(root_cert.clone());

        let untrusted_ca = DeviceKeypair::generate();
        let untrusted_root = Certificate::new_self_signed(&untrusted_ca, 365);

        let alice_device = DeviceKeypair::generate();
        let bob_device = DeviceKeypair::generate();
        let alice_wg = derive_wireguard_keypair(&alice_device);
        let alice_chain = create_device_chain(&untrusted_ca, &untrusted_root, &alice_device);

        let alice_ephemeral = EphemeralKeypair::generate();
        let bob_id = bob_device.device_id();

        let message = HandshakeMessage::create(
            &alice_device,
            &alice_ephemeral,
            &bob_id,
            alice_wg.public,
            &alice_chain,
        );

        let result = message.verify(&alice_device.public_key(), &bob_id, &validator);
        assert!(matches!(result, Err(HandshakeError::CertificateInvalid(_))));
    }

    #[test]
    fn test_handshake_rejects_device_id_mismatch() {
        let (ca, root_cert) = create_test_ca();
        let validator = CertValidator::new(root_cert.clone());

        let alice_device = DeviceKeypair::generate();
        let bob_device = DeviceKeypair::generate();
        let charlie_device = DeviceKeypair::generate();
        let alice_wg = derive_wireguard_keypair(&alice_device);
        let charlie_chain = create_device_chain(&ca, &root_cert, &charlie_device);

        let alice_ephemeral = EphemeralKeypair::generate();
        let bob_id = bob_device.device_id();

        let message = HandshakeMessage::create(
            &alice_device,
            &alice_ephemeral,
            &bob_id,
            alice_wg.public,
            &charlie_chain,
        );

        let result = message.verify(&alice_device.public_key(), &bob_id, &validator);
        assert!(matches!(result, Err(HandshakeError::CertificateInvalid(_))));
    }

    #[test]
    fn test_session_keys_deterministic_from_shared_secret() {
        let alice_ephemeral = EphemeralKeypair::generate();
        let bob_ephemeral = EphemeralKeypair::generate();

        let alice_keys = derive_session_keys(&alice_ephemeral, bob_ephemeral.public_key());
        let alice_keys2 = derive_session_keys(&alice_ephemeral, bob_ephemeral.public_key());

        assert_eq!(*alice_keys.wireguard_psk, *alice_keys2.wireguard_psk);
    }

    #[test]
    fn test_session_keys_psk_matches() {
        let alice_ephemeral = EphemeralKeypair::generate();
        let bob_ephemeral = EphemeralKeypair::generate();

        let alice_keys = derive_session_keys(&alice_ephemeral, bob_ephemeral.public_key());
        let bob_keys = derive_session_keys(&bob_ephemeral, alice_ephemeral.public_key());

        assert_eq!(*alice_keys.wireguard_psk, *bob_keys.wireguard_psk);
    }

    #[test]
    fn wireguard_keypair_deterministic() {
        let device = DeviceKeypair::from_seed(&[9u8; 32]);

        let keys1 = derive_wireguard_keypair(&device);
        let keys2 = derive_wireguard_keypair(&device);

        assert_eq!(*keys1.private, *keys2.private);
        assert_eq!(keys1.public, keys2.public);
    }

    #[test]
    fn wireguard_pubkey_matches_private() {
        let device = DeviceKeypair::from_seed(&[7u8; 32]);

        let keys = derive_wireguard_keypair(&device);

        assert_eq!(wireguard_pubkey(&*keys.private), keys.public);
    }

    #[test]
    fn test_handshake_serialization() {
        let (ca, root_cert) = create_test_ca();

        let device = DeviceKeypair::generate();
        let ephemeral = EphemeralKeypair::generate();
        let peer_id = DeviceKeypair::generate().device_id();
        let wg_keys = derive_wireguard_keypair(&device);
        let chain = create_device_chain(&ca, &root_cert, &device);

        let message =
            HandshakeMessage::create(&device, &ephemeral, &peer_id, wg_keys.public, &chain);

        let json = serde_json::to_string(&message).unwrap();
        let deserialized: HandshakeMessage = serde_json::from_str(&json).unwrap();

        assert_eq!(message.ephemeral_pubkey, deserialized.ephemeral_pubkey);
        assert_eq!(message.nonce, deserialized.nonce);
        assert_eq!(message.wg_pubkey, deserialized.wg_pubkey);
        assert_eq!(message.signature, deserialized.signature);
    }

    #[test]
    fn test_full_handshake_flow() {
        let (ca, root_cert) = create_test_ca();
        let validator = CertValidator::new(root_cert.clone());

        let alice_device = DeviceKeypair::generate();
        let bob_device = DeviceKeypair::generate();
        let alice_wg = derive_wireguard_keypair(&alice_device);
        let bob_wg = derive_wireguard_keypair(&bob_device);
        let alice_chain = create_device_chain(&ca, &root_cert, &alice_device);
        let bob_chain = create_device_chain(&ca, &root_cert, &bob_device);

        let alice_ephemeral = EphemeralKeypair::generate();
        let bob_ephemeral = EphemeralKeypair::generate();

        let alice_msg = HandshakeMessage::create(
            &alice_device,
            &alice_ephemeral,
            &bob_device.device_id(),
            alice_wg.public,
            &alice_chain,
        );
        let bob_msg = HandshakeMessage::create(
            &bob_device,
            &bob_ephemeral,
            &alice_device.device_id(),
            bob_wg.public,
            &bob_chain,
        );

        assert!(alice_msg
            .verify(&alice_device.public_key(), &bob_device.device_id(), &validator)
            .is_ok());
        assert!(bob_msg
            .verify(&bob_device.public_key(), &alice_device.device_id(), &validator)
            .is_ok());

        let alice_keys = derive_session_keys(&alice_ephemeral, &bob_msg.ephemeral_public_key());
        let bob_keys = derive_session_keys(&bob_ephemeral, &alice_msg.ephemeral_public_key());

        assert_eq!(*alice_keys.wireguard_psk, *bob_keys.wireguard_psk);
    }
}
