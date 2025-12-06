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

#[derive(Error, Debug)]
pub enum HandshakeError {
    #[error("signature verification failed")]
    InvalidSignature,
    #[error("peer ID mismatch: expected {expected}, got {actual}")]
    PeerIdMismatch { expected: DeviceId, actual: DeviceId },
}

pub struct EphemeralKeypair {
    secret: StaticSecret,
    public: X25519PublicKey,
}

impl EphemeralKeypair {
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(OsRng);
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

#[serde_as]
#[derive(Clone, Serialize, Deserialize)]
pub struct HandshakeMessage {
    #[serde_as(as = "Bytes")]
    pub ephemeral_pubkey: [u8; 32],
    #[serde_as(as = "Bytes")]
    pub nonce: [u8; 32],
    #[serde_as(as = "Bytes")]
    pub signature: [u8; 64],
}

impl HandshakeMessage {
    pub fn create(
        device: &DeviceKeypair,
        ephemeral: &EphemeralKeypair,
        peer_id: &DeviceId,
    ) -> Self {
        let mut nonce = [0u8; 32];
        rand::RngCore::fill_bytes(&mut OsRng, &mut nonce);

        let ephemeral_pubkey = ephemeral.public_key_bytes();

        let mut message_to_sign = Vec::with_capacity(32 + 32 + 16);
        message_to_sign.extend_from_slice(&ephemeral_pubkey);
        message_to_sign.extend_from_slice(&nonce);
        message_to_sign.extend_from_slice(peer_id.as_bytes());

        let signature = device.sign(&message_to_sign);

        Self {
            ephemeral_pubkey,
            nonce,
            signature: signature.to_bytes(),
        }
    }

    pub fn verify(
        &self,
        peer_pubkey: &VerifyingKey,
        local_id: &DeviceId,
    ) -> Result<(), HandshakeError> {
        let mut message_to_verify = Vec::with_capacity(32 + 32 + 16);
        message_to_verify.extend_from_slice(&self.ephemeral_pubkey);
        message_to_verify.extend_from_slice(&self.nonce);
        message_to_verify.extend_from_slice(local_id.as_bytes());

        let signature = Signature::from_bytes(&self.signature);
        peer_pubkey
            .verify(&message_to_verify, &signature)
            .map_err(|_| HandshakeError::InvalidSignature)
    }

    pub fn ephemeral_public_key(&self) -> X25519PublicKey {
        X25519PublicKey::from(self.ephemeral_pubkey)
    }
}

#[derive(Clone)]
pub struct SessionKeys {
    pub wireguard_private: Zeroizing<[u8; 32]>,
    pub wireguard_psk: Zeroizing<[u8; 32]>,
}

const SESSION_KEY_SALT: &[u8] = b"avena-session-keys-v1";
const WG_PRIVATE_INFO: &[u8] = b"wireguard-private";
const WG_PSK_INFO: &[u8] = b"wireguard-psk";

pub fn derive_session_keys(
    local_ephemeral: &EphemeralKeypair,
    peer_ephemeral: &X25519PublicKey,
    initiator: bool,
) -> SessionKeys {
    let shared_secret = local_ephemeral.diffie_hellman(peer_ephemeral);

    let hkdf = Hkdf::<Sha256>::new(Some(SESSION_KEY_SALT), &shared_secret);

    let role_prefix = if initiator { b"initiator" } else { b"responder" };

    let mut wg_private = [0u8; 32];
    let mut private_info = Vec::with_capacity(role_prefix.len() + WG_PRIVATE_INFO.len());
    private_info.extend_from_slice(role_prefix);
    private_info.extend_from_slice(WG_PRIVATE_INFO);
    hkdf.expand(&private_info, &mut wg_private)
        .expect("32 bytes is valid for HKDF-SHA256");

    let mut wg_psk = [0u8; 32];
    hkdf.expand(WG_PSK_INFO, &mut wg_psk)
        .expect("32 bytes is valid for HKDF-SHA256");

    SessionKeys {
        wireguard_private: Zeroizing::new(wg_private),
        wireguard_psk: Zeroizing::new(wg_psk),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ephemeral_keypair_generation() {
        let kp1 = EphemeralKeypair::generate();
        let kp2 = EphemeralKeypair::generate();

        assert_ne!(kp1.public_key_bytes(), kp2.public_key_bytes());
    }

    #[test]
    fn test_handshake_message_create_and_verify() {
        let alice_device = DeviceKeypair::generate();
        let bob_device = DeviceKeypair::generate();

        let alice_ephemeral = EphemeralKeypair::generate();
        let bob_id = bob_device.device_id();

        let message = HandshakeMessage::create(&alice_device, &alice_ephemeral, &bob_id);

        assert!(message.verify(&alice_device.public_key(), &bob_id).is_ok());
    }

    #[test]
    fn test_handshake_message_fails_wrong_peer() {
        let alice_device = DeviceKeypair::generate();
        let bob_device = DeviceKeypair::generate();
        let charlie_device = DeviceKeypair::generate();

        let alice_ephemeral = EphemeralKeypair::generate();
        let bob_id = bob_device.device_id();
        let charlie_id = charlie_device.device_id();

        let message = HandshakeMessage::create(&alice_device, &alice_ephemeral, &bob_id);

        assert!(message.verify(&alice_device.public_key(), &charlie_id).is_err());
    }

    #[test]
    fn test_handshake_message_fails_wrong_signer() {
        let alice_device = DeviceKeypair::generate();
        let bob_device = DeviceKeypair::generate();

        let alice_ephemeral = EphemeralKeypair::generate();
        let bob_id = bob_device.device_id();

        let message = HandshakeMessage::create(&alice_device, &alice_ephemeral, &bob_id);

        assert!(message.verify(&bob_device.public_key(), &bob_id).is_err());
    }

    #[test]
    fn test_session_keys_deterministic_from_shared_secret() {
        let alice_ephemeral = EphemeralKeypair::generate();
        let bob_ephemeral = EphemeralKeypair::generate();

        let alice_keys = derive_session_keys(&alice_ephemeral, bob_ephemeral.public_key(), true);

        let alice_keys2 = derive_session_keys(&alice_ephemeral, bob_ephemeral.public_key(), true);

        assert_eq!(*alice_keys.wireguard_private, *alice_keys2.wireguard_private);
        assert_eq!(*alice_keys.wireguard_psk, *alice_keys2.wireguard_psk);
    }

    #[test]
    fn test_session_keys_psk_matches() {
        let alice_ephemeral = EphemeralKeypair::generate();
        let bob_ephemeral = EphemeralKeypair::generate();

        let alice_keys = derive_session_keys(&alice_ephemeral, bob_ephemeral.public_key(), true);
        let bob_keys = derive_session_keys(&bob_ephemeral, alice_ephemeral.public_key(), false);

        assert_eq!(*alice_keys.wireguard_psk, *bob_keys.wireguard_psk);
    }

    #[test]
    fn test_session_keys_private_differs_by_role() {
        let alice_ephemeral = EphemeralKeypair::generate();
        let bob_ephemeral = EphemeralKeypair::generate();

        let alice_keys = derive_session_keys(&alice_ephemeral, bob_ephemeral.public_key(), true);
        let bob_keys = derive_session_keys(&bob_ephemeral, alice_ephemeral.public_key(), false);

        assert_ne!(*alice_keys.wireguard_private, *bob_keys.wireguard_private);
    }

    #[test]
    fn test_handshake_serialization() {
        let device = DeviceKeypair::generate();
        let ephemeral = EphemeralKeypair::generate();
        let peer_id = DeviceKeypair::generate().device_id();

        let message = HandshakeMessage::create(&device, &ephemeral, &peer_id);

        let json = serde_json::to_string(&message).unwrap();
        let deserialized: HandshakeMessage = serde_json::from_str(&json).unwrap();

        assert_eq!(message.ephemeral_pubkey, deserialized.ephemeral_pubkey);
        assert_eq!(message.nonce, deserialized.nonce);
        assert_eq!(message.signature, deserialized.signature);
    }

    #[test]
    fn test_full_handshake_flow() {
        let alice_device = DeviceKeypair::generate();
        let bob_device = DeviceKeypair::generate();

        let alice_ephemeral = EphemeralKeypair::generate();
        let bob_ephemeral = EphemeralKeypair::generate();

        let alice_msg = HandshakeMessage::create(
            &alice_device,
            &alice_ephemeral,
            &bob_device.device_id(),
        );
        let bob_msg = HandshakeMessage::create(
            &bob_device,
            &bob_ephemeral,
            &alice_device.device_id(),
        );

        assert!(alice_msg.verify(&alice_device.public_key(), &bob_device.device_id()).is_ok());
        assert!(bob_msg.verify(&bob_device.public_key(), &alice_device.device_id()).is_ok());

        let alice_keys = derive_session_keys(
            &alice_ephemeral,
            &bob_msg.ephemeral_public_key(),
            true,
        );
        let bob_keys = derive_session_keys(
            &bob_ephemeral,
            &alice_msg.ephemeral_public_key(),
            false,
        );

        assert_eq!(*alice_keys.wireguard_psk, *bob_keys.wireguard_psk);
    }
}
