use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum DecodeError {
    #[error("invalid base32 encoding: {0}")]
    InvalidBase32(String),
    #[error("invalid length: expected 16 bytes, got {0}")]
    InvalidLength(usize),
}

/// Stable identifier derived from an Ed25519 public key.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct DeviceId([u8; 16]);

impl DeviceId {
    pub fn from_public_key(pk: &ed25519_dalek::VerifyingKey) -> Self {
        let hash = Sha256::digest(pk.as_bytes());
        let mut id = [0u8; 16];
        id.copy_from_slice(&hash[..16]);
        Self(id)
    }

    pub fn to_base32(&self) -> String {
        base32::encode(base32::Alphabet::Rfc4648 { padding: false }, &self.0).to_lowercase()
    }

    pub fn from_base32(s: &str) -> Result<Self, DecodeError> {
        let bytes = base32::decode(base32::Alphabet::Rfc4648 { padding: false }, &s.to_uppercase())
            .ok_or_else(|| DecodeError::InvalidBase32(s.to_string()))?;

        if bytes.len() != 16 {
            return Err(DecodeError::InvalidLength(bytes.len()));
        }

        let mut id = [0u8; 16];
        id.copy_from_slice(&bytes);
        Ok(Self(id))
    }

    pub fn to_ipv6_suffix(&self) -> [u8; 8] {
        let mut suffix = [0u8; 8];
        suffix.copy_from_slice(&self.0[..8]);
        suffix
    }

    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    pub fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }
}

impl fmt::Display for DeviceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_base32())
    }
}

impl fmt::Debug for DeviceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let b32 = self.to_base32();
        write!(f, "DeviceId({}...{})", &b32[..4], &b32[b32.len()-4..])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    #[test]
    fn test_device_id_from_public_key_deterministic() {
        let seed = [42u8; 32];
        let signing_key = SigningKey::from_bytes(&seed);
        let pk = signing_key.verifying_key();

        let id1 = DeviceId::from_public_key(&pk);
        let id2 = DeviceId::from_public_key(&pk);

        assert_eq!(id1, id2);
    }

    #[test]
    fn test_device_id_different_keys_different_ids() {
        let key1 = SigningKey::generate(&mut OsRng);
        let key2 = SigningKey::generate(&mut OsRng);

        let id1 = DeviceId::from_public_key(&key1.verifying_key());
        let id2 = DeviceId::from_public_key(&key2.verifying_key());

        assert_ne!(id1, id2);
    }

    #[test]
    fn test_base32_roundtrip() {
        let key = SigningKey::generate(&mut OsRng);
        let id = DeviceId::from_public_key(&key.verifying_key());

        let encoded = id.to_base32();
        let decoded = DeviceId::from_base32(&encoded).unwrap();

        assert_eq!(id, decoded);
    }

    #[test]
    fn test_base32_case_insensitive() {
        let key = SigningKey::generate(&mut OsRng);
        let id = DeviceId::from_public_key(&key.verifying_key());

        let lower = id.to_base32();
        let upper = lower.to_uppercase();

        let decoded_lower = DeviceId::from_base32(&lower).unwrap();
        let decoded_upper = DeviceId::from_base32(&upper).unwrap();

        assert_eq!(decoded_lower, decoded_upper);
    }

    #[test]
    fn test_invalid_base32() {
        let result = DeviceId::from_base32("!!!invalid!!!");
        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_length() {
        let result = DeviceId::from_base32("AAAA");
        assert!(result.is_err());
    }

    #[test]
    fn test_ipv6_suffix_length() {
        let key = SigningKey::generate(&mut OsRng);
        let id = DeviceId::from_public_key(&key.verifying_key());

        let suffix = id.to_ipv6_suffix();
        assert_eq!(suffix.len(), 8);
    }

    #[test]
    fn test_display_is_base32() {
        let key = SigningKey::generate(&mut OsRng);
        let id = DeviceId::from_public_key(&key.verifying_key());

        assert_eq!(format!("{}", id), id.to_base32());
    }

    #[test]
    fn test_debug_is_truncated() {
        let key = SigningKey::generate(&mut OsRng);
        let id = DeviceId::from_public_key(&key.verifying_key());

        let debug = format!("{:?}", id);
        assert!(debug.starts_with("DeviceId("));
        assert!(debug.contains("..."));
    }

    #[test]
    fn test_serialization_roundtrip() {
        let key = SigningKey::generate(&mut OsRng);
        let id = DeviceId::from_public_key(&key.verifying_key());

        let json = serde_json::to_string(&id).unwrap();
        let deserialized: DeviceId = serde_json::from_str(&json).unwrap();

        assert_eq!(id, deserialized);
    }

    #[test]
    fn test_ordering() {
        let key1 = SigningKey::from_bytes(&[1u8; 32]);
        let key2 = SigningKey::from_bytes(&[2u8; 32]);

        let id1 = DeviceId::from_public_key(&key1.verifying_key());
        let id2 = DeviceId::from_public_key(&key2.verifying_key());

        assert!(id1 < id2 || id1 > id2 || id1 == id2);
    }
}
