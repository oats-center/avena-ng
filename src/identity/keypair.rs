use crate::identity::device_id::DeviceId;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use zeroize::Zeroizing;

#[expect(missing_debug_implementations, reason = "contains secret signing key")]
pub struct DeviceKeypair {
    signing_key: SigningKey,
    device_id: DeviceId,
}

impl DeviceKeypair {
    /// Generate a new random long-lived device identity.
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        let device_id = DeviceId::from_public_key(&signing_key.verifying_key());
        Self { signing_key, device_id }
    }

    /// Deterministically create a device identity from a seed.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(seed);
        let device_id = DeviceId::from_public_key(&signing_key.verifying_key());
        Self { signing_key, device_id }
    }

    pub fn device_id(&self) -> DeviceId {
        self.device_id
    }

    pub fn public_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    pub fn sign(&self, message: &[u8]) -> Signature {
        self.signing_key.sign(message)
    }

    pub fn to_bytes(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.signing_key.to_bytes())
    }

    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        Self::from_seed(bytes)
    }

}


#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Verifier;

    #[test]
    fn test_generate_creates_valid_keypair() {
        let keypair = DeviceKeypair::generate();
        let message = b"test message";

        let signature = keypair.sign(message);
        assert!(keypair.public_key().verify(message, &signature).is_ok());
    }

    #[test]
    fn test_from_seed_deterministic() {
        let seed = [42u8; 32];

        let keypair1 = DeviceKeypair::from_seed(&seed);
        let keypair2 = DeviceKeypair::from_seed(&seed);

        assert_eq!(keypair1.device_id(), keypair2.device_id());
        assert_eq!(keypair1.public_key().to_bytes(), keypair2.public_key().to_bytes());
    }

    #[test]
    fn test_different_seeds_different_keys() {
        let keypair1 = DeviceKeypair::from_seed(&[1u8; 32]);
        let keypair2 = DeviceKeypair::from_seed(&[2u8; 32]);

        assert_ne!(keypair1.device_id(), keypair2.device_id());
    }

    #[test]
    fn test_device_id_matches_public_key() {
        let keypair = DeviceKeypair::generate();
        let expected_id = DeviceId::from_public_key(&keypair.public_key());

        assert_eq!(keypair.device_id(), expected_id);
    }

    #[test]
    fn test_to_bytes_from_bytes_roundtrip() {
        let original = DeviceKeypair::generate();
        let bytes = original.to_bytes();
        let restored = DeviceKeypair::from_bytes(&bytes);

        assert_eq!(original.device_id(), restored.device_id());
        assert_eq!(original.public_key().to_bytes(), restored.public_key().to_bytes());
    }

    #[test]
    fn test_signature_verification() {
        let keypair = DeviceKeypair::generate();
        let message = b"important data";

        let signature = keypair.sign(message);
        assert!(keypair.public_key().verify(message, &signature).is_ok());
    }

    #[test]
    fn test_signature_fails_wrong_message() {
        let keypair = DeviceKeypair::generate();
        let message = b"original message";
        let wrong_message = b"tampered message";

        let signature = keypair.sign(message);
        assert!(keypair.public_key().verify(wrong_message, &signature).is_err());
    }

    #[test]
    fn test_signature_fails_wrong_key() {
        let keypair1 = DeviceKeypair::generate();
        let keypair2 = DeviceKeypair::generate();
        let message = b"test message";

        let signature = keypair1.sign(message);
        assert!(keypair2.public_key().verify(message, &signature).is_err());
    }

    #[test]
    fn test_zeroizing_bytes() {
        let keypair = DeviceKeypair::generate();
        let bytes = keypair.to_bytes();
        assert_eq!(bytes.len(), 32);
    }
}
