use crate::identity::{DeviceId, DeviceKeypair};
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, Bytes};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum CertError {
    #[error("certificate expired at {0}")]
    Expired(DateTime<Utc>),
    #[error("certificate not yet valid until {0}")]
    NotYetValid(DateTime<Utc>),
    #[error("signature verification failed")]
    InvalidSignature,
    #[error("chain does not terminate at trusted root")]
    UntrustedRoot,
    #[error("chain is broken: certificate {0} not signed by next")]
    BrokenChain(usize),
    #[error("empty certificate chain")]
    EmptyChain,
    #[error("device ID mismatch: certificate has {cert_id}, expected {expected_id}")]
    DeviceIdMismatch {
        cert_id: DeviceId,
        expected_id: DeviceId,
    },
}

#[serde_as]
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Certificate {
    pub device_id: DeviceId,
    #[serde_as(as = "Bytes")]
    pub public_key: [u8; 32],
    pub issuer_id: DeviceId,
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
    #[serde_as(as = "Bytes")]
    pub signature: [u8; 64],
}

impl Certificate {
    pub fn new_self_signed(keypair: &DeviceKeypair, validity_days: i64) -> Self {
        let now = Utc::now();
        let not_after = now + chrono::Duration::days(validity_days);

        let mut cert = Self {
            device_id: keypair.device_id(),
            public_key: keypair.public_key().to_bytes(),
            issuer_id: keypair.device_id(),
            not_before: now,
            not_after,
            signature: [0u8; 64],
        };

        let bytes_to_sign = cert.bytes_to_sign();
        cert.signature = keypair.sign(&bytes_to_sign).to_bytes();
        cert
    }

    pub fn issue(
        issuer: &DeviceKeypair,
        subject_id: DeviceId,
        subject_pubkey: VerifyingKey,
        validity_days: i64,
    ) -> Self {
        let now = Utc::now();
        let not_after = now + chrono::Duration::days(validity_days);

        let mut cert = Self {
            device_id: subject_id,
            public_key: subject_pubkey.to_bytes(),
            issuer_id: issuer.device_id(),
            not_before: now,
            not_after,
            signature: [0u8; 64],
        };

        let bytes_to_sign = cert.bytes_to_sign();
        cert.signature = issuer.sign(&bytes_to_sign).to_bytes();
        cert
    }

    fn bytes_to_sign(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(self.device_id.as_bytes());
        bytes.extend_from_slice(&self.public_key);
        bytes.extend_from_slice(self.issuer_id.as_bytes());
        bytes.extend_from_slice(&self.not_before.timestamp().to_le_bytes());
        bytes.extend_from_slice(&self.not_after.timestamp().to_le_bytes());
        bytes
    }

    pub fn verifying_key(&self) -> Result<VerifyingKey, ed25519_dalek::SignatureError> {
        VerifyingKey::from_bytes(&self.public_key)
    }

    pub fn verify_signature(&self, issuer_pubkey: &VerifyingKey) -> Result<(), CertError> {
        let bytes = self.bytes_to_sign();
        let sig = Signature::from_bytes(&self.signature);
        issuer_pubkey
            .verify(&bytes, &sig)
            .map_err(|_| CertError::InvalidSignature)
    }

    pub fn is_self_signed(&self) -> bool {
        self.device_id == self.issuer_id
    }
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct CertificateChain {
    pub leaf: Certificate,
    pub intermediates: Vec<Certificate>,
}

impl CertificateChain {
    pub fn new(leaf: Certificate) -> Self {
        Self {
            leaf,
            intermediates: Vec::new(),
        }
    }

    pub fn with_intermediates(leaf: Certificate, intermediates: Vec<Certificate>) -> Self {
        Self { leaf, intermediates }
    }
}

pub struct CertValidator {
    trusted_root: Certificate,
}

impl CertValidator {
    pub fn new(trusted_root: Certificate) -> Self {
        Self { trusted_root }
    }

    pub fn validate_chain(&self, chain: &CertificateChain) -> Result<(), CertError> {
        self.check_expiry(&chain.leaf)?;

        let full_chain = std::iter::once(&chain.leaf)
            .chain(chain.intermediates.iter())
            .collect::<Vec<_>>();

        if full_chain.is_empty() {
            return Err(CertError::EmptyChain);
        }

        for i in 0..full_chain.len() {
            let cert = full_chain[i];

            let issuer_pubkey = if i + 1 < full_chain.len() {
                full_chain[i + 1]
                    .verifying_key()
                    .map_err(|_| CertError::BrokenChain(i))?
            } else if cert.issuer_id == self.trusted_root.device_id {
                self.trusted_root
                    .verifying_key()
                    .map_err(|_| CertError::UntrustedRoot)?
            } else if cert.is_self_signed() && cert.device_id == self.trusted_root.device_id {
                cert.verifying_key()
                    .map_err(|_| CertError::UntrustedRoot)?
            } else {
                return Err(CertError::UntrustedRoot);
            };

            cert.verify_signature(&issuer_pubkey)?;

            if i + 1 < full_chain.len() {
                self.check_expiry(full_chain[i + 1])?;
            }
        }

        Ok(())
    }

    pub fn check_expiry(&self, cert: &Certificate) -> Result<(), CertError> {
        let now = Utc::now();

        if now < cert.not_before {
            return Err(CertError::NotYetValid(cert.not_before));
        }

        if now > cert.not_after {
            return Err(CertError::Expired(cert.not_after));
        }

        Ok(())
    }

    pub fn trusted_root(&self) -> &Certificate {
        &self.trusted_root
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_root() -> (DeviceKeypair, Certificate) {
        let keypair = DeviceKeypair::from_seed(&[1u8; 32]);
        let cert = Certificate::new_self_signed(&keypair, 365);
        (keypair, cert)
    }

    #[test]
    fn test_self_signed_certificate() {
        let keypair = DeviceKeypair::generate();
        let cert = Certificate::new_self_signed(&keypair, 365);

        assert_eq!(cert.device_id, keypair.device_id());
        assert_eq!(cert.issuer_id, keypair.device_id());
        assert!(cert.is_self_signed());
    }

    #[test]
    fn test_self_signed_signature_valid() {
        let keypair = DeviceKeypair::generate();
        let cert = Certificate::new_self_signed(&keypair, 365);

        assert!(cert.verify_signature(&keypair.public_key()).is_ok());
    }

    #[test]
    fn test_issued_certificate() {
        let issuer = DeviceKeypair::generate();
        let subject = DeviceKeypair::generate();

        let cert = Certificate::issue(
            &issuer,
            subject.device_id(),
            subject.public_key(),
            365,
        );

        assert_eq!(cert.device_id, subject.device_id());
        assert_eq!(cert.issuer_id, issuer.device_id());
        assert!(!cert.is_self_signed());
        assert!(cert.verify_signature(&issuer.public_key()).is_ok());
    }

    #[test]
    fn test_signature_fails_wrong_issuer() {
        let real_issuer = DeviceKeypair::generate();
        let fake_issuer = DeviceKeypair::generate();
        let subject = DeviceKeypair::generate();

        let cert = Certificate::issue(
            &real_issuer,
            subject.device_id(),
            subject.public_key(),
            365,
        );

        assert!(cert.verify_signature(&fake_issuer.public_key()).is_err());
    }

    #[test]
    fn test_chain_validation_single_cert() {
        let (_root_keypair, root_cert) = create_test_root();
        let validator = CertValidator::new(root_cert.clone());

        let chain = CertificateChain::new(root_cert);
        assert!(validator.validate_chain(&chain).is_ok());
    }

    #[test]
    fn test_chain_validation_with_intermediate() {
        let (root_keypair, root_cert) = create_test_root();

        let intermediate_keypair = DeviceKeypair::generate();
        let intermediate_cert = Certificate::issue(
            &root_keypair,
            intermediate_keypair.device_id(),
            intermediate_keypair.public_key(),
            365,
        );

        let leaf_keypair = DeviceKeypair::generate();
        let leaf_cert = Certificate::issue(
            &intermediate_keypair,
            leaf_keypair.device_id(),
            leaf_keypair.public_key(),
            365,
        );

        let validator = CertValidator::new(root_cert);
        let chain = CertificateChain::with_intermediates(leaf_cert, vec![intermediate_cert]);

        assert!(validator.validate_chain(&chain).is_ok());
    }

    #[test]
    fn test_chain_validation_untrusted_root() {
        let (_, root_cert) = create_test_root();

        let other_root = DeviceKeypair::generate();
        let other_root_cert = Certificate::new_self_signed(&other_root, 365);

        let validator = CertValidator::new(root_cert);
        let chain = CertificateChain::new(other_root_cert);

        assert!(matches!(
            validator.validate_chain(&chain),
            Err(CertError::UntrustedRoot)
        ));
    }

    #[test]
    fn test_expired_certificate() {
        let keypair = DeviceKeypair::generate();
        let mut cert = Certificate::new_self_signed(&keypair, 365);

        cert.not_after = Utc::now() - chrono::Duration::days(1);

        let validator = CertValidator::new(cert.clone());
        assert!(matches!(
            validator.check_expiry(&cert),
            Err(CertError::Expired(_))
        ));
    }

    #[test]
    fn test_not_yet_valid_certificate() {
        let keypair = DeviceKeypair::generate();
        let mut cert = Certificate::new_self_signed(&keypair, 365);

        cert.not_before = Utc::now() + chrono::Duration::days(1);

        let validator = CertValidator::new(cert.clone());
        assert!(matches!(
            validator.check_expiry(&cert),
            Err(CertError::NotYetValid(_))
        ));
    }

    #[test]
    fn test_valid_certificate_time() {
        let keypair = DeviceKeypair::generate();
        let cert = Certificate::new_self_signed(&keypair, 365);

        let validator = CertValidator::new(cert.clone());
        assert!(validator.check_expiry(&cert).is_ok());
    }

    #[test]
    fn test_certificate_serialization() {
        let keypair = DeviceKeypair::generate();
        let cert = Certificate::new_self_signed(&keypair, 365);

        let json = serde_json::to_string(&cert).unwrap();
        let deserialized: Certificate = serde_json::from_str(&json).unwrap();

        assert_eq!(cert.device_id, deserialized.device_id);
        assert_eq!(cert.public_key, deserialized.public_key);
        assert_eq!(cert.signature, deserialized.signature);
    }

    #[test]
    fn test_chain_serialization() {
        let (root_keypair, _root_cert) = create_test_root();

        let leaf_keypair = DeviceKeypair::generate();
        let leaf_cert = Certificate::issue(
            &root_keypair,
            leaf_keypair.device_id(),
            leaf_keypair.public_key(),
            365,
        );

        let chain = CertificateChain::with_intermediates(leaf_cert, vec![]);

        let json = serde_json::to_string(&chain).unwrap();
        let deserialized: CertificateChain = serde_json::from_str(&json).unwrap();

        assert_eq!(chain.leaf.device_id, deserialized.leaf.device_id);
    }

    #[test]
    fn test_broken_chain() {
        let (_, root_cert) = create_test_root();

        let unrelated_issuer = DeviceKeypair::generate();
        let leaf_keypair = DeviceKeypair::generate();

        let leaf_cert = Certificate::issue(
            &unrelated_issuer,
            leaf_keypair.device_id(),
            leaf_keypair.public_key(),
            365,
        );

        let validator = CertValidator::new(root_cert);
        let chain = CertificateChain::new(leaf_cert);

        assert!(validator.validate_chain(&chain).is_err());
    }
}
