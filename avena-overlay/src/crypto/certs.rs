//! JWT-based certificate support for devices and workloads.
//!
//! Certificates are JWTs (RFC 7519) signed with Ed25519 (`EdDSA` algorithm).
//! A certificate attests a `DeviceId` is valid for a time window. The validator
//! caches intermediate certificates and verifies chains against a trusted root.

use crate::identity::{DeviceId, DeviceKeypair};
use chrono::{DateTime, TimeZone, Utc};
use ed25519_dalek::VerifyingKey;
use jsonwebtoken::{
    decode, encode, Algorithm, DecodingKey, EncodingKey, Header, TokenData, Validation,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum CertError {
    #[error("certificate expired at {0}")]
    Expired(DateTime<Utc>),
    #[error("certificate not yet valid until {0}")]
    NotYetValid(DateTime<Utc>),
    #[error("signature verification failed: {0}")]
    InvalidSignature(String),
    #[error("issuer not found in cache: {0}")]
    IssuerNotFound(DeviceId),
    #[error("chain does not terminate at trusted root")]
    UntrustedRoot,
    #[error("device ID mismatch: certificate has {cert_id}, expected {expected_id}")]
    DeviceIdMismatch {
        cert_id: DeviceId,
        expected_id: DeviceId,
    },
    #[error("JWT error: {0}")]
    JwtError(#[from] jsonwebtoken::errors::Error),
    #[error("invalid public key in certificate")]
    InvalidPublicKey,
    #[error("chain depth limit exceeded")]
    ChainTooDeep,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct CertClaims {
    pub sub: String,
    pub iss: String,
    #[serde(with = "base64_bytes")]
    pub public_key: [u8; 32],
    pub iat: i64,
    pub nbf: i64,
    pub exp: i64,
}

mod base64_bytes {
    use base64::{engine::general_purpose::STANDARD, Engine};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = STANDARD
            .decode(&s)
            .map_err(|e| serde::de::Error::custom(e.to_string()))?;
        if bytes.len() != 32 {
            return Err(serde::de::Error::custom("expected 32 bytes"));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(arr)
    }
}

impl CertClaims {
    pub fn device_id(&self) -> Result<DeviceId, CertError> {
        DeviceId::from_base32(&self.sub).map_err(|_| CertError::InvalidPublicKey)
    }

    pub fn issuer_id(&self) -> Result<DeviceId, CertError> {
        DeviceId::from_base32(&self.iss).map_err(|_| CertError::InvalidPublicKey)
    }

    pub fn verifying_key(&self) -> Result<VerifyingKey, CertError> {
        VerifyingKey::from_bytes(&self.public_key).map_err(|_| CertError::InvalidPublicKey)
    }

    pub fn is_self_signed(&self) -> bool {
        self.sub == self.iss
    }

    pub fn not_before(&self) -> DateTime<Utc> {
        Utc.timestamp_opt(self.nbf, 0).unwrap()
    }

    pub fn not_after(&self) -> DateTime<Utc> {
        Utc.timestamp_opt(self.exp, 0).unwrap()
    }
}

#[derive(Clone, Debug)]
struct CachedCert {
    pubkey: VerifyingKey,
    issuer_id: DeviceId,
    exp: i64,
}

pub fn create_self_signed_jwt(keypair: &DeviceKeypair, validity_days: i64) -> String {
    let now = Utc::now();
    let exp = now + chrono::Duration::days(validity_days);

    let claims = CertClaims {
        sub: keypair.device_id().to_string(),
        iss: keypair.device_id().to_string(),
        public_key: keypair.public_key().to_bytes(),
        iat: now.timestamp(),
        nbf: now.timestamp(),
        exp: exp.timestamp(),
    };

    let header = Header::new(Algorithm::EdDSA);
    let key = EncodingKey::from_ed_der(&keypair.to_pkcs8_der());

    encode(&header, &claims, &key).expect("JWT encoding should not fail")
}

pub fn issue_jwt(
    issuer: &DeviceKeypair,
    subject_id: DeviceId,
    subject_pubkey: VerifyingKey,
    validity_days: i64,
) -> String {
    let now = Utc::now();
    let exp = now + chrono::Duration::days(validity_days);

    let claims = CertClaims {
        sub: subject_id.to_string(),
        iss: issuer.device_id().to_string(),
        public_key: subject_pubkey.to_bytes(),
        iat: now.timestamp(),
        nbf: now.timestamp(),
        exp: exp.timestamp(),
    };

    let header = Header::new(Algorithm::EdDSA);
    let key = EncodingKey::from_ed_der(&issuer.to_pkcs8_der());

    encode(&header, &claims, &key).expect("JWT encoding should not fail")
}

pub fn decode_jwt_unsafe(token: &str) -> Result<CertClaims, CertError> {
    let mut validation = Validation::new(Algorithm::EdDSA);
    validation.insecure_disable_signature_validation();
    validation.validate_exp = false;
    validation.validate_nbf = false;

    let token_data: TokenData<CertClaims> =
        decode(token, &DecodingKey::from_secret(&[]), &validation)?;
    Ok(token_data.claims)
}

pub fn decode_and_verify_jwt(
    token: &str,
    issuer_pubkey: &VerifyingKey,
) -> Result<CertClaims, CertError> {
    let mut validation = Validation::new(Algorithm::EdDSA);
    validation.validate_exp = false;
    validation.validate_nbf = false;

    let key = DecodingKey::from_ed_der(&issuer_pubkey.to_bytes());
    let token_data: TokenData<CertClaims> = decode(token, &key, &validation)?;
    Ok(token_data.claims)
}

const MAX_CHAIN_DEPTH: usize = 10;

#[derive(Debug)]
pub struct CertValidator {
    trusted_root_id: DeviceId,
    trusted_root_pubkey: VerifyingKey,
    cache: HashMap<DeviceId, CachedCert>,
}

impl CertValidator {
    pub fn new(root_jwt: &str) -> Result<Self, CertError> {
        let claims = decode_jwt_unsafe(root_jwt)?;

        if !claims.is_self_signed() {
            return Err(CertError::UntrustedRoot);
        }

        let pubkey = claims.verifying_key()?;
        let device_id = claims.device_id()?;

        decode_and_verify_jwt(root_jwt, &pubkey)?;

        let mut cache = HashMap::new();
        cache.insert(
            device_id,
            CachedCert {
                pubkey,
                issuer_id: device_id,
                exp: claims.exp,
            },
        );

        Ok(Self {
            trusted_root_id: device_id,
            trusted_root_pubkey: pubkey,
            cache,
        })
    }

    pub fn cache_cert(&mut self, jwt: &str) -> Result<DeviceId, CertError> {
        let claims = decode_jwt_unsafe(jwt)?;
        let device_id = claims.device_id()?;
        let issuer_id = claims.issuer_id()?;

        let issuer_pubkey = self.get_pubkey(&issuer_id)?;
        decode_and_verify_jwt(jwt, &issuer_pubkey)?;

        self.check_expiry(&claims)?;

        let pubkey = claims.verifying_key()?;
        self.cache.insert(
            device_id,
            CachedCert {
                pubkey,
                issuer_id,
                exp: claims.exp,
            },
        );

        Ok(device_id)
    }

    pub fn validate_cert(&self, jwt: &str) -> Result<CertClaims, CertError> {
        let claims = decode_jwt_unsafe(jwt)?;
        let issuer_id = claims.issuer_id()?;

        self.check_expiry(&claims)?;

        let issuer_pubkey = self.get_pubkey(&issuer_id)?;
        decode_and_verify_jwt(jwt, &issuer_pubkey)?;

        self.verify_chain_to_root(&issuer_id, 0)?;

        Ok(claims)
    }

    pub fn validate_cert_for_device(
        &self,
        jwt: &str,
        expected_device_id: &DeviceId,
    ) -> Result<CertClaims, CertError> {
        let claims = self.validate_cert(jwt)?;
        let cert_device_id = claims.device_id()?;

        if cert_device_id != *expected_device_id {
            return Err(CertError::DeviceIdMismatch {
                cert_id: cert_device_id,
                expected_id: *expected_device_id,
            });
        }

        Ok(claims)
    }

    fn get_pubkey(&self, device_id: &DeviceId) -> Result<VerifyingKey, CertError> {
        if *device_id == self.trusted_root_id {
            return Ok(self.trusted_root_pubkey);
        }

        self.cache
            .get(device_id)
            .map(|c| c.pubkey)
            .ok_or_else(|| CertError::IssuerNotFound(*device_id))
    }

    fn verify_chain_to_root(&self, device_id: &DeviceId, depth: usize) -> Result<(), CertError> {
        if depth > MAX_CHAIN_DEPTH {
            return Err(CertError::ChainTooDeep);
        }

        if *device_id == self.trusted_root_id {
            return Ok(());
        }

        let cached = self
            .cache
            .get(device_id)
            .ok_or_else(|| CertError::IssuerNotFound(*device_id))?;

        let now = Utc::now().timestamp();
        if now > cached.exp {
            return Err(CertError::Expired(Utc.timestamp_opt(cached.exp, 0).unwrap()));
        }

        self.verify_chain_to_root(&cached.issuer_id, depth + 1)
    }

    pub fn check_expiry(&self, claims: &CertClaims) -> Result<(), CertError> {
        let now = Utc::now();

        if now < claims.not_before() {
            return Err(CertError::NotYetValid(claims.not_before()));
        }

        if now > claims.not_after() {
            return Err(CertError::Expired(claims.not_after()));
        }

        Ok(())
    }

    pub fn trusted_root_id(&self) -> &DeviceId {
        &self.trusted_root_id
    }

    pub fn is_cached(&self, device_id: &DeviceId) -> bool {
        *device_id == self.trusted_root_id || self.cache.contains_key(device_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_root() -> (DeviceKeypair, String) {
        let keypair = DeviceKeypair::from_seed(&[1u8; 32]);
        let jwt = create_self_signed_jwt(&keypair, 365);
        (keypair, jwt)
    }

    #[test]
    fn test_self_signed_jwt() {
        let keypair = DeviceKeypair::generate();
        let jwt = create_self_signed_jwt(&keypair, 365);

        let claims = decode_jwt_unsafe(&jwt).unwrap();
        assert_eq!(claims.device_id().unwrap(), keypair.device_id());
        assert!(claims.is_self_signed());
    }

    #[test]
    fn test_self_signed_signature_valid() {
        let keypair = DeviceKeypair::generate();
        let jwt = create_self_signed_jwt(&keypair, 365);

        let result = decode_and_verify_jwt(&jwt, &keypair.public_key());
        assert!(result.is_ok());
    }

    #[test]
    fn test_issued_jwt() {
        let issuer = DeviceKeypair::generate();
        let subject = DeviceKeypair::generate();

        let jwt = issue_jwt(&issuer, subject.device_id(), subject.public_key(), 365);

        let claims = decode_jwt_unsafe(&jwt).unwrap();
        assert_eq!(claims.device_id().unwrap(), subject.device_id());
        assert_eq!(claims.issuer_id().unwrap(), issuer.device_id());
        assert!(!claims.is_self_signed());

        let result = decode_and_verify_jwt(&jwt, &issuer.public_key());
        assert!(result.is_ok());
    }

    #[test]
    fn test_signature_fails_wrong_issuer() {
        let real_issuer = DeviceKeypair::generate();
        let fake_issuer = DeviceKeypair::generate();
        let subject = DeviceKeypair::generate();

        let jwt = issue_jwt(&real_issuer, subject.device_id(), subject.public_key(), 365);

        let result = decode_and_verify_jwt(&jwt, &fake_issuer.public_key());
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_cert_direct_from_root() {
        let (root_keypair, root_jwt) = create_test_root();
        let validator = CertValidator::new(&root_jwt).unwrap();

        let device = DeviceKeypair::generate();
        let device_jwt = issue_jwt(&root_keypair, device.device_id(), device.public_key(), 365);

        let claims = validator.validate_cert(&device_jwt).unwrap();
        assert_eq!(claims.device_id().unwrap(), device.device_id());
    }

    #[test]
    fn test_validate_cert_with_intermediate() {
        let (root_keypair, root_jwt) = create_test_root();
        let mut validator = CertValidator::new(&root_jwt).unwrap();

        let intermediate = DeviceKeypair::generate();
        let intermediate_jwt = issue_jwt(
            &root_keypair,
            intermediate.device_id(),
            intermediate.public_key(),
            365,
        );
        validator.cache_cert(&intermediate_jwt).unwrap();

        let device = DeviceKeypair::generate();
        let device_jwt = issue_jwt(
            &intermediate,
            device.device_id(),
            device.public_key(),
            365,
        );

        let claims = validator.validate_cert(&device_jwt).unwrap();
        assert_eq!(claims.device_id().unwrap(), device.device_id());
    }

    #[test]
    fn test_validate_cert_fails_without_cached_intermediate() {
        let (root_keypair, root_jwt) = create_test_root();
        let validator = CertValidator::new(&root_jwt).unwrap();

        let intermediate = DeviceKeypair::generate();
        let _intermediate_jwt = issue_jwt(
            &root_keypair,
            intermediate.device_id(),
            intermediate.public_key(),
            365,
        );

        let device = DeviceKeypair::generate();
        let device_jwt = issue_jwt(
            &intermediate,
            device.device_id(),
            device.public_key(),
            365,
        );

        let result = validator.validate_cert(&device_jwt);
        assert!(matches!(result, Err(CertError::IssuerNotFound(_))));
    }

    #[test]
    fn test_validate_cert_untrusted_issuer() {
        let (_, root_jwt) = create_test_root();
        let validator = CertValidator::new(&root_jwt).unwrap();

        let untrusted = DeviceKeypair::generate();
        let device = DeviceKeypair::generate();
        let device_jwt = issue_jwt(&untrusted, device.device_id(), device.public_key(), 365);

        let result = validator.validate_cert(&device_jwt);
        assert!(matches!(result, Err(CertError::IssuerNotFound(_))));
    }

    #[test]
    fn test_cache_cert() {
        let (root_keypair, root_jwt) = create_test_root();
        let mut validator = CertValidator::new(&root_jwt).unwrap();

        let device = DeviceKeypair::generate();
        let device_jwt = issue_jwt(&root_keypair, device.device_id(), device.public_key(), 365);

        assert!(!validator.is_cached(&device.device_id()));
        validator.cache_cert(&device_jwt).unwrap();
        assert!(validator.is_cached(&device.device_id()));
    }

    #[test]
    fn test_is_cached() {
        let (_, root_jwt) = create_test_root();
        let validator = CertValidator::new(&root_jwt).unwrap();

        assert!(validator.is_cached(validator.trusted_root_id()));

        let random = DeviceKeypair::generate();
        assert!(!validator.is_cached(&random.device_id()));
    }
}
