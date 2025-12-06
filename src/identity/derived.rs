use crate::identity::keypair::DeviceKeypair;
use hkdf::Hkdf;
use sha2::Sha256;

const WORKLOAD_DERIVATION_SALT: &[u8] = b"avena-workload-key-derivation-v1";

pub fn derive_workload_keypair(parent: &DeviceKeypair, workload_id: &str) -> DeviceKeypair {
    let parent_seed = parent.to_bytes();
    let hkdf = Hkdf::<Sha256>::new(Some(WORKLOAD_DERIVATION_SALT), &*parent_seed);

    let mut derived_seed = [0u8; 32];
    hkdf.expand(workload_id.as_bytes(), &mut derived_seed)
        .expect("32 bytes is a valid output length for HKDF-SHA256");

    DeviceKeypair::from_seed(&derived_seed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derived_keypair_deterministic() {
        let parent = DeviceKeypair::from_seed(&[42u8; 32]);

        let child1 = derive_workload_keypair(&parent, "workload-a");
        let child2 = derive_workload_keypair(&parent, "workload-a");

        assert_eq!(child1.device_id(), child2.device_id());
    }

    #[test]
    fn test_different_workloads_different_keys() {
        let parent = DeviceKeypair::from_seed(&[42u8; 32]);

        let child1 = derive_workload_keypair(&parent, "workload-a");
        let child2 = derive_workload_keypair(&parent, "workload-b");

        assert_ne!(child1.device_id(), child2.device_id());
    }

    #[test]
    fn test_different_parents_different_keys() {
        let parent1 = DeviceKeypair::from_seed(&[1u8; 32]);
        let parent2 = DeviceKeypair::from_seed(&[2u8; 32]);

        let child1 = derive_workload_keypair(&parent1, "workload-a");
        let child2 = derive_workload_keypair(&parent2, "workload-a");

        assert_ne!(child1.device_id(), child2.device_id());
    }

    #[test]
    fn test_derived_key_independent_of_parent() {
        let parent = DeviceKeypair::from_seed(&[42u8; 32]);
        let child = derive_workload_keypair(&parent, "workload-a");

        assert_ne!(parent.device_id(), child.device_id());
    }

    #[test]
    fn test_derived_keypair_can_sign() {
        let parent = DeviceKeypair::generate();
        let child = derive_workload_keypair(&parent, "signing-workload");

        let message = b"test message";
        let signature = child.sign(message);

        use ed25519_dalek::Verifier;
        assert!(child.public_key().verify(message, &signature).is_ok());
    }

    #[test]
    fn test_nested_derivation() {
        let root = DeviceKeypair::from_seed(&[1u8; 32]);
        let level1 = derive_workload_keypair(&root, "container");
        let level2 = derive_workload_keypair(&level1, "nested-process");

        assert_ne!(root.device_id(), level1.device_id());
        assert_ne!(level1.device_id(), level2.device_id());
        assert_ne!(root.device_id(), level2.device_id());
    }

    #[test]
    fn test_empty_workload_id() {
        let parent = DeviceKeypair::from_seed(&[42u8; 32]);
        let child = derive_workload_keypair(&parent, "");

        assert_ne!(parent.device_id(), child.device_id());
    }

    #[test]
    fn test_long_workload_id() {
        let parent = DeviceKeypair::from_seed(&[42u8; 32]);
        let long_id = "a".repeat(1000);
        let child = derive_workload_keypair(&parent, &long_id);

        assert_ne!(parent.device_id(), child.device_id());
    }
}
