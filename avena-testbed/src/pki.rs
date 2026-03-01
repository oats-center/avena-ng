use avena_overlay::{create_self_signed_jwt, issue_jwt, DeviceKeypair};
use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use tempfile::TempDir;
use thiserror::Error;

use crate::scenario::NodeConfig;

#[derive(Error, Debug)]
pub enum PkiError {
    #[error("failed to write PKI files: {0}")]
    Io(#[from] std::io::Error),
}

pub struct NodePaths {
    pub key_path: PathBuf,
    pub cert_path: PathBuf,
    pub root_cert_path: PathBuf,
}

impl std::fmt::Debug for NodePaths {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodePaths")
            .field("key_path", &self.key_path)
            .field("cert_path", &self.cert_path)
            .field("root_cert_path", &self.root_cert_path)
            .finish()
    }
}

#[expect(missing_debug_implementations, reason = "contains secret CA key")]
pub struct TestPki {
    ca_keypair: DeviceKeypair,
    root_jwt: String,
    node_keypairs: HashMap<String, DeviceKeypair>,
    node_jwts: HashMap<String, String>,
    temp_dir: TempDir,
}

impl TestPki {
    const VALIDITY_DAYS: i64 = 1;

    pub fn generate(nodes: &[NodeConfig]) -> Result<Self, PkiError> {
        let temp_dir = TempDir::new()?;

        let ca_keypair = DeviceKeypair::generate();
        let root_jwt = create_self_signed_jwt(&ca_keypair, Self::VALIDITY_DAYS);

        let mut node_keypairs = HashMap::new();
        let mut node_jwts = HashMap::new();

        for node in nodes {
            let node_keypair = DeviceKeypair::generate();
            let node_jwt = issue_jwt(
                &ca_keypair,
                node_keypair.device_id(),
                node_keypair.public_key(),
                Self::VALIDITY_DAYS,
            );
            node_keypairs.insert(node.id.clone(), node_keypair);
            node_jwts.insert(node.id.clone(), node_jwt);
        }

        Ok(Self {
            ca_keypair,
            root_jwt,
            node_keypairs,
            node_jwts,
            temp_dir,
        })
    }

    pub fn write_node_files(&self, node_id: &str) -> Result<NodePaths, PkiError> {
        let node_dir = self.temp_dir.path().join(node_id);
        std::fs::create_dir_all(&node_dir)?;

        let key_path = node_dir.join("device.key");
        let cert_path = node_dir.join("device.jwt");
        let root_cert_path = node_dir.join("root.jwt");

        let keypair = self
            .node_keypairs
            .get(node_id)
            .expect("node should exist in PKI");

        let mut key_file = std::fs::File::create(&key_path)?;
        key_file.write_all(&keypair.to_bytes()[..])?;

        let jwt = self.node_jwts.get(node_id).expect("node should have JWT");
        std::fs::write(&cert_path, jwt)?;
        std::fs::write(&root_cert_path, &self.root_jwt)?;

        Ok(NodePaths {
            key_path,
            cert_path,
            root_cert_path,
        })
    }

    pub fn root_jwt(&self) -> &str {
        &self.root_jwt
    }

    pub fn node_keypair(&self, node_id: &str) -> Option<&DeviceKeypair> {
        self.node_keypairs.get(node_id)
    }

    pub fn temp_dir(&self) -> &Path {
        self.temp_dir.path()
    }

    pub fn ca_keypair(&self) -> &DeviceKeypair {
        &self.ca_keypair
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use avena_overlay::CertValidator;

    fn test_nodes() -> Vec<NodeConfig> {
        vec![
            NodeConfig {
                id: "gateway".into(),
                capabilities: vec!["relay".into()],
                mobility_trace: None,
                position: None,
                radio_profile: None,
                radios: vec![],
                start_delay_secs: None,
            },
            NodeConfig {
                id: "sensor".into(),
                capabilities: vec![],
                mobility_trace: None,
                position: None,
                radio_profile: None,
                radios: vec![],
                start_delay_secs: None,
            },
        ]
    }

    #[test]
    fn test_generate_pki() {
        let nodes = test_nodes();
        let pki = TestPki::generate(&nodes).unwrap();

        assert!(pki.node_keypair("gateway").is_some());
        assert!(pki.node_keypair("sensor").is_some());
        assert!(pki.node_keypair("unknown").is_none());
    }

    #[test]
    fn test_certificates_validate() {
        let nodes = test_nodes();
        let pki = TestPki::generate(&nodes).unwrap();

        let validator = CertValidator::new(pki.root_jwt()).unwrap();

        let gateway_jwt = pki.node_jwts.get("gateway").unwrap();
        let claims = validator.validate_cert(gateway_jwt).unwrap();

        let expected_id = pki.node_keypair("gateway").unwrap().device_id();
        assert_eq!(claims.device_id().unwrap(), expected_id);
    }

    #[test]
    fn test_write_node_files() {
        let nodes = test_nodes();
        let pki = TestPki::generate(&nodes).unwrap();

        let paths = pki.write_node_files("gateway").unwrap();

        assert!(paths.key_path.exists());
        assert!(paths.cert_path.exists());
        assert!(paths.root_cert_path.exists());

        let key_bytes = std::fs::read(&paths.key_path).unwrap();
        assert_eq!(key_bytes.len(), 32);
    }
}
