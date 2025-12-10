//! Device identity primitives: Ed25519 keypairs and deterministic IDs.
//!
//! A `DeviceKeypair` is the long-lived root identity; `DeviceId` is a stable
//! hash of its public key and is used throughout addressing and discovery.
//! Workload keypairs can be deterministically derived for sub-identities.

pub mod device_id;
pub mod derived;
pub mod keypair;

pub use device_id::{DecodeError, DeviceId};
pub use derived::derive_workload_keypair;
pub use keypair::DeviceKeypair;
