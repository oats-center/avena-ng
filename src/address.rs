use crate::identity::DeviceId;
use serde::{Deserialize, Serialize};
use std::net::Ipv6Addr;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NetworkConfig {
    pub prefix: Ipv6Addr,
    pub prefix_len: u8,
}

impl NetworkConfig {
    pub fn new(prefix: Ipv6Addr, prefix_len: u8) -> Self {
        Self { prefix, prefix_len }
    }

    pub fn default_ula() -> Self {
        Self {
            prefix: "fd00:a0e0:a000::".parse().unwrap(),
            prefix_len: 48,
        }
    }

    pub fn device_address(&self, id: &DeviceId) -> Ipv6Addr {
        let prefix_segments = self.prefix.segments();
        let suffix = id.to_ipv6_suffix();

        let seg4 = u16::from_be_bytes([suffix[0], suffix[1]]);
        let seg5 = u16::from_be_bytes([suffix[2], suffix[3]]);
        let seg6 = u16::from_be_bytes([suffix[4], suffix[5]]);
        let seg7 = u16::from_be_bytes([suffix[6], suffix[7]]);

        Ipv6Addr::new(
            prefix_segments[0],
            prefix_segments[1],
            prefix_segments[2],
            seg4,
            seg5,
            seg6,
            seg7,
            1,
        )
    }

    pub fn workload_address(&self, host_id: &DeviceId, workload_idx: u16) -> Ipv6Addr {
        let prefix_segments = self.prefix.segments();
        let suffix = host_id.to_ipv6_suffix();

        let seg4 = u16::from_be_bytes([suffix[0], suffix[1]]);
        let seg5 = u16::from_be_bytes([suffix[2], suffix[3]]);
        let seg6 = u16::from_be_bytes([suffix[4], suffix[5]]);
        let seg7 = u16::from_be_bytes([suffix[6], suffix[7]]);

        Ipv6Addr::new(
            prefix_segments[0],
            prefix_segments[1],
            prefix_segments[2],
            seg4,
            seg5,
            seg6,
            seg7,
            workload_idx.wrapping_add(0x100),
        )
    }

    pub fn is_overlay_address(&self, addr: &Ipv6Addr) -> bool {
        let prefix_segments = self.prefix.segments();
        let addr_segments = addr.segments();

        let prefix_bytes = (self.prefix_len / 16) as usize;

        for i in 0..prefix_bytes {
            if addr_segments[i] != prefix_segments[i] {
                return false;
            }
        }

        let remaining_bits = self.prefix_len % 16;
        if remaining_bits > 0 && prefix_bytes < 8 {
            let mask = 0xFFFF << (16 - remaining_bits);
            if (addr_segments[prefix_bytes] & mask) != (prefix_segments[prefix_bytes] & mask) {
                return false;
            }
        }

        true
    }
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self::default_ula()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::DeviceKeypair;

    #[test]
    fn test_device_address_deterministic() {
        let config = NetworkConfig::default_ula();
        let keypair = DeviceKeypair::from_seed(&[42u8; 32]);
        let id = keypair.device_id();

        let addr1 = config.device_address(&id);
        let addr2 = config.device_address(&id);

        assert_eq!(addr1, addr2);
    }

    #[test]
    fn test_different_devices_different_addresses() {
        let config = NetworkConfig::default_ula();

        let kp1 = DeviceKeypair::from_seed(&[1u8; 32]);
        let kp2 = DeviceKeypair::from_seed(&[2u8; 32]);

        let addr1 = config.device_address(&kp1.device_id());
        let addr2 = config.device_address(&kp2.device_id());

        assert_ne!(addr1, addr2);
    }

    #[test]
    fn test_device_address_in_prefix() {
        let config = NetworkConfig::default_ula();
        let keypair = DeviceKeypair::generate();
        let addr = config.device_address(&keypair.device_id());

        assert!(config.is_overlay_address(&addr));
    }

    #[test]
    fn test_workload_address_differs_from_host() {
        let config = NetworkConfig::default_ula();
        let keypair = DeviceKeypair::generate();
        let id = keypair.device_id();

        let host_addr = config.device_address(&id);
        let workload_addr = config.workload_address(&id, 1);

        assert_ne!(host_addr, workload_addr);
    }

    #[test]
    fn test_different_workloads_different_addresses() {
        let config = NetworkConfig::default_ula();
        let keypair = DeviceKeypair::generate();
        let id = keypair.device_id();

        let addr1 = config.workload_address(&id, 1);
        let addr2 = config.workload_address(&id, 2);

        assert_ne!(addr1, addr2);
    }

    #[test]
    fn test_workload_address_in_prefix() {
        let config = NetworkConfig::default_ula();
        let keypair = DeviceKeypair::generate();
        let addr = config.workload_address(&keypair.device_id(), 1);

        assert!(config.is_overlay_address(&addr));
    }

    #[test]
    fn test_non_overlay_address() {
        let config = NetworkConfig::default_ula();
        let external: Ipv6Addr = "2001:db8::1".parse().unwrap();

        assert!(!config.is_overlay_address(&external));
    }

    #[test]
    fn test_custom_prefix() {
        let prefix: Ipv6Addr = "fd12:3456:7890::".parse().unwrap();
        let config = NetworkConfig::new(prefix, 48);

        let keypair = DeviceKeypair::generate();
        let addr = config.device_address(&keypair.device_id());

        let segments = addr.segments();
        assert_eq!(segments[0], 0xfd12);
        assert_eq!(segments[1], 0x3456);
        assert_eq!(segments[2], 0x7890);
    }

    #[test]
    fn test_serialization() {
        let config = NetworkConfig::default_ula();

        let json = serde_json::to_string(&config).unwrap();
        let deserialized: NetworkConfig = serde_json::from_str(&json).unwrap();

        assert_eq!(config.prefix, deserialized.prefix);
        assert_eq!(config.prefix_len, deserialized.prefix_len);
    }

    #[test]
    fn test_prefix_boundary_48() {
        let config = NetworkConfig::new("fd00:1234:5678::".parse().unwrap(), 48);

        let in_prefix: Ipv6Addr = "fd00:1234:5678:ffff::1".parse().unwrap();
        let out_prefix: Ipv6Addr = "fd00:1234:5679::1".parse().unwrap();

        assert!(config.is_overlay_address(&in_prefix));
        assert!(!config.is_overlay_address(&out_prefix));
    }

    #[test]
    fn test_workload_idx_range() {
        let config = NetworkConfig::default_ula();
        let keypair = DeviceKeypair::generate();
        let id = keypair.device_id();

        let addr_0 = config.workload_address(&id, 0);
        let addr_max = config.workload_address(&id, u16::MAX);

        assert!(config.is_overlay_address(&addr_0));
        assert!(config.is_overlay_address(&addr_max));
        assert_ne!(addr_0, addr_max);
    }
}
