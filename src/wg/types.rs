use std::collections::HashMap;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::time::SystemTime;

use crate::wg::error::WgError;

const KEY_LENGTH: usize = 32;

#[derive(Clone, Default)]
pub struct Key([u8; KEY_LENGTH]);

impl Key {
    pub fn new(buf: [u8; KEY_LENGTH]) -> Self {
        Self(buf)
    }

    pub fn as_array(&self) -> [u8; KEY_LENGTH] {
        self.0
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    pub fn to_hex(&self) -> String {
        let mut hex = String::with_capacity(64);
        for byte in &self.0 {
            hex.push_str(&format!("{:02x}", byte));
        }
        hex
    }

    pub fn from_hex(hex: &str) -> Result<Self, WgError> {
        if hex.len() != KEY_LENGTH * 2 {
            return Err(WgError::InvalidKey(format!(
                "expected {} hex chars, got {}",
                KEY_LENGTH * 2,
                hex.len()
            )));
        }

        let mut key = [0u8; KEY_LENGTH];
        for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
            let high = hex_value(chunk[0]).ok_or_else(|| {
                WgError::InvalidKey(format!("invalid hex char at position {}", i * 2))
            })?;
            let low = hex_value(chunk[1]).ok_or_else(|| {
                WgError::InvalidKey(format!("invalid hex char at position {}", i * 2 + 1))
            })?;
            key[i] = (high << 4) | low;
        }
        Ok(Self(key))
    }
}

fn hex_value(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

impl Hash for Key {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

impl PartialEq for Key {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl Eq for Key {}

impl fmt::Debug for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl fmt::Display for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct IpAddrMask {
    pub ip: IpAddr,
    pub cidr: u8,
}

impl IpAddrMask {
    pub fn new(ip: IpAddr, cidr: u8) -> Self {
        Self { ip, cidr }
    }

    pub fn host(ip: IpAddr) -> Self {
        let cidr = match ip {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        Self { ip, cidr }
    }
}

impl fmt::Display for IpAddrMask {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.ip, self.cidr)
    }
}

#[derive(Debug, PartialEq)]
pub struct IpAddrParseError;

impl fmt::Display for IpAddrParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid IP address/mask")
    }
}

impl std::error::Error for IpAddrParseError {}

impl FromStr for IpAddrMask {
    type Err = IpAddrParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some((ip_str, cidr_str)) = s.split_once('/') {
            let ip: IpAddr = ip_str.parse().map_err(|_| IpAddrParseError)?;
            let cidr: u8 = cidr_str.parse().map_err(|_| IpAddrParseError)?;
            let max_cidr = match ip {
                IpAddr::V4(_) => 32,
                IpAddr::V6(_) => 128,
            };
            if cidr > max_cidr {
                return Err(IpAddrParseError);
            }
            Ok(Self { ip, cidr })
        } else {
            let ip: IpAddr = s.parse().map_err(|_| IpAddrParseError)?;
            Ok(Self::host(ip))
        }
    }
}

#[derive(Clone, Default, PartialEq)]
pub struct Peer {
    pub public_key: Key,
    pub preshared_key: Option<Key>,
    pub endpoint: Option<SocketAddr>,
    pub last_handshake: Option<SystemTime>,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub persistent_keepalive_interval: Option<u16>,
    pub allowed_ips: Vec<IpAddrMask>,
}

impl fmt::Debug for Peer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Peer")
            .field("public_key", &self.public_key)
            .field("endpoint", &self.endpoint)
            .field("last_handshake", &self.last_handshake)
            .field("tx_bytes", &self.tx_bytes)
            .field("rx_bytes", &self.rx_bytes)
            .field(
                "persistent_keepalive_interval",
                &self.persistent_keepalive_interval,
            )
            .field("allowed_ips", &self.allowed_ips)
            .finish_non_exhaustive()
    }
}

impl Peer {
    pub fn new(public_key: Key) -> Self {
        Self {
            public_key,
            preshared_key: None,
            endpoint: None,
            last_handshake: None,
            tx_bytes: 0,
            rx_bytes: 0,
            persistent_keepalive_interval: None,
            allowed_ips: Vec::new(),
        }
    }
}

#[derive(Clone, Default)]
pub struct Host {
    pub listen_port: u16,
    pub private_key: Option<Key>,
    pub fwmark: Option<u32>,
    pub peers: HashMap<Key, Peer>,
}

impl fmt::Debug for Host {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Host")
            .field("listen_port", &self.listen_port)
            .field("fwmark", &self.fwmark)
            .field("peers", &self.peers)
            .finish_non_exhaustive()
    }
}

impl Host {
    pub fn new(listen_port: u16, private_key: Key) -> Self {
        Self {
            listen_port,
            private_key: Some(private_key),
            fwmark: None,
            peers: HashMap::new(),
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct PeerStats {
    pub last_handshake: Option<SystemTime>,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn key_from_hex() {
        let hex = "000102030405060708090a0b0c0d0e0ff0e1d2c3b4a5968778695a4b3c2d1e0f";
        let key = Key::from_hex(hex).unwrap();
        assert_eq!(key.to_hex(), hex);
    }

    #[test]
    fn key_from_hex_uppercase() {
        let hex = "000102030405060708090A0B0C0D0E0FF0E1D2C3B4A5968778695A4B3C2D1E0F";
        let key = Key::from_hex(hex).unwrap();
        assert_eq!(key.to_hex(), hex.to_lowercase());
    }

    #[test]
    fn key_from_hex_invalid_length() {
        let result = Key::from_hex("0001");
        assert!(result.is_err());
    }

    #[test]
    fn key_from_hex_invalid_char() {
        let hex = "zz0102030405060708090a0b0c0d0e0ff0e1d2c3b4a5968778695a4b3c2d1e0f";
        let result = Key::from_hex(hex);
        assert!(result.is_err());
    }

    #[test]
    fn key_equality() {
        let key1 = Key::new([1u8; 32]);
        let key2 = Key::new([1u8; 32]);
        let key3 = Key::new([2u8; 32]);
        assert_eq!(key1, key2);
        assert_ne!(key1, key3);
    }

    #[test]
    fn key_hash() {
        use std::collections::HashSet;
        let key1 = Key::new([1u8; 32]);
        let key2 = Key::new([1u8; 32]);
        let mut set = HashSet::new();
        set.insert(key1);
        assert!(set.contains(&key2));
    }

    #[test]
    fn ip_addr_mask_parse_v4() {
        let addr: IpAddrMask = "192.168.1.1/24".parse().unwrap();
        assert_eq!(addr.ip, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
        assert_eq!(addr.cidr, 24);
    }

    #[test]
    fn ip_addr_mask_parse_v4_host() {
        let addr: IpAddrMask = "192.168.1.1".parse().unwrap();
        assert_eq!(addr.cidr, 32);
    }

    #[test]
    fn ip_addr_mask_parse_v6() {
        let addr: IpAddrMask = "fd00::1/64".parse().unwrap();
        assert!(matches!(addr.ip, IpAddr::V6(_)));
        assert_eq!(addr.cidr, 64);
    }

    #[test]
    fn ip_addr_mask_parse_invalid_cidr() {
        let result: Result<IpAddrMask, _> = "192.168.1.1/33".parse();
        assert!(result.is_err());
    }

    #[test]
    fn ip_addr_mask_display() {
        let addr = IpAddrMask::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 8);
        assert_eq!(addr.to_string(), "10.0.0.1/8");
    }

    #[test]
    fn peer_new() {
        let key = Key::new([42u8; 32]);
        let peer = Peer::new(key.clone());
        assert_eq!(peer.public_key, key);
        assert!(peer.preshared_key.is_none());
        assert!(peer.endpoint.is_none());
        assert!(peer.allowed_ips.is_empty());
    }

    #[test]
    fn peer_debug_hides_preshared_key() {
        let mut peer = Peer::new(Key::new([1u8; 32]));
        peer.preshared_key = Some(Key::new([99u8; 32]));
        let debug = format!("{:?}", peer);
        assert!(!debug.contains("preshared_key"));
    }

    #[test]
    fn host_new() {
        let key = Key::new([1u8; 32]);
        let host = Host::new(51820, key.clone());
        assert_eq!(host.listen_port, 51820);
        assert_eq!(host.private_key, Some(key));
        assert!(host.peers.is_empty());
    }

    #[test]
    fn host_debug_hides_private_key() {
        let host = Host::new(51820, Key::new([1u8; 32]));
        let debug = format!("{:?}", host);
        assert!(!debug.contains("private_key"));
    }

    #[test]
    fn peer_stats_default() {
        let stats = PeerStats::default();
        assert!(stats.last_handshake.is_none());
        assert_eq!(stats.rx_bytes, 0);
        assert_eq!(stats.tx_bytes, 0);
    }
}
