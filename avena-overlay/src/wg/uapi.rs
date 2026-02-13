//! Helpers to serialize/deserialize WireGuard state with the kernel UAPI.
//!
//! Converts the Rust wrappers into the textual UAPI format and back.

use std::io::{BufRead, BufReader, Read};
use std::net::SocketAddr;
use std::str::FromStr;
use std::time::{Duration, SystemTime};

use crate::wg::error::WgError;
use crate::wg::types::{Host, IpAddrMask, Key, Peer};

impl Host {
    pub fn as_uapi(&self) -> String {
        let mut output = format!("listen_port={}\n", self.listen_port);
        if let Some(key) = &self.private_key {
            output.push_str("private_key=");
            output.push_str(&key.to_hex());
            output.push('\n');
        }
        if let Some(fwmark) = self.fwmark {
            output.push_str("fwmark=");
            output.push_str(&fwmark.to_string());
            output.push('\n');
        }
        output.push_str("replace_peers=true\n");
        for peer in self.peers.values() {
            output.push_str(&peer.as_uapi_update());
        }
        output
    }

    pub fn parse_uapi<R: Read>(reader: R) -> Result<Self, WgError> {
        let buf_reader = BufReader::new(reader);
        let mut host = Host::default();
        let mut current_peer: Option<Peer> = None;

        for line_result in buf_reader.lines() {
            let line = line_result?;
            if let Some((keyword, value)) = line.split_once('=') {
                match keyword {
                    "listen_port" => {
                        host.listen_port = value.parse().unwrap_or_default();
                    }
                    "fwmark" => {
                        host.fwmark = value.parse().ok();
                    }
                    "private_key" => {
                        host.private_key = Key::from_hex(value).ok();
                    }
                    "public_key" => {
                        if let Some(peer) = current_peer.take() {
                            host.peers.insert(peer.public_key.clone(), peer);
                        }
                        if let Ok(key) = Key::from_hex(value) {
                            current_peer = Some(Peer::new(key));
                        }
                    }
                    "preshared_key" => {
                        if let Some(ref mut peer) = current_peer {
                            peer.preshared_key = Key::from_hex(value).ok();
                        }
                    }
                    "endpoint" => {
                        if let Some(ref mut peer) = current_peer {
                            peer.endpoint = SocketAddr::from_str(value).ok();
                        }
                    }
                    "persistent_keepalive_interval" => {
                        if let Some(ref mut peer) = current_peer {
                            peer.persistent_keepalive_interval = value.parse().ok();
                        }
                    }
                    "allowed_ip" => {
                        if let Some(ref mut peer) = current_peer {
                            if let Ok(addr) = value.parse::<IpAddrMask>() {
                                peer.allowed_ips.push(addr);
                            }
                        }
                    }
                    "last_handshake_time_sec" => {
                        if let Some(ref mut peer) = current_peer {
                            let sec: u64 = value.parse().unwrap_or_default();
                            if sec > 0 {
                                let nanos = peer
                                    .last_handshake
                                    .and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok())
                                    .map(|d| d.subsec_nanos())
                                    .unwrap_or(0);
                                peer.last_handshake = Some(
                                    SystemTime::UNIX_EPOCH
                                        + Duration::from_secs(sec)
                                        + Duration::from_nanos(nanos as u64),
                                );
                            }
                        }
                    }
                    "last_handshake_time_nsec" => {
                        if let Some(ref mut peer) = current_peer {
                            let nsec: u64 = value.parse().unwrap_or_default();
                            if nsec > 0 {
                                let sec = peer
                                    .last_handshake
                                    .and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok())
                                    .map(|d| d.as_secs())
                                    .unwrap_or(0);
                                peer.last_handshake = Some(
                                    SystemTime::UNIX_EPOCH
                                        + Duration::from_secs(sec)
                                        + Duration::from_nanos(nsec),
                                );
                            }
                        }
                    }
                    "rx_bytes" => {
                        if let Some(ref mut peer) = current_peer {
                            peer.rx_bytes = value.parse().unwrap_or_default();
                        }
                    }
                    "tx_bytes" => {
                        if let Some(ref mut peer) = current_peer {
                            peer.tx_bytes = value.parse().unwrap_or_default();
                        }
                    }
                    "errno" => {
                        if let Ok(errno) = value.parse::<u32>() {
                            if errno == 0 {
                                break;
                            }
                        }
                        return Err(WgError::UapiError(format!("errno={}", value)));
                    }
                    _ => {}
                }
            }
        }

        if let Some(peer) = current_peer {
            host.peers.insert(peer.public_key.clone(), peer);
        }

        Ok(host)
    }
}

impl Peer {
    pub fn as_uapi_update(&self) -> String {
        let mut output = format!("public_key={}\n", self.public_key.to_hex());
        if let Some(key) = &self.preshared_key {
            output.push_str("preshared_key=");
            output.push_str(&key.to_hex());
            output.push('\n');
        }
        if let Some(endpoint) = &self.endpoint {
            output.push_str("endpoint=");
            output.push_str(&endpoint.to_string());
            output.push('\n');
        }
        if let Some(interval) = self.persistent_keepalive_interval {
            output.push_str("persistent_keepalive_interval=");
            output.push_str(&interval.to_string());
            output.push('\n');
        }
        output.push_str("replace_allowed_ips=true\n");
        for allowed_ip in &self.allowed_ips {
            output.push_str("allowed_ip=");
            output.push_str(&allowed_ip.to_string());
            output.push('\n');
        }
        output
    }

    pub fn as_uapi_remove(&self) -> String {
        format!("public_key={}\nremove=true\n", self.public_key.to_hex())
    }
}

pub fn parse_errno<R: Read>(reader: R) -> u32 {
    let buf_reader = BufReader::new(reader);
    for line in buf_reader.lines().flatten() {
        if let Some((keyword, value)) = line.split_once('=') {
            if keyword == "errno" {
                return value.parse().unwrap_or(0);
            }
        }
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn host_as_uapi() {
        let key_hex = "000102030405060708090a0b0c0d0e0ff0e1d2c3b4a5968778695a4b3c2d1e0f";
        let key = Key::from_hex(key_hex).unwrap();
        let host = Host::new(12345, key);

        let uapi = host.as_uapi();
        assert!(uapi.contains("listen_port=12345"));
        assert!(uapi.contains(&format!("private_key={}", key_hex)));
        assert!(uapi.contains("replace_peers=true"));
    }

    #[test]
    fn peer_as_uapi_update() {
        let key_hex = "000102030405060708090a0b0c0d0e0ff0e1d2c3b4a5968778695a4b3c2d1e0f";
        let key = Key::from_hex(key_hex).unwrap();
        let peer = Peer::new(key);

        let uapi = peer.as_uapi_update();
        assert!(uapi.contains(&format!("public_key={}", key_hex)));
        assert!(uapi.contains("replace_allowed_ips=true"));
    }

    #[test]
    fn peer_as_uapi_update_with_all_fields() {
        let key = Key::from_hex("000102030405060708090a0b0c0d0e0ff0e1d2c3b4a5968778695a4b3c2d1e0f")
            .unwrap();
        let psk = Key::from_hex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
            .unwrap();

        let mut peer = Peer::new(key);
        peer.preshared_key = Some(psk);
        peer.endpoint = Some("192.168.1.1:51820".parse().unwrap());
        peer.persistent_keepalive_interval = Some(25);
        peer.allowed_ips.push("10.0.0.0/8".parse().unwrap());
        peer.allowed_ips.push("fd00::1/128".parse().unwrap());

        let uapi = peer.as_uapi_update();
        assert!(uapi.contains("preshared_key="));
        assert!(uapi.contains("endpoint=192.168.1.1:51820"));
        assert!(uapi.contains("persistent_keepalive_interval=25"));
        assert!(uapi.contains("allowed_ip=10.0.0.0/8"));
        assert!(uapi.contains("allowed_ip=fd00::1/128"));
    }

    #[test]
    fn peer_as_uapi_remove() {
        let key_hex = "000102030405060708090a0b0c0d0e0ff0e1d2c3b4a5968778695a4b3c2d1e0f";
        let key = Key::from_hex(key_hex).unwrap();
        let peer = Peer::new(key);

        let uapi = peer.as_uapi_remove();
        assert!(uapi.contains(&format!("public_key={}", key_hex)));
        assert!(uapi.contains("remove=true"));
    }

    #[test]
    fn parse_uapi_host() {
        let uapi_output =
            b"private_key=000102030405060708090a0b0c0d0e0ff0e1d2c3b4a5968778695a4b3c2d1e0f\n\
            listen_port=7301\n\
            public_key=100102030405060708090a0b0c0d0e0ff0e1d2c3b4a5968778695a4b3c2d1e0f\n\
            preshared_key=0000000000000000000000000000000000000000000000000000000000000000\n\
            last_handshake_time_sec=0\n\
            last_handshake_time_nsec=0\n\
            tx_bytes=0\n\
            rx_bytes=0\n\
            persistent_keepalive_interval=0\n\
            allowed_ip=10.6.0.12/32\n\
            public_key=200102030405060708090a0b0c0d0e0ff0e1d2c3b4a5968778695a4b3c2d1e0f\n\
            endpoint=83.11.218.160:51421\n\
            last_handshake_time_sec=1654631933\n\
            last_handshake_time_nsec=862977251\n\
            tx_bytes=52759980\n\
            rx_bytes=3683056\n\
            allowed_ip=10.6.0.25/32\n\
            errno=0\n";

        let cursor = Cursor::new(uapi_output);
        let host = Host::parse_uapi(cursor).unwrap();

        assert_eq!(host.listen_port, 7301);
        assert!(host.private_key.is_some());
        assert_eq!(host.peers.len(), 2);

        let peer1_key =
            Key::from_hex("100102030405060708090a0b0c0d0e0ff0e1d2c3b4a5968778695a4b3c2d1e0f")
                .unwrap();
        let peer1 = host.peers.get(&peer1_key).unwrap();
        assert_eq!(peer1.allowed_ips.len(), 1);
        assert!(peer1.preshared_key.is_some());
        assert!(peer1.last_handshake.is_none());

        let peer2_key =
            Key::from_hex("200102030405060708090a0b0c0d0e0ff0e1d2c3b4a5968778695a4b3c2d1e0f")
                .unwrap();
        let peer2 = host.peers.get(&peer2_key).unwrap();
        assert!(peer2.endpoint.is_some());
        assert_eq!(peer2.tx_bytes, 52_759_980);
        assert_eq!(peer2.rx_bytes, 3_683_056);
        assert!(peer2.last_handshake.is_some());
    }

    #[test]
    fn parse_uapi_errno_error() {
        let uapi_output = b"errno=1\n";
        let cursor = Cursor::new(uapi_output);
        let result = Host::parse_uapi(cursor);
        assert!(result.is_err());
    }

    #[test]
    fn parse_errno_success() {
        let buf = Cursor::new(b"errno=0\n");
        assert_eq!(parse_errno(buf), 0);
    }

    #[test]
    fn parse_errno_nonzero() {
        let buf = Cursor::new(b"errno=12345\n");
        assert_eq!(parse_errno(buf), 12345);
    }

    #[test]
    fn roundtrip_host_uapi() {
        let priv_key =
            Key::from_hex("000102030405060708090a0b0c0d0e0ff0e1d2c3b4a5968778695a4b3c2d1e0f")
                .unwrap();
        let mut host = Host::new(51820, priv_key);
        host.fwmark = Some(1234);

        let pub_key =
            Key::from_hex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
                .unwrap();
        let mut peer = Peer::new(pub_key.clone());
        peer.allowed_ips.push("10.0.0.1/32".parse().unwrap());
        peer.persistent_keepalive_interval = Some(25);
        host.peers.insert(pub_key, peer);

        let uapi = host.as_uapi();

        let uapi_with_errno = format!("{}errno=0\n", uapi);
        let cursor = Cursor::new(uapi_with_errno.as_bytes());
        let parsed = Host::parse_uapi(cursor).unwrap();

        assert_eq!(parsed.listen_port, host.listen_port);
        assert_eq!(parsed.private_key, host.private_key);
        assert_eq!(parsed.peers.len(), 1);
    }
}
