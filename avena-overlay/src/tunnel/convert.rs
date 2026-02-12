use crate::tunnel::backend::PeerConfig;
use crate::wg::{IpAddrMask, Key, Peer as WgPeer};

pub(crate) fn peer_config_to_wg_peer(config: &PeerConfig) -> WgPeer {
    let pubkey = Key::new(config.wireguard_pubkey);
    let mut peer = WgPeer::new(pubkey);

    if let Some(psk) = &config.psk {
        peer.preshared_key = Some(Key::new(*psk));
    }

    if let Some(endpoint) = config.endpoint {
        peer.endpoint = Some(endpoint);
    }

    if let Some(keepalive) = config.persistent_keepalive {
        peer.persistent_keepalive_interval = Some(keepalive);
    }

    for ip in &config.allowed_ips {
        peer.allowed_ips
            .push(IpAddrMask::new(ip.addr(), ip.prefix_len()));
    }

    peer
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tunnel::backend::PeerConfig;
    use std::net::SocketAddr;

    #[test]
    fn peer_config_to_wg_peer_minimal() {
        let pubkey = [42u8; 32];
        let config = PeerConfig::new(pubkey);
        let peer = peer_config_to_wg_peer(&config);

        assert_eq!(peer.public_key.as_array(), pubkey);
        assert!(peer.preshared_key.is_none());
        assert!(peer.endpoint.is_none());
        assert!(peer.persistent_keepalive_interval.is_none());
        assert!(peer.allowed_ips.is_empty());
    }

    #[test]
    fn peer_config_to_wg_peer_full() {
        let pubkey = [42u8; 32];
        let psk = [99u8; 32];
        let endpoint: SocketAddr = "[::1]:51820".parse().unwrap();
        let allowed: ipnet::IpNet = "fd00::/64".parse().unwrap();

        let config = PeerConfig::new(pubkey)
            .with_psk(psk)
            .with_endpoint(endpoint)
            .with_allowed_ips(vec![allowed])
            .with_keepalive(25);

        let peer = peer_config_to_wg_peer(&config);

        assert_eq!(peer.public_key.as_array(), pubkey);
        assert_eq!(peer.preshared_key.as_ref().unwrap().as_array(), psk);
        assert_eq!(peer.endpoint, Some(endpoint));
        assert_eq!(peer.persistent_keepalive_interval, Some(25));
        assert_eq!(peer.allowed_ips.len(), 1);
    }
}
