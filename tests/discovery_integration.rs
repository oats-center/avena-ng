use avena_overlay::{
    Capability, DeviceId, DeviceKeypair, DiscoveryConfig, DiscoveryService, LocalAnnouncement,
    StaticPeerConfig,
};
use std::collections::HashSet;
use std::time::Duration;
use tokio::time::timeout;

fn test_keypair(seed: u8) -> DeviceKeypair {
    DeviceKeypair::from_seed(&[seed; 32])
}

fn test_device_id(seed: u8) -> DeviceId {
    test_keypair(seed).device_id()
}

#[tokio::test]
async fn static_peer_resolution() {
    let device1 = test_device_id(1);
    let device2 = test_device_id(2);

    let config = DiscoveryConfig {
        enable_mdns: false,
        mdns_interface: None,
        static_peers: vec![
            StaticPeerConfig::new("127.0.0.1:51820")
                .with_device_id(device1)
                .with_capability(Capability::Gateway),
            StaticPeerConfig::new("127.0.0.1:51821")
                .with_device_id(device2)
                .with_capability(Capability::Relay),
        ],
    };

    let service = DiscoveryService::new(config).expect("should create service");

    let peers = service.resolve_static_peers().await;
    assert_eq!(peers.len(), 2);

    let peer1 = peers.iter().find(|p| p.device_id == device1).unwrap();
    assert!(peer1.has_capability(&Capability::Gateway));
    assert_eq!(peer1.endpoint.port(), 51820);

    let peer2 = peers.iter().find(|p| p.device_id == device2).unwrap();
    assert!(peer2.has_capability(&Capability::Relay));
    assert_eq!(peer2.endpoint.port(), 51821);
}

#[tokio::test]
async fn discovery_service_event_channel() {
    use avena_overlay::DiscoveryEvent;

    let config = DiscoveryConfig {
        enable_mdns: false,
        mdns_interface: None,
        static_peers: vec![],
    };

    let service = DiscoveryService::new(config).expect("should create service");

    let mut rx = service.subscribe();

    let device = test_device_id(42);
    let peer = avena_overlay::DiscoveredPeer::new(
        device,
        "10.0.0.1:51820".parse().unwrap(),
        HashSet::new(),
        avena_overlay::DiscoverySource::Static,
    );

    service
        .emit_event(DiscoveryEvent::PeerDiscovered(peer))
        .expect("should emit event");

    let event = timeout(Duration::from_millis(100), rx.recv())
        .await
        .expect("should receive within timeout")
        .expect("should receive event");

    match event {
        DiscoveryEvent::PeerDiscovered(p) => {
            assert_eq!(p.device_id, device);
        }
        _ => panic!("expected PeerDiscovered event"),
    }
}

#[tokio::test]
async fn mdns_service_creation() {
    let config = DiscoveryConfig {
        enable_mdns: true,
        mdns_interface: None,
        static_peers: vec![],
    };

    let service = DiscoveryService::new(config).expect("should create service with mDNS");
    assert!(service.mdns().is_some());
}

#[tokio::test]
async fn mdns_disabled_service() {
    let config = DiscoveryConfig {
        enable_mdns: false,
        mdns_interface: None,
        static_peers: vec![],
    };

    let service = DiscoveryService::new(config).expect("should create service without mDNS");
    assert!(service.mdns().is_none());
}

#[tokio::test]
#[ignore = "requires network access for mDNS broadcast"]
async fn mdns_advertise_and_browse() {
    let keypair1 = test_keypair(1);

    let config1 = DiscoveryConfig {
        enable_mdns: true,
        mdns_interface: None,
        static_peers: vec![],
    };

    let config2 = DiscoveryConfig {
        enable_mdns: true,
        mdns_interface: None,
        static_peers: vec![],
    };

    let service1 = DiscoveryService::new(config1).expect("should create service1");
    let service2 = DiscoveryService::new(config2).expect("should create service2");

    let mdns2 = service2.mdns().expect("mdns should be enabled");
    let mut rx = mdns2.browse().expect("should start browse");

    tokio::time::sleep(Duration::from_millis(100)).await;

    let mut caps = HashSet::new();
    caps.insert(Capability::Relay);
    caps.insert(Capability::Gateway);

    let announcement = LocalAnnouncement {
        device_id: keypair1.device_id(),
        wg_endpoint: "192.168.1.100:51820".parse().unwrap(),
        capabilities: caps,
    };

    service1
        .announce(&announcement)
        .await
        .expect("should advertise");

    let discovery_result = timeout(Duration::from_secs(3), rx.recv()).await;

    match discovery_result {
        Ok(Some(peer)) => {
            assert_eq!(peer.device_id, keypair1.device_id());
            assert!(peer.has_capability(&Capability::Relay));
            assert!(peer.has_capability(&Capability::Gateway));
        }
        Ok(None) => panic!("browse channel closed unexpectedly"),
        Err(_) => panic!("timeout waiting for mDNS discovery"),
    }
}
