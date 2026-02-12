//! Tests for concurrent handshake race condition handling.
//!
//! Verifies that when multiple handshakes complete simultaneously for the same
//! peer, only the first result is stored and subsequent duplicates are discarded.

use avena_overlay::{DeviceId, DeviceKeypair, PeerState};
use ed25519_dalek::SigningKey;
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::net::Ipv6Addr;
use std::sync::Arc;
use tokio::sync::RwLock;

fn make_peer_state(
    seed: u8,
    device_id: DeviceId,
    wg_suffix: u8,
    tunnel_interface: &str,
) -> PeerState {
    let signing_key = SigningKey::from_bytes(&[seed; 32]);
    let public_key = signing_key.verifying_key();
    let mut wg_pubkey = [0u8; 32];
    wg_pubkey[0] = wg_suffix;
    let overlay_ip = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, u16::from(seed));

    PeerState::new(
        device_id,
        public_key,
        wg_pubkey,
        overlay_ip,
        tunnel_interface.to_string(),
    )
}

#[tokio::test]
async fn test_concurrent_handshake_does_not_corrupt_peer_state() {
    let peers: Arc<RwLock<HashMap<DeviceId, PeerState>>> = Arc::new(RwLock::new(HashMap::new()));

    let target_keypair = DeviceKeypair::from_seed(&[42u8; 32]);
    let target_id = target_keypair.device_id();

    let num_concurrent = 10;
    let mut handles = Vec::with_capacity(num_concurrent);

    for i in 0..num_concurrent {
        let peers_clone = Arc::clone(&peers);
        let device_id = target_id;

        handles.push(tokio::spawn(async move {
            let peer_state = make_peer_state(i as u8, device_id, i as u8, "av-test");
            let wg_pubkey = peer_state.wg_pubkey;

            let mut peers_guard = peers_clone.write().await;
            let inserted = if let Entry::Vacant(entry) = peers_guard.entry(device_id) {
                entry.insert(peer_state);
                true
            } else {
                false
            };

            (inserted, wg_pubkey)
        }));
    }

    let results: Vec<(bool, [u8; 32])> = futures::future::join_all(handles)
        .await
        .into_iter()
        .map(|r| r.unwrap())
        .collect();

    let insert_count = results.iter().filter(|(inserted, _)| *inserted).count();
    assert_eq!(
        insert_count, 1,
        "Exactly one handshake should succeed, got {insert_count}"
    );

    let peers_guard = peers.read().await;
    assert_eq!(peers_guard.len(), 1, "Should have exactly one peer entry");
    assert!(
        peers_guard.contains_key(&target_id),
        "Peer map should contain the target device ID"
    );

    let stored_peer = peers_guard.get(&target_id).unwrap();
    let winning_wg_key = results
        .iter()
        .find(|(inserted, _)| *inserted)
        .map(|(_, key)| *key)
        .unwrap();

    assert_eq!(
        stored_peer.wg_pubkey, winning_wg_key,
        "Stored peer should have the winning handshake's WG pubkey"
    );
}

#[tokio::test]
async fn test_sequential_handshakes_first_wins() {
    let mut peers: HashMap<DeviceId, PeerState> = HashMap::new();

    let target_keypair = DeviceKeypair::from_seed(&[99u8; 32]);
    let target_id = target_keypair.device_id();

    let first_peer = make_peer_state(1, target_id, 0xAA, "av-test");
    let first_wg_key = first_peer.wg_pubkey;

    if let Entry::Vacant(entry) = peers.entry(target_id) {
        entry.insert(first_peer);
    }
    assert_eq!(peers.len(), 1);

    let second_peer = make_peer_state(2, target_id, 0xBB, "av-test");
    if let Entry::Vacant(entry) = peers.entry(target_id) {
        entry.insert(second_peer);
    }
    assert_eq!(peers.len(), 1, "Second insert should be rejected");

    let stored = peers.get(&target_id).unwrap();
    assert_eq!(
        stored.wg_pubkey, first_wg_key,
        "First peer's WG key should be preserved"
    );
}

#[tokio::test]
async fn test_different_peers_can_connect_concurrently() {
    let peers: Arc<RwLock<HashMap<DeviceId, PeerState>>> = Arc::new(RwLock::new(HashMap::new()));

    let num_peers = 5;
    let mut handles = Vec::with_capacity(num_peers);

    for i in 0..num_peers {
        let peers_clone = Arc::clone(&peers);

        handles.push(tokio::spawn(async move {
            let keypair = DeviceKeypair::from_seed(&[i as u8; 32]);
            let device_id = keypair.device_id();
            let peer_state = make_peer_state(i as u8, device_id, i as u8, "av-test");

            let mut peers_guard = peers_clone.write().await;
            if let Entry::Vacant(entry) = peers_guard.entry(device_id) {
                entry.insert(peer_state);
                true
            } else {
                false
            }
        }));
    }

    let results: Vec<bool> = futures::future::join_all(handles)
        .await
        .into_iter()
        .map(|r| r.unwrap())
        .collect();

    let insert_count = results.iter().filter(|&&inserted| inserted).count();
    assert_eq!(
        insert_count, num_peers,
        "All different peers should be inserted"
    );

    let peers_guard = peers.read().await;
    assert_eq!(
        peers_guard.len(),
        num_peers,
        "Should have all {num_peers} peers"
    );
}

#[tokio::test]
async fn test_same_peer_can_hold_multiple_underlay_tunnels() {
    let mut peers: HashMap<String, PeerState> = HashMap::new();

    let target_keypair = DeviceKeypair::from_seed(&[55u8; 32]);
    let target_id = target_keypair.device_id();

    let wifi_tunnel = make_peer_state(1, target_id, 0xA1, "av-wifi01");
    let cell_tunnel = make_peer_state(2, target_id, 0xB2, "av-cell02");

    if let Entry::Vacant(entry) = peers.entry(wifi_tunnel.tunnel_interface.clone()) {
        entry.insert(wifi_tunnel);
    }
    if let Entry::Vacant(entry) = peers.entry(cell_tunnel.tunnel_interface.clone()) {
        entry.insert(cell_tunnel);
    }

    assert_eq!(peers.len(), 2, "same peer should keep both tunnels");
    assert!(peers.contains_key("av-wifi01"));
    assert!(peers.contains_key("av-cell02"));
    assert!(peers.values().all(|state| state.device_id == target_id));
}
