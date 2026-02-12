use avena_overlay::{
    create_self_signed_jwt, derive_wireguard_keypair, issue_jwt, CertValidator, DeviceKeypair,
    EphemeralKeypair, HandshakeMessage,
};

fn create_test_ca() -> (DeviceKeypair, String) {
    let ca = DeviceKeypair::from_seed(&[99u8; 32]);
    let jwt = create_self_signed_jwt(&ca, 365);
    (ca, jwt)
}

fn create_device_cert(ca: &DeviceKeypair, device: &DeviceKeypair) -> String {
    issue_jwt(ca, device.device_id(), device.public_key(), 365)
}

#[test]
fn three_node_interface_key_stability() {
    let (ca, root_jwt) = create_test_ca();
    let validator = CertValidator::new(&root_jwt).unwrap();

    let local_device = DeviceKeypair::from_seed(&[1u8; 32]);
    let peer_b = DeviceKeypair::from_seed(&[2u8; 32]);
    let peer_c = DeviceKeypair::from_seed(&[3u8; 32]);

    let local_wg = derive_wireguard_keypair(&local_device);
    let local_cert = create_device_cert(&ca, &local_device);

    let msg_to_b = HandshakeMessage::create(
        &local_device,
        &EphemeralKeypair::from_seed([10u8; 32]),
        &peer_b.device_id(),
        local_wg.public,
        51820,
        &local_cert,
    );
    assert!(msg_to_b
        .verify(&local_device.public_key(), &peer_b.device_id(), &validator)
        .is_ok());

    let msg_to_c = HandshakeMessage::create(
        &local_device,
        &EphemeralKeypair::from_seed([11u8; 32]),
        &peer_c.device_id(),
        local_wg.public,
        51820,
        &local_cert,
    );
    assert!(msg_to_c
        .verify(&local_device.public_key(), &peer_c.device_id(), &validator)
        .is_ok());

    assert_eq!(msg_to_b.wg_pubkey, local_wg.public);
    assert_eq!(msg_to_c.wg_pubkey, local_wg.public);
    assert_eq!(
        msg_to_b.wg_pubkey, msg_to_c.wg_pubkey,
        "wireguard interface key rotated between peer connections"
    );
}
