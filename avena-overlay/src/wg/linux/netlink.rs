//! Netlink serialization helpers for configuring WireGuard on Linux.

use std::fmt::Debug;
use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use netlink_packet_core::{
    NetlinkDeserializable, NetlinkMessage, NetlinkPayload, NetlinkSerializable, NLM_F_ACK,
    NLM_F_CREATE, NLM_F_DUMP, NLM_F_EXCL, NLM_F_REQUEST,
};
use netlink_packet_generic::{
    ctrl::{nlas::GenlCtrlAttrs, GenlCtrl, GenlCtrlCmd},
    GenlFamily, GenlMessage,
};
use netlink_packet_route::{
    address::{AddressAttribute, AddressMessage},
    link::{InfoKind, LinkAttribute, LinkFlags, LinkInfo, LinkMessage},
    route::{RouteAttribute, RouteMessage, RouteProtocol, RouteScope, RouteType},
    AddressFamily, RouteNetlinkMessage,
};
use netlink_packet_wireguard::{
    constants::{WGDEVICE_F_REPLACE_PEERS, WGPEER_F_REMOVE_ME, WGPEER_F_REPLACE_ALLOWEDIPS},
    nlas::{WgAllowedIp, WgAllowedIpAttrs, WgDeviceAttrs, WgPeer, WgPeerAttrs},
    Wireguard, WireguardCmd,
};
use netlink_sys::{constants::NETLINK_GENERIC, constants::NETLINK_ROUTE, Socket, SocketAddr};

use crate::wg::error::WgError;
use crate::wg::types::{Host, IpAddrMask, Key, Peer};

const SOCKET_BUFFER_LENGTH: usize = 12288;
const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;

fn netlink_request<I>(
    message: I,
    flags: u16,
    protocol: isize,
) -> Result<Vec<NetlinkMessage<I>>, WgError>
where
    NetlinkPayload<I>: From<I>,
    I: Clone + Debug + Eq + NetlinkSerializable + NetlinkDeserializable,
{
    let mut req = NetlinkMessage::from(message);
    req.header.flags = flags;
    req.finalize();

    let len = req.buffer_len();
    let mut buf = vec![0u8; len];
    req.serialize(&mut buf);

    let mut socket = Socket::new(protocol).map_err(|e| WgError::NetlinkError(e.to_string()))?;
    // Bind to get an auto-assigned port ID (required for proper responses in user namespaces)
    let local_addr = SocketAddr::new(0, 0);
    socket
        .bind(&local_addr)
        .map_err(|e| WgError::NetlinkError(format!("bind failed: {}", e)))?;
    let kernel_addr = SocketAddr::new(0, 0);
    socket
        .connect(&kernel_addr)
        .map_err(|e| WgError::NetlinkError(e.to_string()))?;

    let n_sent = socket
        .send(&buf, 0)
        .map_err(|e| WgError::NetlinkError(format!("send failed: {}", e)))?;

    if n_sent != len {
        return Err(WgError::NetlinkError(format!(
            "partial send: sent {} of {} bytes",
            n_sent, len
        )));
    }

    let mut responses = Vec::new();
    loop {
        let mut recv_buf = Vec::with_capacity(SOCKET_BUFFER_LENGTH);
        let n_received = socket
            .recv(&mut recv_buf, 0)
            .map_err(|e| WgError::NetlinkError(e.to_string()))?;

        if n_received == 0 {
            return Ok(responses);
        }

        let mut offset = 0;
        loop {
            if offset >= n_received {
                break;
            }

            let remaining = n_received - offset;
            if remaining < 16 {
                break;
            }

            let response = NetlinkMessage::<I>::deserialize(&recv_buf[offset..n_received])
                .map_err(|e| {
                    WgError::NetlinkError(format!(
                        "{} (offset={}, n_received={}, first_bytes={:02x?})",
                        e,
                        offset,
                        n_received,
                        &recv_buf[offset..std::cmp::min(offset + 16, n_received)]
                    ))
                })?;

            match &response.payload {
                NetlinkPayload::Error(msg) if msg.code.is_none() => return Ok(responses),
                NetlinkPayload::Done(_) => return Ok(responses),
                NetlinkPayload::Error(msg) => {
                    return match msg.to_io().kind() {
                        ErrorKind::AlreadyExists => Ok(responses),
                        ErrorKind::NotFound => Err(WgError::InterfaceNotFound("not found".into())),
                        ErrorKind::PermissionDenied => {
                            Err(WgError::PermissionDenied("operation not permitted".into()))
                        }
                        _ => Err(WgError::NetlinkError(format!("netlink error: {:?}", msg))),
                    };
                }
                _ => {}
            }

            let header_length = response.header.length as usize;
            offset += header_length;
            responses.push(response);

            if offset >= n_received || header_length == 0 {
                break;
            }
        }
    }
}

fn netlink_request_genl<F>(
    mut message: GenlMessage<F>,
    flags: u16,
) -> Result<Vec<NetlinkMessage<GenlMessage<F>>>, WgError>
where
    F: GenlFamily + Clone + Debug + Eq,
    GenlMessage<F>: Clone + Debug + Eq + NetlinkSerializable + NetlinkDeserializable,
{
    if message.family_id() == 0 {
        let genlmsg: GenlMessage<GenlCtrl> = GenlMessage::from_payload(GenlCtrl {
            cmd: GenlCtrlCmd::GetFamily,
            nlas: vec![GenlCtrlAttrs::FamilyName(F::family_name().to_string())],
        });

        let responses = netlink_request_genl::<GenlCtrl>(genlmsg, NLM_F_REQUEST | NLM_F_ACK)?;

        match responses.first() {
            Some(NetlinkMessage {
                payload:
                    NetlinkPayload::InnerMessage(GenlMessage {
                        payload: GenlCtrl { nlas, .. },
                        ..
                    }),
                ..
            }) => {
                let family_id = nlas
                    .iter()
                    .find_map(|attr| match attr {
                        GenlCtrlAttrs::FamilyId(id) => Some(id),
                        _ => None,
                    })
                    .ok_or_else(|| WgError::NetlinkError("family id not found".into()))?;
                message.set_resolved_family_id(*family_id);
            }
            _ => return Err(WgError::NetlinkError("unexpected genl response".into())),
        }
    }
    netlink_request(message, flags, NETLINK_GENERIC)
}

pub fn create_interface(ifname: &str) -> Result<(), WgError> {
    let mut message = LinkMessage::default();
    message.header.flags = LinkFlags::Up;
    message.header.change_mask = LinkFlags::Up;
    message
        .attributes
        .push(LinkAttribute::IfName(ifname.into()));
    message
        .attributes
        .push(LinkAttribute::LinkInfo(vec![LinkInfo::Kind(
            InfoKind::Wireguard,
        )]));

    netlink_request(
        RouteNetlinkMessage::NewLink(message),
        NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
        NETLINK_ROUTE,
    )?;
    Ok(())
}

pub fn delete_interface(ifname: &str) -> Result<(), WgError> {
    let mut message = LinkMessage::default();
    message
        .attributes
        .push(LinkAttribute::IfName(ifname.into()));
    message
        .attributes
        .push(LinkAttribute::LinkInfo(vec![LinkInfo::Kind(
            InfoKind::Wireguard,
        )]));

    netlink_request(
        RouteNetlinkMessage::DelLink(message),
        NLM_F_REQUEST | NLM_F_ACK,
        NETLINK_ROUTE,
    )?;
    Ok(())
}

pub fn get_host(ifname: &str) -> Result<Host, WgError> {
    let genlmsg = GenlMessage::from_payload(Wireguard {
        cmd: WireguardCmd::GetDevice,
        nlas: vec![WgDeviceAttrs::IfName(ifname.into())],
    });

    let responses = netlink_request_genl(genlmsg, NLM_F_REQUEST | NLM_F_DUMP)?;

    let mut host = Host::default();
    for nlmsg in responses {
        if let NetlinkMessage {
            payload: NetlinkPayload::InnerMessage(ref message),
            ..
        } = nlmsg
        {
            append_host_nlas(&mut host, &message.payload.nlas);
        }
    }

    Ok(host)
}

fn append_host_nlas(host: &mut Host, nlas: &[WgDeviceAttrs]) {
    for nla in nlas {
        match nla {
            WgDeviceAttrs::PrivateKey(value) => host.private_key = Some(Key::new(*value)),
            WgDeviceAttrs::ListenPort(value) => host.listen_port = *value,
            WgDeviceAttrs::Fwmark(value) => host.fwmark = Some(*value),
            WgDeviceAttrs::Peers(peer_nlas) => {
                for peer_nla in peer_nlas {
                    let peer = peer_from_nlas(peer_nla);
                    host.peers.insert(peer.public_key.clone(), peer);
                }
            }
            _ => {}
        }
    }
}

fn peer_from_nlas(nlas: &WgPeer) -> Peer {
    let mut peer = Peer::default();

    for nla in &nlas.0 {
        match nla {
            WgPeerAttrs::PublicKey(value) => peer.public_key = Key::new(*value),
            WgPeerAttrs::PresharedKey(value) => peer.preshared_key = Some(Key::new(*value)),
            WgPeerAttrs::Endpoint(value) => peer.endpoint = Some(*value),
            WgPeerAttrs::PersistentKeepalive(value) => {
                peer.persistent_keepalive_interval = Some(*value);
            }
            WgPeerAttrs::LastHandshake(value) => peer.last_handshake = Some(*value),
            WgPeerAttrs::RxBytes(value) => peer.rx_bytes = *value,
            WgPeerAttrs::TxBytes(value) => peer.tx_bytes = *value,
            WgPeerAttrs::AllowedIps(ip_nlas) => {
                for ip_nla in ip_nlas {
                    if let Some(addr) = ip_addr_mask_from_nlas(ip_nla) {
                        peer.allowed_ips.push(addr);
                    }
                }
            }
            _ => {}
        }
    }

    peer
}

fn ip_addr_mask_from_nlas(nlas: &WgAllowedIp) -> Option<IpAddrMask> {
    let mut ip = None;
    let mut cidr = None;

    for nla in &nlas.0 {
        match nla {
            WgAllowedIpAttrs::IpAddr(addr) => ip = Some(*addr),
            WgAllowedIpAttrs::Cidr(c) => cidr = Some(*c),
            _ => {}
        }
    }

    match (ip, cidr) {
        (Some(ip), Some(cidr)) => Some(IpAddrMask::new(ip, cidr)),
        _ => None,
    }
}

pub fn set_host(ifname: &str, host: &Host) -> Result<(), WgError> {
    let mut nlas = vec![
        WgDeviceAttrs::IfName(ifname.into()),
        WgDeviceAttrs::ListenPort(host.listen_port),
    ];

    if let Some(key) = &host.private_key {
        nlas.push(WgDeviceAttrs::PrivateKey(key.as_array()));
    }
    if let Some(fwmark) = host.fwmark {
        nlas.push(WgDeviceAttrs::Fwmark(fwmark));
    }
    nlas.push(WgDeviceAttrs::Flags(WGDEVICE_F_REPLACE_PEERS));

    let genlmsg = GenlMessage::from_payload(Wireguard {
        cmd: WireguardCmd::SetDevice,
        nlas,
    });

    netlink_request_genl(genlmsg, NLM_F_REQUEST | NLM_F_ACK)?;

    for peer in host.peers.values() {
        set_peer(ifname, peer)?;
    }

    Ok(())
}

pub fn set_peer(ifname: &str, peer: &Peer) -> Result<(), WgError> {
    let genlmsg = GenlMessage::from_payload(Wireguard {
        cmd: WireguardCmd::SetDevice,
        nlas: peer_as_nlas(ifname, peer),
    });

    netlink_request_genl(genlmsg, NLM_F_REQUEST | NLM_F_ACK)?;
    Ok(())
}

fn peer_as_nlas(ifname: &str, peer: &Peer) -> Vec<WgDeviceAttrs> {
    let mut attrs = vec![WgPeerAttrs::PublicKey(peer.public_key.as_array())];

    if let Some(psk) = &peer.preshared_key {
        attrs.push(WgPeerAttrs::PresharedKey(psk.as_array()));
    }
    if let Some(endpoint) = peer.endpoint {
        attrs.push(WgPeerAttrs::Endpoint(endpoint));
    }
    if let Some(keepalive) = peer.persistent_keepalive_interval {
        attrs.push(WgPeerAttrs::PersistentKeepalive(keepalive));
    }

    attrs.push(WgPeerAttrs::Flags(WGPEER_F_REPLACE_ALLOWEDIPS));

    let allowed_ips: Vec<WgAllowedIp> = peer.allowed_ips.iter().map(ip_addr_mask_to_nlas).collect();
    attrs.push(WgPeerAttrs::AllowedIps(allowed_ips));

    vec![
        WgDeviceAttrs::IfName(ifname.into()),
        WgDeviceAttrs::Peers(vec![WgPeer(attrs)]),
    ]
}

fn ip_addr_mask_to_nlas(addr: &IpAddrMask) -> WgAllowedIp {
    let family = match addr.ip {
        IpAddr::V4(_) => AF_INET,
        IpAddr::V6(_) => AF_INET6,
    };

    WgAllowedIp(vec![
        WgAllowedIpAttrs::Family(family),
        WgAllowedIpAttrs::IpAddr(addr.ip),
        WgAllowedIpAttrs::Cidr(addr.cidr),
    ])
}

pub fn delete_peer(ifname: &str, pubkey: &Key) -> Result<(), WgError> {
    let genlmsg = GenlMessage::from_payload(Wireguard {
        cmd: WireguardCmd::SetDevice,
        nlas: vec![
            WgDeviceAttrs::IfName(ifname.into()),
            WgDeviceAttrs::Peers(vec![WgPeer(vec![
                WgPeerAttrs::PublicKey(pubkey.as_array()),
                WgPeerAttrs::Flags(WGPEER_F_REMOVE_ME),
            ])]),
        ],
    });

    netlink_request_genl(genlmsg, NLM_F_REQUEST | NLM_F_ACK)?;
    Ok(())
}

const RT_TABLE_MAIN: u8 = 254;

fn get_interface_index(ifname: &str) -> Result<u32, WgError> {
    let mut message = LinkMessage::default();
    message
        .attributes
        .push(LinkAttribute::IfName(ifname.into()));

    let responses = netlink_request(
        RouteNetlinkMessage::GetLink(message),
        NLM_F_REQUEST | NLM_F_DUMP,
        NETLINK_ROUTE,
    )?;

    for response in responses {
        if let NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewLink(link)) = response.payload {
            for attr in &link.attributes {
                if let LinkAttribute::IfName(name) = attr {
                    if name == ifname {
                        return Ok(link.header.index);
                    }
                }
            }
        }
    }

    Err(WgError::InterfaceNotFound(ifname.into()))
}

pub fn add_ipv6_address(ifname: &str, addr: Ipv6Addr, prefix_len: u8) -> Result<(), WgError> {
    let ifindex = get_interface_index(ifname)?;

    let mut message = AddressMessage::default();
    message.header.family = AddressFamily::Inet6;
    message.header.prefix_len = prefix_len;
    message.header.index = ifindex;

    message
        .attributes
        .push(AddressAttribute::Address(IpAddr::V6(addr)));
    message
        .attributes
        .push(AddressAttribute::Local(IpAddr::V6(addr)));

    netlink_request(
        RouteNetlinkMessage::NewAddress(message),
        NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
        NETLINK_ROUTE,
    )?;

    Ok(())
}

pub fn add_ipv6_route(ifname: &str, dest: Ipv6Addr, prefix_len: u8) -> Result<(), WgError> {
    let ifindex = get_interface_index(ifname)?;

    let mut message = RouteMessage::default();
    message.header.address_family = AddressFamily::Inet6;
    message.header.destination_prefix_length = prefix_len;
    message.header.table = RT_TABLE_MAIN;
    message.header.protocol = RouteProtocol::Boot;
    message.header.scope = RouteScope::Universe;
    message.header.kind = RouteType::Unicast;

    message
        .attributes
        .push(RouteAttribute::Destination(IpAddr::V6(dest).into()));
    message.attributes.push(RouteAttribute::Oif(ifindex));

    netlink_request(
        RouteNetlinkMessage::NewRoute(message),
        NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
        NETLINK_ROUTE,
    )?;

    Ok(())
}

pub fn set_link_up(ifname: &str) -> Result<(), WgError> {
    let ifindex = get_interface_index(ifname)?;

    let mut message = LinkMessage::default();
    message.header.index = ifindex;
    message.header.flags = LinkFlags::Up;
    message.header.change_mask = LinkFlags::Up;

    netlink_request(
        RouteNetlinkMessage::SetLink(message),
        NLM_F_REQUEST | NLM_F_ACK,
        NETLINK_ROUTE,
    )?;

    Ok(())
}

pub fn get_interface_ipv4(ifname: &str) -> Option<Ipv4Addr> {
    let ifindex = get_interface_index(ifname).ok()?;

    let mut message = AddressMessage::default();
    message.header.family = AddressFamily::Inet;

    let responses = netlink_request(
        RouteNetlinkMessage::GetAddress(message),
        NLM_F_REQUEST | NLM_F_DUMP,
        NETLINK_ROUTE,
    )
    .ok()?;

    for response in responses {
        if let NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewAddress(addr_msg)) =
            response.payload
        {
            if addr_msg.header.index != ifindex {
                continue;
            }
            for attr in &addr_msg.attributes {
                if let AddressAttribute::Address(IpAddr::V4(ip)) = attr {
                    return Some(*ip);
                }
            }
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn ip_addr_mask_to_nlas_v4() {
        let addr = IpAddrMask::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 24);
        let nlas = ip_addr_mask_to_nlas(&addr);
        assert!(!nlas.0.is_empty());
    }

    #[test]
    fn ip_addr_mask_roundtrip() {
        let original = IpAddrMask::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 0)), 24);
        let nlas = ip_addr_mask_to_nlas(&original);
        let parsed = ip_addr_mask_from_nlas(&nlas).unwrap();
        assert_eq!(original.ip, parsed.ip);
        assert_eq!(original.cidr, parsed.cidr);
    }

    #[test]
    fn peer_from_empty_nlas() {
        let nlas = WgPeer(vec![]);
        let peer = peer_from_nlas(&nlas);
        assert!(peer.allowed_ips.is_empty());
    }
}
