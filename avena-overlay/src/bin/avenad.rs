use avena_overlay::{
    derive_session_keys, derive_wireguard_keypair,
    routing::{BabeldController, RoutingError},
    AvenadConfig, CertValidator, DeviceId, DeviceKeypair, DiscoveredPeer, DiscoveryEvent,
    DiscoveryService, EphemeralKeypair, HandshakeMessage, KernelBackend, LocalAnnouncement,
    NetworkConfig, PeerConfig, PeerState, TunnelBackend, TunnelMode, UserspaceBackend,
};
use ed25519_dalek::VerifyingKey;
use ipnet::IpNet;
use lru::LruCache;
use sha2::{Digest, Sha256};
use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, RwLock, Semaphore};
use tracing::{debug, error, info, warn};

const HANDSHAKE_MAGIC: &[u8; 4] = b"AVHS";
const HANDSHAKE_VERSION: u8 = 1;
const MAX_HANDSHAKE_MSG_LEN: usize = 8 * 1024;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const NONCE_CACHE_EXPIRY: Duration = Duration::from_secs(70);
const MAX_CONCURRENT_HANDSHAKES: usize = 32;
const MAX_HANDSHAKES_PER_IP: u32 = 5;
const MAX_NONCE_CACHE_SIZE: usize = 10_000;
const MAX_RATE_LIMITER_SIZE: usize = 10_000;
const MAX_CONCURRENT_OUTGOING_HANDSHAKES: usize = 16;
const TUNNEL_PORT_BASE: u16 = 20000;
const TUNNEL_PORT_SPAN: u16 = 40000;

struct NonceCache {
    entries: Mutex<LruCache<(DeviceId, [u8; 32]), Instant>>,
}

impl NonceCache {
    fn new() -> Self {
        Self {
            entries: Mutex::new(LruCache::new(
                NonZeroUsize::new(MAX_NONCE_CACHE_SIZE).unwrap(),
            )),
        }
    }

    async fn check_and_insert(&self, device_id: DeviceId, nonce: [u8; 32]) -> bool {
        let mut entries = self.entries.lock().await;
        let now = Instant::now();
        let key = (device_id, nonce);

        if let Some(&expiry) = entries.get(&key) {
            if expiry > now {
                return false;
            }
        }
        entries.put(key, now + NONCE_CACHE_EXPIRY);
        true
    }
}

struct RateLimiter {
    counts: Mutex<LruCache<IpAddr, (u32, Instant)>>,
    window: Duration,
}

impl RateLimiter {
    fn new(window: Duration) -> Self {
        Self {
            counts: Mutex::new(LruCache::new(
                NonZeroUsize::new(MAX_RATE_LIMITER_SIZE).unwrap(),
            )),
            window,
        }
    }

    async fn check(&self, addr: IpAddr) -> bool {
        let mut counts = self.counts.lock().await;
        let now = Instant::now();

        if let Some((count, expiry)) = counts.get_mut(&addr) {
            if *expiry <= now {
                *count = 1;
                *expiry = now + self.window;
                true
            } else if *count >= MAX_HANDSHAKES_PER_IP {
                false
            } else {
                *count += 1;
                true
            }
        } else {
            counts.put(addr, (1, now + self.window));
            true
        }
    }
}

struct AvenadInner {
    config: AvenadConfig,
    keypair: DeviceKeypair,
    wg_public: [u8; 32],
    network: NetworkConfig,
    base_tunnel: Arc<dyn TunnelBackend>,
    peer_tunnels: Mutex<HashMap<String, Arc<dyn TunnelBackend>>>,
    discovery: DiscoveryService,
    peers: RwLock<HashMap<String, PeerState>>,
    nonce_cache: NonceCache,
    rate_limiter: RateLimiter,
    handshake_semaphore: Arc<Semaphore>,
    outgoing_semaphore: Arc<Semaphore>,
    cert_validator: CertValidator,
    device_cert: String,
    routing: Mutex<Option<BabeldController>>,
}

struct Avenad {
    inner: Arc<AvenadInner>,
    discovery_rx: Option<tokio::sync::broadcast::Receiver<DiscoveryEvent>>,
    handshake_listener: TcpListener,
}

#[derive(Clone)]
struct PeerTunnelBinding {
    interface_name: String,
    tunnel: Arc<dyn TunnelBackend>,
    listen_port: u16,
}

fn peer_tunnel_interface_name(local: &DeviceId, peer: &DeviceId, underlay_hint: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(local.as_bytes());
    hasher.update(peer.as_bytes());
    hasher.update(underlay_hint.as_bytes());
    let digest = hasher.finalize();
    let suffix = hex::encode(&digest[..4]);
    format!("av-{suffix}")
}

fn canonical_underlay_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(v6)),
        IpAddr::V4(_) => ip,
    }
}

#[cfg(target_os = "linux")]
fn resolve_local_underlay_identifier(local_ip: IpAddr) -> Result<String, AvenadError> {
    use avena_overlay::wg::linux::netlink;

    let canonical_ip = canonical_underlay_ip(local_ip);
    netlink::get_interface_name_for_ip(canonical_ip).ok_or_else(|| {
        AvenadError::Handshake(format!(
            "strict underlay resolution failed for local IP {}",
            canonical_ip
        ))
    })
}

#[cfg(not(target_os = "linux"))]
fn resolve_local_underlay_identifier(local_ip: IpAddr) -> Result<String, AvenadError> {
    Err(AvenadError::Handshake(format!(
        "strict underlay resolution unsupported on this platform for local IP {}",
        local_ip
    )))
}

fn deterministic_tunnel_listen_port(interface_name: &str) -> u16 {
    let mut hasher = Sha256::new();
    hasher.update(interface_name.as_bytes());
    let digest = hasher.finalize();
    let n = u16::from_le_bytes([digest[0], digest[1]]);
    TUNNEL_PORT_BASE + (n % TUNNEL_PORT_SPAN)
}

impl Avenad {
    async fn new(config: AvenadConfig) -> Result<Self, AvenadError> {
        validate_interface_name(&config.interface_name)?;

        if let Err(e) = try_raise_nofile_limit() {
            warn!("Failed to raise NOFILE limit: {}", e);
        }

        let keypair = load_or_generate_keypair(&config)?;
        let device_id = keypair.device_id();
        info!(device_id = %device_id, "Initialized device identity");

        let (cert_validator, device_cert) =
            config.load_crypto().map_err(AvenadError::CertConfig)?;
        info!("Loaded device certificate");

        let wg_keys = derive_wireguard_keypair(&keypair);

        let network = config.network.clone();
        let overlay_ip = network.device_address(&device_id);
        info!(overlay_ip = %overlay_ip, "Overlay address");

        let base_tunnel =
            select_tunnel_backend(config.tunnel_mode.clone(), &config.interface_name, "base")
                .await?;
        info!(mode = ?config.tunnel_mode, "Tunnel backend selected");

        base_tunnel.set_private_key(&*wg_keys.private).await?;
        base_tunnel.set_listen_port(config.listen_port).await?;

        assign_interface_address(&config.interface_name, overlay_ip)?;
        info!(interface = %config.interface_name, addr = %overlay_ip, "Assigned overlay address to interface");

        let discovery_config = config.to_discovery_config();
        let discovery = DiscoveryService::new(discovery_config)?;
        let discovery_rx = discovery.subscribe();
        discovery.start_mdns_browse()?;
        info!("Discovery service initialized");

        let wg_port = base_tunnel
            .listen_port()
            .await
            .unwrap_or(config.listen_port);
        let handshake_port = wg_port + 1;
        let listen_addr: SocketAddr = config
            .listen_address
            .unwrap_or_else(|| format!("[::]:{}", handshake_port).parse().unwrap());
        let handshake_listener = TcpListener::bind(listen_addr).await?;
        info!(addr = %listen_addr, "Handshake listener bound");

        let routing = Some(start_routing_controller(&config).await?);

        let inner = Arc::new(AvenadInner {
            config,
            keypair,
            wg_public: wg_keys.public,
            network,
            base_tunnel,
            peer_tunnels: Mutex::new(HashMap::new()),
            discovery,
            peers: RwLock::new(HashMap::new()),
            nonce_cache: NonceCache::new(),
            rate_limiter: RateLimiter::new(Duration::from_secs(60)),
            handshake_semaphore: Arc::new(Semaphore::new(MAX_CONCURRENT_HANDSHAKES)),
            outgoing_semaphore: Arc::new(Semaphore::new(MAX_CONCURRENT_OUTGOING_HANDSHAKES)),
            cert_validator,
            device_cert,
            routing: Mutex::new(routing),
        });

        Ok(Self {
            inner,
            discovery_rx: Some(discovery_rx),
            handshake_listener,
        })
    }

    async fn run(&mut self) -> Result<(), AvenadError> {
        let mut discovery_rx = self
            .discovery_rx
            .take()
            .expect("discovery_rx already taken");
        let inner = Arc::clone(&self.inner);

        inner.announce_presence().await?;

        for peer in inner.discovery.resolve_static_peers().await {
            info!(peer_id = %peer.device_id, endpoint = %peer.endpoint, "Resolved static peer");
            inner.discovery.cache_discovered_peer(&peer);
            let inner_clone = Arc::clone(&inner);
            tokio::spawn(async move {
                if let Err(e) = inner_clone.handle_discovered_peer(peer).await {
                    warn!("Failed to connect to static peer: {}", e);
                }
            });
        }

        info!("Avenad running. Press Ctrl+C to stop.");

        let mut dead_peer_interval =
            tokio::time::interval(Duration::from_secs(inner.config.dead_peer_timeout_secs));
        dead_peer_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        let mut overlay_route_interval = tokio::time::interval(Duration::from_secs(2));
        overlay_route_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        let reannounce_every = Duration::from_millis(
            inner
                .config
                .discovery
                .presence_reannounce_interval_ms
                .max(1),
        );
        let mut reannounce_interval = tokio::time::interval(reannounce_every);
        reannounce_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        reannounce_interval.tick().await;

        let peer_retry_every =
            Duration::from_millis(inner.config.discovery.peer_retry_interval_ms.max(1));
        let mut discovered_peer_retry_interval = tokio::time::interval(peer_retry_every);
        discovered_peer_retry_interval
            .set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        discovered_peer_retry_interval.tick().await;

        loop {
            tokio::select! {
                result = discovery_rx.recv() => {
                    match result {
                        Ok(DiscoveryEvent::PeerDiscovered(peer)) => {
                            if peer.device_id != inner.keypair.device_id() {
                                let permit = match inner.outgoing_semaphore.clone().try_acquire_owned() {
                                    Ok(p) => p,
                                    Err(_) => {
                                        warn!(peer_id = %peer.device_id, "Outgoing handshake queue full, skipping");
                                        continue;
                                    }
                                };

                                info!(peer_id = %peer.device_id, endpoint = %peer.endpoint, "Peer discovered");
                                inner.discovery.cache_discovered_peer(&peer);
                                let inner_clone = Arc::clone(&inner);
                                tokio::spawn(async move {
                                    let _permit = permit;
                                    if let Err(e) = inner_clone.handle_discovered_peer(peer).await {
                                        warn!("Failed to handle discovered peer: {}", e);
                                    }
                                });
                            }
                        }
                        Ok(DiscoveryEvent::PeerLost(device_id)) => {
                            info!(peer_id = %device_id, "Peer lost");
                            inner.handle_peer_lost(&device_id).await;
                        }
                        Err(e) => {
                            debug!("Discovery channel error: {}", e);
                        }
                    }
                }
                result = self.handshake_listener.accept() => {
                    match result {
                        Ok((stream, addr)) => {
                            if !inner.rate_limiter.check(addr.ip()).await {
                                debug!(addr = %addr, "Rate limited handshake connection");
                                continue;
                            }

                            let permit = match inner.handshake_semaphore.clone().try_acquire_owned() {
                                Ok(p) => p,
                                Err(_) => {
                                    debug!(addr = %addr, "Too many concurrent handshakes");
                                    continue;
                                }
                            };

                            info!(addr = %addr, "Incoming handshake connection");
                            let inner_clone = Arc::clone(&inner);
                            tokio::spawn(async move {
                                let _permit = permit;
                                match inner_clone.handle_incoming_handshake(stream, addr).await {
                                    Ok(peer_state) => {
                                        let device_id = peer_state.device_id;
                                        let iface = peer_state.tunnel_interface.clone();
                                        let mut peers = inner_clone.peers.write().await;
                                        let mut inserted = false;
                                        if let Entry::Vacant(entry) = peers.entry(iface.clone()) {
                                            entry.insert(peer_state);
                                            inserted = true;
                                            info!(peer_id = %device_id, iface = %iface, "Peer connected via incoming handshake");
                                        } else {
                                            debug!(peer_id = %device_id, iface = %iface, "Peer tunnel already connected, discarding duplicate handshake result");
                                        }
                                        drop(peers);

                                        if let Err(e) = inner_clone.reconcile_peer_allowed_ips().await {
                                            warn!(
                                                peer_id = %device_id,
                                                inserted,
                                                "Failed to reconcile peer allowed-ips after incoming handshake: {}",
                                                e
                                            );
                                        }
                                    }
                                    Err(e) => {
                                        warn!(addr = %addr, "Incoming handshake failed: {}", e);
                                    }
                                }
                            });
                        }
                        Err(e) => {
                            error!("Failed to accept connection: {}", e);
                        }
                    }
                }
                _ = dead_peer_interval.tick() => {
                    inner.check_dead_peers().await;
                }
                _ = overlay_route_interval.tick() => {
                    inner.maintain_overlay_prefix_route().await;
                }
                _ = reannounce_interval.tick() => {
                    if let Err(e) = inner.announce_presence().await {
                        warn!("failed to re-announce presence: {}", e);
                    }
                }
                _ = discovered_peer_retry_interval.tick() => {
                    inner.retry_discovered_peers().await;
                }
                _ = tokio::signal::ctrl_c() => {
                    info!("Shutdown signal received");
                    break;
                }
            }
        }

        inner.shutdown().await;
        Ok(())
    }
}

async fn start_routing_controller(config: &AvenadConfig) -> Result<BabeldController, AvenadError> {
    let mut controller = BabeldController::new(config.routing.babel.clone());
    controller.start(&[&config.interface_name]).await?;
    info!("Started babeld for dynamic routing");
    Ok(controller)
}

async fn select_tunnel_backend(
    mode: TunnelMode,
    interface_name: &str,
    context: &str,
) -> Result<Arc<dyn TunnelBackend>, AvenadError> {
    let prefer_kernel = matches!(mode, TunnelMode::PreferKernel);
    let candidates: Vec<Arc<dyn TunnelBackend>> = match mode {
        TunnelMode::Kernel => vec![Arc::new(KernelBackend::new())],
        TunnelMode::Userspace => vec![Arc::new(UserspaceBackend::new())],
        TunnelMode::PreferKernel => vec![
            Arc::new(KernelBackend::new()),
            Arc::new(UserspaceBackend::new()),
        ],
    };

    let mut last_err = None;
    for (idx, tunnel) in candidates.into_iter().enumerate() {
        match tunnel.ensure_interface(interface_name).await {
            Ok(()) => return Ok(tunnel),
            Err(e) => {
                if idx == 0 && prefer_kernel {
                    debug!(
                        iface = %interface_name,
                        context = context,
                        "Kernel tunnel unavailable, falling back to userspace backend: {}",
                        e
                    );
                }
                last_err = Some(e);
            }
        }
    }

    Err(AvenadError::Tunnel(last_err.unwrap_or_else(|| {
        avena_overlay::TunnelError::InterfaceCreation(
            "no tunnel backend could create interface".into(),
        )
    })))
}

impl AvenadInner {
    async fn ensure_peer_tunnel(
        &self,
        peer_id: &DeviceId,
        local_underlay_hint: &str,
    ) -> Result<PeerTunnelBinding, AvenadError> {
        let interface_name =
            peer_tunnel_interface_name(&self.keypair.device_id(), peer_id, local_underlay_hint);
        let listen_port = deterministic_tunnel_listen_port(&interface_name);

        let mut tunnels = self.peer_tunnels.lock().await;
        if let Some(existing) = tunnels.get(&interface_name).cloned() {
            return Ok(PeerTunnelBinding {
                interface_name,
                tunnel: existing,
                listen_port,
            });
        }

        let tunnel =
            select_tunnel_backend(self.config.tunnel_mode.clone(), &interface_name, "peer").await?;

        self.configure_peer_tunnel_backend(&tunnel, &interface_name, listen_port)
            .await?;

        tunnels.insert(interface_name.clone(), tunnel.clone());

        Ok(PeerTunnelBinding {
            interface_name,
            tunnel,
            listen_port,
        })
    }

    async fn configure_peer_tunnel_backend(
        &self,
        tunnel: &Arc<dyn TunnelBackend>,
        interface_name: &str,
        listen_port: u16,
    ) -> Result<(), AvenadError> {
        let wg_keys = derive_wireguard_keypair(&self.keypair);
        tunnel.set_private_key(&*wg_keys.private).await?;
        tunnel.set_listen_port(listen_port).await?;

        let overlay_ip = self.network.device_address(&self.keypair.device_id());
        assign_interface_address(interface_name, overlay_ip)?;

        let mut routing = self.routing.lock().await;
        let controller = routing
            .as_mut()
            .ok_or_else(|| AvenadError::Routing(RoutingError::not_running()))?;
        controller.add_interface(interface_name).await?;
        Ok(())
    }

    async fn announce_presence(&self) -> Result<(), AvenadError> {
        let wg_port = self
            .base_tunnel
            .listen_port()
            .await
            .unwrap_or(self.config.listen_port);
        let interfaces = self.config.discovery.effective_mdns_interfaces();

        if interfaces.is_empty() {
            let announcement = LocalAnnouncement {
                device_id: self.keypair.device_id(),
                wg_endpoint: SocketAddr::new(IpAddr::from([0u8; 4]), wg_port),
                capabilities: std::collections::HashSet::new(),
                interface_suffix: None,
            };
            self.discovery.announce(&announcement).await?;
        } else {
            for (idx, iface) in interfaces.iter().enumerate() {
                let ip = match get_interface_ip(iface) {
                    Some(ip) => ip,
                    None => {
                        warn!(interface = %iface, "Could not get IP for interface, skipping");
                        continue;
                    }
                };

                let announcement = LocalAnnouncement {
                    device_id: self.keypair.device_id(),
                    wg_endpoint: SocketAddr::new(ip, wg_port),
                    capabilities: std::collections::HashSet::new(),
                    interface_suffix: Some(idx as u8),
                };
                info!(interface = %iface, endpoint = %announcement.wg_endpoint, "Announcing on interface");
                self.discovery.announce(&announcement).await?;
            }
        }
        Ok(())
    }

    async fn handle_discovered_peer(&self, peer: DiscoveredPeer) -> Result<(), AvenadError> {
        let should_initiate = self.keypair.device_id() > peer.device_id;
        if !should_initiate {
            debug!(peer_id = %peer.device_id, "Waiting for peer to initiate");
            return Ok(());
        }

        {
            let peers = self.peers.read().await;
            if peers.values().any(|state| {
                state.device_id == peer.device_id
                    && state.endpoint.map(|endpoint| endpoint.ip()) == Some(peer.endpoint.ip())
            }) {
                debug!(peer_id = %peer.device_id, endpoint = %peer.endpoint, "Already connected to peer endpoint");
                return Ok(());
            }
        }

        info!(peer_id = %peer.device_id, "Initiating handshake");

        let handshake_addr = SocketAddr::new(peer.endpoint.ip(), peer.endpoint.port() + 1);
        let peer_state = self
            .perform_outgoing_handshake(handshake_addr, &peer)
            .await?;

        let iface = peer_state.tunnel_interface.clone();
        let mut peers = self.peers.write().await;
        if let Entry::Vacant(entry) = peers.entry(iface.clone()) {
            entry.insert(peer_state);
            info!(peer_id = %peer.device_id, iface = %iface, "Peer connected");
        } else {
            debug!(peer_id = %peer.device_id, iface = %iface, "Peer tunnel already connected, discarding duplicate handshake result");
        }
        drop(peers);

        self.reconcile_peer_allowed_ips().await?;

        Ok(())
    }

    async fn perform_outgoing_handshake(
        &self,
        addr: SocketAddr,
        peer: &DiscoveredPeer,
    ) -> Result<PeerState, AvenadError> {
        tokio::time::timeout(
            HANDSHAKE_TIMEOUT,
            self.perform_outgoing_handshake_inner(addr, peer),
        )
        .await
        .map_err(|_| AvenadError::Timeout)?
    }

    async fn perform_outgoing_handshake_inner(
        &self,
        addr: SocketAddr,
        peer: &DiscoveredPeer,
    ) -> Result<PeerState, AvenadError> {
        let mut stream = TcpStream::connect(addr).await?;

        let local_underlay_hint = resolve_local_underlay_identifier(stream.local_addr()?.ip())?;
        let binding = self
            .ensure_peer_tunnel(&peer.device_id, &local_underlay_hint)
            .await?;

        let local_ephemeral = EphemeralKeypair::generate();
        let local_msg = HandshakeMessage::create(
            &self.keypair,
            &local_ephemeral,
            &peer.device_id,
            self.wg_public,
            binding.listen_port,
            &self.device_cert,
        );

        stream.write_all(HANDSHAKE_MAGIC).await?;
        stream.write_u8(HANDSHAKE_VERSION).await?;

        let pubkey_bytes = self.keypair.public_key().to_bytes();
        stream.write_all(&pubkey_bytes).await?;

        let msg_bytes = serde_json::to_vec(&local_msg)?;
        stream.write_u32(msg_bytes.len() as u32).await?;
        stream.write_all(&msg_bytes).await?;

        let mut magic = [0u8; 4];
        stream.read_exact(&mut magic).await?;
        if &magic != HANDSHAKE_MAGIC {
            return Err(AvenadError::Handshake("invalid magic".into()));
        }

        let version = stream.read_u8().await?;
        if version != HANDSHAKE_VERSION {
            return Err(AvenadError::Handshake("version mismatch".into()));
        }

        let mut peer_pubkey_bytes = [0u8; 32];
        stream.read_exact(&mut peer_pubkey_bytes).await?;
        let peer_pubkey = VerifyingKey::from_bytes(&peer_pubkey_bytes)
            .map_err(|_| AvenadError::Handshake("invalid peer public key".into()))?;

        let peer_device_id = DeviceId::from_public_key(&peer_pubkey);
        if peer_device_id != peer.device_id {
            return Err(AvenadError::Handshake("device id mismatch".into()));
        }

        let msg_len = stream.read_u32().await? as usize;
        if msg_len > MAX_HANDSHAKE_MSG_LEN {
            return Err(AvenadError::Handshake("message too large".into()));
        }
        let mut msg_bytes = vec![0u8; msg_len];
        stream.read_exact(&mut msg_bytes).await?;
        let peer_msg: HandshakeMessage = serde_json::from_slice(&msg_bytes)?;

        peer_msg
            .verify(
                &peer_pubkey,
                &self.keypair.device_id(),
                &self.cert_validator,
            )
            .map_err(|e| AvenadError::Handshake(format!("handshake verification failed: {}", e)))?;

        let peer_ephemeral = peer_msg.ephemeral_public_key();
        let our_keys = derive_session_keys(&local_ephemeral, &peer_ephemeral);
        let peer_wg_pubkey = peer_msg.wg_pubkey;
        let peer_overlay_ip = self.network.device_address(&peer.device_id);
        let peer_wg_endpoint =
            SocketAddr::new(canonical_underlay_ip(addr.ip()), peer_msg.wg_listen_port);

        let allowed_ips = universal_peer_allowed_ips();

        let peer_config = PeerConfig::new(peer_wg_pubkey)
            .with_psk(*our_keys.wireguard_psk)
            .with_allowed_ips(allowed_ips)
            .with_endpoint(peer_wg_endpoint)
            .with_keepalive(self.config.persistent_keepalive);

        binding.tunnel.add_peer(&peer_config).await?;

        // Always install a direct /128 route for the connected peer.
        // Babel handles multi-hop routes, but direct peer routes are needed
        // immediately after handshake so overlay probes are routable.
        if let Err(e) = ensure_direct_peer_route(&binding.interface_name, peer_overlay_ip) {
            if e.kind() != std::io::ErrorKind::Unsupported {
                warn!(
                    peer_id = %peer.device_id,
                    interface = %binding.interface_name,
                    "failed to install direct peer route: {}",
                    e
                );
            }
        }

        Ok(PeerState::new(
            peer.device_id,
            peer_pubkey,
            peer_wg_pubkey,
            peer_overlay_ip,
            binding.interface_name,
        )
        .with_endpoint(peer_wg_endpoint))
    }

    async fn handle_incoming_handshake(
        &self,
        stream: TcpStream,
        addr: SocketAddr,
    ) -> Result<PeerState, AvenadError> {
        tokio::time::timeout(
            HANDSHAKE_TIMEOUT,
            self.handle_incoming_handshake_inner(stream, addr),
        )
        .await
        .map_err(|_| AvenadError::Timeout)?
    }

    async fn handle_incoming_handshake_inner(
        &self,
        mut stream: TcpStream,
        addr: SocketAddr,
    ) -> Result<PeerState, AvenadError> {
        let local_underlay_hint = resolve_local_underlay_identifier(stream.local_addr()?.ip())?;

        let mut magic = [0u8; 4];
        stream.read_exact(&mut magic).await?;
        if &magic != HANDSHAKE_MAGIC {
            return Err(AvenadError::Handshake("invalid magic".into()));
        }

        let version = stream.read_u8().await?;
        if version != HANDSHAKE_VERSION {
            return Err(AvenadError::Handshake("version mismatch".into()));
        }

        let mut peer_pubkey_bytes = [0u8; 32];
        stream.read_exact(&mut peer_pubkey_bytes).await?;
        let peer_pubkey = VerifyingKey::from_bytes(&peer_pubkey_bytes)
            .map_err(|_| AvenadError::Handshake("invalid peer public key".into()))?;
        let peer_device_id = DeviceId::from_public_key(&peer_pubkey);

        let msg_len = stream.read_u32().await? as usize;
        if msg_len > MAX_HANDSHAKE_MSG_LEN {
            return Err(AvenadError::Handshake("message too large".into()));
        }
        let mut msg_bytes = vec![0u8; msg_len];
        stream.read_exact(&mut msg_bytes).await?;
        let peer_msg: HandshakeMessage = serde_json::from_slice(&msg_bytes)?;

        peer_msg
            .verify(
                &peer_pubkey,
                &self.keypair.device_id(),
                &self.cert_validator,
            )
            .map_err(|e| AvenadError::Handshake(format!("handshake verification failed: {}", e)))?;

        if !self
            .nonce_cache
            .check_and_insert(peer_device_id, peer_msg.nonce)
            .await
        {
            return Err(AvenadError::Handshake("replay detected".into()));
        }

        let binding = self
            .ensure_peer_tunnel(&peer_device_id, &local_underlay_hint)
            .await?;

        let local_ephemeral = EphemeralKeypair::generate();
        let local_msg = HandshakeMessage::create(
            &self.keypair,
            &local_ephemeral,
            &peer_device_id,
            self.wg_public,
            binding.listen_port,
            &self.device_cert,
        );

        stream.write_all(HANDSHAKE_MAGIC).await?;
        stream.write_u8(HANDSHAKE_VERSION).await?;

        let pubkey_bytes = self.keypair.public_key().to_bytes();
        stream.write_all(&pubkey_bytes).await?;

        let msg_bytes = serde_json::to_vec(&local_msg)?;
        stream.write_u32(msg_bytes.len() as u32).await?;
        stream.write_all(&msg_bytes).await?;

        let peer_ephemeral = peer_msg.ephemeral_public_key();
        let our_keys = derive_session_keys(&local_ephemeral, &peer_ephemeral);
        let peer_wg_pubkey = peer_msg.wg_pubkey;
        let peer_overlay_ip = self.network.device_address(&peer_device_id);
        let peer_wg_endpoint =
            SocketAddr::new(canonical_underlay_ip(addr.ip()), peer_msg.wg_listen_port);

        let allowed_ips = universal_peer_allowed_ips();

        let peer_config = PeerConfig::new(peer_wg_pubkey)
            .with_psk(*our_keys.wireguard_psk)
            .with_allowed_ips(allowed_ips)
            .with_endpoint(peer_wg_endpoint)
            .with_keepalive(self.config.persistent_keepalive);

        binding.tunnel.add_peer(&peer_config).await?;

        // Always install a direct /128 route for the connected peer.
        // Babel handles multi-hop routes, but direct peer routes are needed
        // immediately after handshake so overlay probes are routable.
        if let Err(e) = ensure_direct_peer_route(&binding.interface_name, peer_overlay_ip) {
            if e.kind() != std::io::ErrorKind::Unsupported {
                warn!(
                    peer_id = %peer_device_id,
                    interface = %binding.interface_name,
                    "failed to install direct peer route: {}",
                    e
                );
            }
        }

        Ok(PeerState::new(
            peer_device_id,
            peer_pubkey,
            peer_wg_pubkey,
            peer_overlay_ip,
            binding.interface_name,
        )
        .with_endpoint(peer_wg_endpoint))
    }

    async fn remove_tunnel_interface(&self, tunnel_interface: &str) -> Option<DeviceId> {
        let peer = self.peers.write().await.remove(tunnel_interface)?;

        let tunnel = self
            .peer_tunnels
            .lock()
            .await
            .get(tunnel_interface)
            .cloned();

        if let Some(tunnel) = tunnel {
            if let Err(e) = tunnel.remove_peer(&peer.wg_pubkey).await {
                warn!(peer_id = %peer.device_id, iface = %peer.tunnel_interface, "Failed to remove peer from tunnel: {}", e);
            }
            if let Err(e) = tunnel.remove_interface().await {
                warn!(peer_id = %peer.device_id, iface = %peer.tunnel_interface, "Failed to remove tunnel interface: {}", e);
            }
        }

        self.peer_tunnels.lock().await.remove(tunnel_interface);

        let mut routing = self.routing.lock().await;
        if let Some(ref mut controller) = *routing {
            if let Err(e) = controller.flush_interface(tunnel_interface).await {
                warn!(peer_id = %peer.device_id, iface = %tunnel_interface, "Failed to flush interface from babeld: {}", e);
            }
        }

        Some(peer.device_id)
    }

    async fn handle_peer_lost(&self, device_id: &DeviceId) {
        let tunnels_to_remove = {
            let peers = self.peers.read().await;
            peers
                .values()
                .filter(|state| state.device_id == *device_id)
                .map(|state| state.tunnel_interface.clone())
                .collect::<Vec<_>>()
        };

        if tunnels_to_remove.is_empty() {
            return;
        }

        for tunnel_interface in tunnels_to_remove {
            self.remove_tunnel_interface(&tunnel_interface).await;
        }

        if let Err(e) = self.reconcile_peer_allowed_ips().await {
            warn!(peer_id = %device_id, "Failed to reconcile peer allowed-ips after peer removal: {}", e);
        }
    }

    async fn reconcile_peer_allowed_ips(&self) -> Result<(), AvenadError> {
        let (peer_count, peers) = {
            let peers = self.peers.read().await;
            let peer_count = peers
                .values()
                .map(|peer| peer.device_id)
                .collect::<HashSet<_>>()
                .len();
            let snapshot = peers
                .values()
                .map(|peer| {
                    (
                        peer.device_id,
                        peer.tunnel_interface.clone(),
                        peer.wg_pubkey,
                        peer.endpoint,
                    )
                })
                .collect::<Vec<_>>();
            (peer_count, snapshot)
        };

        info!(peer_count, "Reconciling peer allowed-ips");

        if peer_count == 1 && peers.len() == 1 {
            let tunnel_interface = &peers[0].1;
            if let Err(e) = ensure_overlay_prefix_route(tunnel_interface, &self.network) {
                if e.kind() != std::io::ErrorKind::Unsupported {
                    return Err(e.into());
                }
            } else {
                info!(
                    interface = %tunnel_interface,
                    prefix = %format!("{}/{}", self.network.prefix, self.network.prefix_len),
                    "Ensured overlay prefix route"
                );
            }
        }

        let tunnels = self.peer_tunnels.lock().await.clone();
        for (device_id, tunnel_interface, wg_pubkey, endpoint) in peers {
            let allowed_ips = universal_peer_allowed_ips();

            let mut peer_config = PeerConfig::new(wg_pubkey)
                .with_allowed_ips(allowed_ips)
                .with_keepalive(self.config.persistent_keepalive);
            if let Some(endpoint) = endpoint {
                peer_config = peer_config.with_endpoint(endpoint);
            }

            if let Some(tunnel) = tunnels.get(&tunnel_interface).cloned() {
                tunnel.add_peer(&peer_config).await?;
            }
            debug!(
                peer_id = %device_id,
                iface = %tunnel_interface,
                "reconciled peer allowed-ips for babel routing"
            );
        }

        Ok(())
    }

    async fn maintain_overlay_prefix_route(&self) {
        let (peer_count, tunnel_interface) = {
            let peers = self.peers.read().await;
            let peer_count = peers
                .values()
                .map(|peer| peer.device_id)
                .collect::<HashSet<_>>()
                .len();
            let tunnel_interface = if peer_count == 1 && peers.len() == 1 {
                peers
                    .values()
                    .next()
                    .map(|peer| peer.tunnel_interface.clone())
            } else {
                None
            };
            (peer_count, tunnel_interface)
        };

        if peer_count == 1 {
            if let Some(tunnel_interface) = tunnel_interface {
                if let Err(e) = ensure_overlay_prefix_route(&tunnel_interface, &self.network) {
                    if e.kind() != std::io::ErrorKind::Unsupported {
                        warn!(
                            interface = %tunnel_interface,
                            "failed to maintain overlay prefix route: {}",
                            e
                        );
                    }
                }
            }
        }
    }

    async fn retry_discovered_peers(&self) {
        let cached_peers = self.discovery.cached_peers();
        if cached_peers.is_empty() {
            return;
        }

        for peer in cached_peers {
            if peer.device_id == self.keypair.device_id() {
                continue;
            }

            let already_connected = self.peers.read().await.values().any(|state| {
                state.device_id == peer.device_id
                    && state.endpoint.map(|endpoint| endpoint.ip()) == Some(peer.endpoint.ip())
            });
            if already_connected {
                continue;
            }

            if let Err(e) = self.handle_discovered_peer(peer.clone()).await {
                debug!(peer_id = %peer.device_id, "retrying discovered peer failed: {}", e);
            }
        }
    }

    async fn check_dead_peers(&self) {
        let timeout = Duration::from_secs(self.config.dead_peer_timeout_secs);
        let peer_snapshot = {
            let peers = self.peers.read().await;
            peers
                .values()
                .map(|state| {
                    (
                        state.device_id,
                        state.wg_pubkey,
                        state.tunnel_interface.clone(),
                        state.last_seen,
                    )
                })
                .collect::<Vec<_>>()
        };

        let tunnels = self.peer_tunnels.lock().await.clone();
        let mut to_remove = HashSet::new();

        for (device_id, wg_pubkey, tunnel_interface, last_seen) in peer_snapshot {
            match tunnels.get(&tunnel_interface).cloned() {
                Some(tunnel) => match tunnel.peer_stats(&wg_pubkey).await {
                    Ok(stats) => {
                        if let Some(last_handshake) = stats.last_handshake {
                            if let Ok(elapsed) = last_handshake.elapsed() {
                                if elapsed > timeout {
                                    to_remove.insert((device_id, tunnel_interface.clone()));
                                }
                            }
                        }
                    }
                    Err(_) => {
                        if last_seen.elapsed() > timeout {
                            to_remove.insert((device_id, tunnel_interface.clone()));
                        }
                    }
                },
                None => {
                    if last_seen.elapsed() > timeout {
                        to_remove.insert((device_id, tunnel_interface.clone()));
                    }
                }
            }
        }

        let mut removed_any = false;
        for (device_id, tunnel_interface) in to_remove {
            warn!(peer_id = %device_id, iface = %tunnel_interface, "Removing dead peer tunnel");
            removed_any |= self
                .remove_tunnel_interface(&tunnel_interface)
                .await
                .is_some();
        }

        if removed_any {
            if let Err(e) = self.reconcile_peer_allowed_ips().await {
                warn!(
                    "Failed to reconcile peer allowed-ips after dead-peer cleanup: {}",
                    e
                );
            }
        }
    }

    async fn shutdown(&self) {
        info!("Shutting down avenad...");

        // Stop babeld first
        let mut routing = self.routing.lock().await;
        if let Some(ref mut controller) = *routing {
            if let Err(e) = controller.stop().await {
                warn!("Failed to stop babeld: {}", e);
            }
        }
        *routing = None;
        drop(routing);

        let peers = self.peers.read().await;
        for (id, peer) in peers.iter() {
            if let Some(tunnel) = self
                .peer_tunnels
                .lock()
                .await
                .get(&peer.tunnel_interface)
                .cloned()
            {
                if let Err(e) = tunnel.remove_peer(&peer.wg_pubkey).await {
                    warn!(peer_id = %id, iface = %peer.tunnel_interface, "Failed to remove peer during shutdown: {}", e);
                }
                if let Err(e) = tunnel.remove_interface().await {
                    warn!(peer_id = %id, iface = %peer.tunnel_interface, "Failed to remove tunnel interface during shutdown: {}", e);
                }
            }
        }
    }
}

fn validate_interface_name(name: &str) -> Result<(), AvenadError> {
    if name.is_empty() {
        return Err(AvenadError::Config("interface name cannot be empty".into()));
    }
    if name.len() > 15 {
        return Err(AvenadError::Config(
            "interface name too long (max 15 chars)".into(),
        ));
    }
    if name.starts_with('-') {
        return Err(AvenadError::Config(
            "interface name cannot start with '-'".into(),
        ));
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return Err(AvenadError::Config(
            "interface name contains invalid characters".into(),
        ));
    }
    Ok(())
}

fn load_or_generate_keypair(config: &AvenadConfig) -> Result<DeviceKeypair, AvenadError> {
    if let Some(ref path) = config.keypair_path {
        if path.exists() {
            let bytes = std::fs::read(path)?;
            if bytes.len() != 32 {
                return Err(AvenadError::Config("invalid keypair file size".into()));
            }
            let mut seed = [0u8; 32];
            seed.copy_from_slice(&bytes);
            return Ok(DeviceKeypair::from_seed(&seed));
        }
    }

    let keypair = DeviceKeypair::generate();

    if let Some(ref path) = config.keypair_path {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let bytes = keypair.to_bytes();

        #[cfg(unix)]
        {
            use std::fs::OpenOptions;
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;

            let mut file = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(path)?;
            file.write_all(&*bytes)?;
        }

        #[cfg(not(unix))]
        {
            std::fs::write(path, &*bytes)?;
        }

        info!(path = %path.display(), "Generated and saved new keypair");
    }

    Ok(keypair)
}

#[cfg(unix)]
fn try_raise_nofile_limit() -> Result<(), std::io::Error> {
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };

    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) } != 0 {
        return Err(std::io::Error::last_os_error());
    }

    if limit.rlim_cur < limit.rlim_max {
        let target = libc::rlimit {
            rlim_cur: limit.rlim_max,
            rlim_max: limit.rlim_max,
        };
        if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &target) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }

    Ok(())
}

#[cfg(not(unix))]
fn try_raise_nofile_limit() -> Result<(), std::io::Error> {
    Ok(())
}

#[cfg(target_os = "linux")]
fn assign_interface_address(
    interface_name: &str,
    addr: std::net::Ipv6Addr,
) -> Result<(), std::io::Error> {
    use avena_overlay::wg::linux::netlink;

    netlink::add_ipv6_address(interface_name, addr, 128)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("add address: {e}")))?;

    netlink::set_link_up(interface_name)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("set link up: {e}")))?;

    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn assign_interface_address(
    _interface_name: &str,
    _addr: std::net::Ipv6Addr,
) -> Result<(), std::io::Error> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "requires Linux",
    ))
}

#[cfg(target_os = "linux")]
fn add_peer_route(
    interface_name: &str,
    peer_addr: std::net::Ipv6Addr,
) -> Result<(), std::io::Error> {
    use avena_overlay::wg::linux::netlink;

    netlink::add_ipv6_route(interface_name, peer_addr, 128)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("add route: {e}")))
}

#[cfg(not(target_os = "linux"))]
fn add_peer_route(
    _interface_name: &str,
    _peer_addr: std::net::Ipv6Addr,
) -> Result<(), std::io::Error> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "requires Linux",
    ))
}

fn ensure_direct_peer_route(
    interface_name: &str,
    peer_addr: std::net::Ipv6Addr,
) -> Result<(), std::io::Error> {
    match add_peer_route(interface_name, peer_addr) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::Unsupported => Ok(()),
        Err(e) => Err(e),
    }
}

#[cfg(target_os = "linux")]
fn ensure_overlay_prefix_route(
    interface_name: &str,
    network: &NetworkConfig,
) -> Result<(), std::io::Error> {
    use avena_overlay::wg::linux::netlink;

    netlink::add_ipv6_route(interface_name, network.prefix, network.prefix_len).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("add overlay prefix route: {e}"),
        )
    })
}

#[cfg(not(target_os = "linux"))]
fn ensure_overlay_prefix_route(
    _interface_name: &str,
    _network: &NetworkConfig,
) -> Result<(), std::io::Error> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "requires Linux",
    ))
}

fn universal_peer_allowed_ips() -> Vec<IpNet> {
    vec![IpNet::new(std::net::Ipv6Addr::UNSPECIFIED.into(), 0).expect("::/0 is always valid")]
}

#[cfg(target_os = "linux")]
fn get_interface_ip(interface_name: &str) -> Option<IpAddr> {
    use avena_overlay::wg::linux::netlink;
    netlink::get_interface_ipv4(interface_name).map(IpAddr::V4)
}

#[cfg(not(target_os = "linux"))]
fn get_interface_ip(_interface_name: &str) -> Option<IpAddr> {
    None
}

#[derive(Debug)]
enum AvenadError {
    Config(String),
    CertConfig(avena_overlay::ConfigError),
    Tunnel(avena_overlay::TunnelError),
    Discovery(avena_overlay::DiscoveryError),
    Routing(RoutingError),
    Io(std::io::Error),
    Handshake(String),
    Json(serde_json::Error),
    Timeout,
}

impl std::fmt::Display for AvenadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AvenadError::Config(e) => write!(f, "config error: {}", e),
            AvenadError::CertConfig(e) => write!(f, "certificate config error: {}", e),
            AvenadError::Tunnel(e) => write!(f, "tunnel error: {}", e),
            AvenadError::Discovery(e) => write!(f, "discovery error: {}", e),
            AvenadError::Routing(e) => write!(f, "routing error: {}", e),
            AvenadError::Io(e) => write!(f, "io error: {}", e),
            AvenadError::Handshake(e) => write!(f, "handshake error: {}", e),
            AvenadError::Json(e) => write!(f, "json error: {}", e),
            AvenadError::Timeout => write!(f, "handshake timeout"),
        }
    }
}

impl std::error::Error for AvenadError {}

impl From<avena_overlay::TunnelError> for AvenadError {
    fn from(e: avena_overlay::TunnelError) -> Self {
        AvenadError::Tunnel(e)
    }
}

impl From<avena_overlay::DiscoveryError> for AvenadError {
    fn from(e: avena_overlay::DiscoveryError) -> Self {
        AvenadError::Discovery(e)
    }
}

impl From<RoutingError> for AvenadError {
    fn from(e: RoutingError) -> Self {
        AvenadError::Routing(e)
    }
}

impl From<std::io::Error> for AvenadError {
    fn from(e: std::io::Error) -> Self {
        AvenadError::Io(e)
    }
}

impl From<serde_json::Error> for AvenadError {
    fn from(e: serde_json::Error) -> Self {
        AvenadError::Json(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[tokio::test]
    async fn routing_startup_is_fatal_when_babel_binary_is_missing() {
        let mut config = AvenadConfig::default();
        config.routing.babel.binary_path = PathBuf::from("/definitely/missing/babeld");

        let err = start_routing_controller(&config).await.unwrap_err();
        assert!(matches!(err, AvenadError::Routing(_)));
    }

    #[test]
    fn peer_allowed_ips_use_universal_ipv6_prefix() {
        let allowed_ips = universal_peer_allowed_ips();
        assert_eq!(allowed_ips, vec!["::/0".parse().unwrap()]);
    }

    #[test]
    fn peer_allowed_ips_are_invariant_across_peer_counts() {
        let for_single = universal_peer_allowed_ips();
        let for_many = universal_peer_allowed_ips();
        assert_eq!(for_single, vec!["::/0".parse().unwrap()]);
        assert_eq!(for_many, vec!["::/0".parse().unwrap()]);
    }

    #[test]
    fn peer_tunnel_interface_name_is_deterministic_and_underlay_scoped() {
        let local = DeviceId::from_bytes([1u8; 16]);
        let peer = DeviceId::from_bytes([2u8; 16]);

        let a = peer_tunnel_interface_name(&local, &peer, "10.1.0.10");
        let b = peer_tunnel_interface_name(&local, &peer, "10.1.0.10");
        let c = peer_tunnel_interface_name(&local, &peer, "10.2.0.10");

        assert_eq!(a, b);
        assert_ne!(a, c);
        assert!(a.starts_with("av-"));
        assert!(a.len() <= 15);
    }

    #[test]
    fn deterministic_tunnel_listen_port_is_stable_and_nonzero() {
        let iface = "av-deadbeef";
        let p1 = deterministic_tunnel_listen_port(iface);
        let p2 = deterministic_tunnel_listen_port(iface);
        assert_eq!(p1, p2);
        assert_ne!(p1, 0);
    }

    #[test]
    fn canonical_underlay_ip_normalizes_ipv4_mapped_ipv6() {
        let mapped: IpAddr = "::ffff:10.1.2.3".parse().unwrap();
        let normalized = canonical_underlay_ip(mapped);
        assert_eq!(normalized, "10.1.2.3".parse::<IpAddr>().unwrap());
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::INFO.into()),
        )
        .init();

    let config_path = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/etc/avena/avenad.toml"));

    let config = if config_path.exists() {
        match AvenadConfig::load_from_file(&config_path) {
            Ok(c) => {
                info!(path = %config_path.display(), "Loaded configuration");
                c
            }
            Err(e) => {
                error!("Failed to load config: {}", e);
                std::process::exit(1);
            }
        }
    } else {
        info!("Using default configuration");
        AvenadConfig::default()
    };

    match Avenad::new(config).await {
        Ok(mut daemon) => {
            if let Err(e) = daemon.run().await {
                error!("Avenad error: {}", e);
                std::process::exit(1);
            }
        }
        Err(e) => {
            error!("Failed to initialize avenad: {}", e);
            std::process::exit(1);
        }
    }
}
