use avena_overlay::{
    derive_session_keys, derive_wireguard_keypair, AvenadConfig, DeviceId, DeviceKeypair,
    DiscoveredPeer, DiscoveryEvent, DiscoveryService, EphemeralKeypair, HandshakeMessage,
    KernelBackend, LocalAnnouncement, NetworkConfig, PeerConfig, PeerState, TunnelBackend,
    TunnelMode, UserspaceBackend,
};
use ed25519_dalek::VerifyingKey;
use ipnet::IpNet;
use lru::LruCache;
use std::collections::hash_map::Entry;
use std::collections::HashMap;
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
    tunnel: Arc<dyn TunnelBackend>,
    discovery: DiscoveryService,
    peers: RwLock<HashMap<DeviceId, PeerState>>,
    nonce_cache: NonceCache,
    rate_limiter: RateLimiter,
    handshake_semaphore: Arc<Semaphore>,
    outgoing_semaphore: Arc<Semaphore>,
}

struct Avenad {
    inner: Arc<AvenadInner>,
    discovery_rx: Option<tokio::sync::broadcast::Receiver<DiscoveryEvent>>,
    handshake_listener: TcpListener,
}

impl Avenad {
    async fn new(config: AvenadConfig) -> Result<Self, AvenadError> {
        validate_interface_name(&config.interface_name)?;

        let keypair = load_or_generate_keypair(&config)?;
        let device_id = keypair.device_id();
        info!(device_id = %device_id, "Initialized device identity");

        let wg_keys = derive_wireguard_keypair(&keypair);

        let network = config.network.clone();
        let overlay_ip = network.device_address(&device_id);
        info!(overlay_ip = %overlay_ip, "Overlay address");

        let tunnel: Arc<dyn TunnelBackend> = match config.tunnel_mode {
            TunnelMode::Kernel => Arc::new(KernelBackend::new()),
            TunnelMode::Userspace => Arc::new(UserspaceBackend::new()),
        };
        info!(mode = ?config.tunnel_mode, "Tunnel backend created");

        tunnel.ensure_interface(&config.interface_name).await?;
        tunnel.set_listen_port(config.listen_port).await?;
        tunnel.set_private_key(&*wg_keys.private).await?;

        assign_interface_address(&config.interface_name, overlay_ip)?;
        info!(interface = %config.interface_name, addr = %overlay_ip, "Assigned overlay address to interface");

        let discovery_config = config.to_discovery_config();
        let discovery = DiscoveryService::new(discovery_config)?;
        let discovery_rx = discovery.subscribe();
        discovery.start_mdns_browse()?;
        info!("Discovery service initialized");

        let wg_port = tunnel.listen_port().await.unwrap_or(config.listen_port);
        let handshake_port = wg_port + 1;
        let listen_addr: SocketAddr = config
            .listen_address
            .unwrap_or_else(|| format!("[::]:{}", handshake_port).parse().unwrap());
        let handshake_listener = TcpListener::bind(listen_addr).await?;
        info!(addr = %listen_addr, "Handshake listener bound");

        let inner = Arc::new(AvenadInner {
            config,
            keypair,
            wg_public: wg_keys.public,
            network,
            tunnel,
            discovery,
            peers: RwLock::new(HashMap::new()),
            nonce_cache: NonceCache::new(),
            rate_limiter: RateLimiter::new(Duration::from_secs(60)),
            handshake_semaphore: Arc::new(Semaphore::new(MAX_CONCURRENT_HANDSHAKES)),
            outgoing_semaphore: Arc::new(Semaphore::new(MAX_CONCURRENT_OUTGOING_HANDSHAKES)),
        });

        Ok(Self {
            inner,
            discovery_rx: Some(discovery_rx),
            handshake_listener,
        })
    }

    async fn run(&mut self) -> Result<(), AvenadError> {
        let mut discovery_rx = self.discovery_rx.take().expect("discovery_rx already taken");
        let inner = Arc::clone(&self.inner);

        inner.announce_presence().await?;

        for peer in inner.discovery.resolve_static_peers().await {
            info!(peer_id = %peer.device_id, endpoint = %peer.endpoint, "Resolved static peer");
            let inner_clone = Arc::clone(&inner);
            tokio::spawn(async move {
                if let Err(e) = inner_clone.handle_discovered_peer(peer).await {
                    warn!("Failed to connect to static peer: {}", e);
                }
            });
        }

        info!("Avenad running. Press Ctrl+C to stop.");

        let mut dead_peer_interval = tokio::time::interval(Duration::from_secs(inner.config.dead_peer_timeout_secs));
        dead_peer_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

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
                                        let mut peers = inner_clone.peers.write().await;
                                        if let Entry::Vacant(entry) = peers.entry(device_id) {
                                            entry.insert(peer_state);
                                            info!(peer_id = %device_id, "Peer connected via incoming handshake");
                                        } else {
                                            debug!(peer_id = %device_id, "Peer already connected, discarding duplicate handshake result");
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

impl AvenadInner {
    async fn announce_presence(&self) -> Result<(), AvenadError> {
        let wg_port = self.tunnel.listen_port().await.unwrap_or(self.config.listen_port);

        let ip = if let Some(ref iface) = self.config.discovery.mdns_interface {
            get_interface_ip(iface).unwrap_or_else(|| {
                warn!(interface = %iface, "Could not get IP for interface, using unspecified");
                IpAddr::from([0u8; 4])
            })
        } else {
            IpAddr::from([0u8; 4])
        };

        let announcement = LocalAnnouncement {
            device_id: self.keypair.device_id(),
            wg_endpoint: SocketAddr::new(ip, wg_port),
            capabilities: std::collections::HashSet::new(),
        };
        self.discovery.announce(&announcement).await?;
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
            if peers.contains_key(&peer.device_id) {
                debug!(peer_id = %peer.device_id, "Already connected to peer");
                return Ok(());
            }
        }

        info!(peer_id = %peer.device_id, "Initiating handshake");

        let handshake_addr = SocketAddr::new(peer.endpoint.ip(), peer.endpoint.port() + 1);
        let peer_state = self.perform_outgoing_handshake(handshake_addr, &peer).await?;

        let mut peers = self.peers.write().await;
        if let Entry::Vacant(entry) = peers.entry(peer.device_id) {
            entry.insert(peer_state);
            info!(peer_id = %peer.device_id, "Peer connected");
        } else {
            debug!(peer_id = %peer.device_id, "Peer already connected, discarding duplicate handshake result");
        }

        Ok(())
    }

    async fn perform_outgoing_handshake(
        &self,
        addr: SocketAddr,
        peer: &DiscoveredPeer,
    ) -> Result<PeerState, AvenadError> {
        tokio::time::timeout(HANDSHAKE_TIMEOUT, self.perform_outgoing_handshake_inner(addr, peer))
            .await
            .map_err(|_| AvenadError::Timeout)?
    }

    async fn perform_outgoing_handshake_inner(
        &self,
        addr: SocketAddr,
        peer: &DiscoveredPeer,
    ) -> Result<PeerState, AvenadError> {
        let mut stream = TcpStream::connect(addr).await?;

        let local_ephemeral = EphemeralKeypair::generate();
        let local_msg = HandshakeMessage::create(
            &self.keypair,
            &local_ephemeral,
            &peer.device_id,
            self.wg_public,
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
            .verify(&peer_pubkey, &self.keypair.device_id())
            .map_err(|e| AvenadError::Handshake(format!("signature verification failed: {}", e)))?;

        let peer_ephemeral = peer_msg.ephemeral_public_key();
        let our_keys = derive_session_keys(&local_ephemeral, &peer_ephemeral, true);
        let peer_wg_pubkey = peer_msg.wg_pubkey;
        let peer_overlay_ip = self.network.device_address(&peer.device_id);

        let peer_config = PeerConfig::new(peer_wg_pubkey)
            .with_psk(*our_keys.wireguard_psk)
            .with_allowed_ips(vec![IpNet::new(peer_overlay_ip.into(), 128).unwrap()])
            .with_endpoint(peer.endpoint)
            .with_keepalive(self.config.persistent_keepalive);

        self.tunnel.add_peer(&peer_config).await?;

        add_peer_route(&self.config.interface_name, peer_overlay_ip)?;

        Ok(PeerState::new(peer.device_id, peer_pubkey, peer_wg_pubkey, peer_overlay_ip)
            .with_endpoint(peer.endpoint))
    }

    async fn handle_incoming_handshake(
        &self,
        stream: TcpStream,
        addr: SocketAddr,
    ) -> Result<PeerState, AvenadError> {
        tokio::time::timeout(HANDSHAKE_TIMEOUT, self.handle_incoming_handshake_inner(stream, addr))
            .await
            .map_err(|_| AvenadError::Timeout)?
    }

    async fn handle_incoming_handshake_inner(
        &self,
        mut stream: TcpStream,
        addr: SocketAddr,
    ) -> Result<PeerState, AvenadError> {
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
            .verify(&peer_pubkey, &self.keypair.device_id())
            .map_err(|e| AvenadError::Handshake(format!("signature verification failed: {}", e)))?;

        if !self.nonce_cache.check_and_insert(peer_device_id, peer_msg.nonce).await {
            return Err(AvenadError::Handshake("replay detected".into()));
        }

        let local_ephemeral = EphemeralKeypair::generate();
        let local_msg = HandshakeMessage::create(
            &self.keypair,
            &local_ephemeral,
            &peer_device_id,
            self.wg_public,
        );

        stream.write_all(HANDSHAKE_MAGIC).await?;
        stream.write_u8(HANDSHAKE_VERSION).await?;

        let pubkey_bytes = self.keypair.public_key().to_bytes();
        stream.write_all(&pubkey_bytes).await?;

        let msg_bytes = serde_json::to_vec(&local_msg)?;
        stream.write_u32(msg_bytes.len() as u32).await?;
        stream.write_all(&msg_bytes).await?;

        let peer_ephemeral = peer_msg.ephemeral_public_key();
        let our_keys = derive_session_keys(&local_ephemeral, &peer_ephemeral, false);
        let peer_wg_pubkey = peer_msg.wg_pubkey;
        let peer_overlay_ip = self.network.device_address(&peer_device_id);

        let peer_wg_endpoint = self.discovery
            .get_discovered_endpoint(&peer_device_id)
            .unwrap_or_else(|| {
                warn!(peer_id = %peer_device_id, "No discovered endpoint, using connection address");
                SocketAddr::new(addr.ip(), addr.port() - 1)
            });

        let peer_config = PeerConfig::new(peer_wg_pubkey)
            .with_psk(*our_keys.wireguard_psk)
            .with_allowed_ips(vec![IpNet::new(peer_overlay_ip.into(), 128).unwrap()])
            .with_endpoint(peer_wg_endpoint)
            .with_keepalive(self.config.persistent_keepalive);

        self.tunnel.add_peer(&peer_config).await?;

        add_peer_route(&self.config.interface_name, peer_overlay_ip)?;

        Ok(PeerState::new(peer_device_id, peer_pubkey, peer_wg_pubkey, peer_overlay_ip)
            .with_endpoint(peer_wg_endpoint))
    }

    async fn handle_peer_lost(&self, device_id: &DeviceId) {
        let mut peers = self.peers.write().await;
        if let Some(peer) = peers.remove(device_id) {
            if let Err(e) = self.tunnel.remove_peer(&peer.wg_pubkey).await {
                warn!(peer_id = %device_id, "Failed to remove peer from tunnel: {}", e);
            }
        }
    }

    async fn check_dead_peers(&self) {
        let timeout = Duration::from_secs(self.config.dead_peer_timeout_secs);
        let mut to_remove = Vec::new();

        {
            let peers = self.peers.read().await;
            for (id, state) in peers.iter() {
                match self.tunnel.peer_stats(&state.wg_pubkey).await {
                    Ok(stats) => {
                        if let Some(last_handshake) = stats.last_handshake {
                            if let Ok(elapsed) = last_handshake.elapsed() {
                                if elapsed > timeout {
                                    to_remove.push(*id);
                                }
                            }
                        }
                    }
                    Err(_) => {
                        if state.time_since_last_seen() > timeout {
                            to_remove.push(*id);
                        }
                    }
                }
            }
        }

        for id in to_remove {
            warn!(peer_id = %id, "Removing dead peer");
            self.handle_peer_lost(&id).await;
        }
    }

    async fn shutdown(&self) {
        info!("Shutting down avenad...");
        let peers = self.peers.read().await;
        for (id, peer) in peers.iter() {
            if let Err(e) = self.tunnel.remove_peer(&peer.wg_pubkey).await {
                warn!(peer_id = %id, "Failed to remove peer during shutdown: {}", e);
            }
        }
    }
}

fn validate_interface_name(name: &str) -> Result<(), AvenadError> {
    if name.is_empty() {
        return Err(AvenadError::Config("interface name cannot be empty".into()));
    }
    if name.len() > 15 {
        return Err(AvenadError::Config("interface name too long (max 15 chars)".into()));
    }
    if name.starts_with('-') {
        return Err(AvenadError::Config("interface name cannot start with '-'".into()));
    }
    if !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-') {
        return Err(AvenadError::Config("interface name contains invalid characters".into()));
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

#[cfg(target_os = "linux")]
fn assign_interface_address(
    interface_name: &str,
    addr: std::net::Ipv6Addr,
) -> Result<(), std::io::Error> {
    use avena_overlay::wg::linux::netlink;

    netlink::add_ipv6_address(interface_name, addr, 128).map_err(|e| {
        std::io::Error::new(std::io::ErrorKind::Other, format!("add address: {e}"))
    })?;

    netlink::set_link_up(interface_name).map_err(|e| {
        std::io::Error::new(std::io::ErrorKind::Other, format!("set link up: {e}"))
    })?;

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

fn add_peer_route(
    interface_name: &str,
    peer_addr: std::net::Ipv6Addr,
) -> Result<(), std::io::Error> {
    use std::process::Command;

    let addr_str = format!("{}/128", peer_addr);
    let output = Command::new("ip")
        .args(["-6", "route", "add", &addr_str, "dev", interface_name])
        .output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if !stderr.contains("File exists") {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("failed to add route: {}", stderr),
            ));
        }
    }

    Ok(())
}

fn get_interface_ip(interface_name: &str) -> Option<IpAddr> {
    let output = std::process::Command::new("ip")
        .args(["-4", "-o", "addr", "show", interface_name])
        .output()
        .ok()?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if let Some(idx) = parts.iter().position(|&s| s == "inet") {
            if let Some(addr_cidr) = parts.get(idx + 1) {
                if let Some(addr_str) = addr_cidr.split('/').next() {
                    if let Ok(ip) = addr_str.parse::<IpAddr>() {
                        return Some(ip);
                    }
                }
            }
        }
    }
    None
}

#[derive(Debug)]
enum AvenadError {
    Config(String),
    Tunnel(avena_overlay::TunnelError),
    Discovery(avena_overlay::DiscoveryError),
    Io(std::io::Error),
    Handshake(String),
    Json(serde_json::Error),
    Timeout,
}

impl std::fmt::Display for AvenadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AvenadError::Config(e) => write!(f, "config error: {}", e),
            AvenadError::Tunnel(e) => write!(f, "tunnel error: {}", e),
            AvenadError::Discovery(e) => write!(f, "discovery error: {}", e),
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
