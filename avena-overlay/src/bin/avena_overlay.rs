use avena_overlay::{
    acme::{AcmeRuntime, DiscoveryPayload as AcmeDiscoveryPayload, IncomingControlRequest},
    derive_session_keys, derive_wireguard_keypair,
    routing::{BabeldController, RoutingError},
    wg::WgError,
    Capability, CertValidator, DeviceId, DeviceKeypair, DiscoveredPeer, DiscoveryEvent,
    DiscoveryService, EphemeralKeypair, HandshakeMessage, KernelBackend, LocalAnnouncement,
    NetworkConfig, OverlayConfig, PeerConfig, PeerLocator, PeerPathId, PeerState,
    TunnelBackend, TunnelMode, UserspaceBackend,
};
use ed25519_dalek::VerifyingKey;
use ipnet::IpNet;
use lru::LruCache;
use serde::Serialize;
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
use tokio::sync::{Mutex, RwLock, Semaphore, mpsc};
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
const OUTGOING_HANDSHAKE_COOLDOWN: Duration = Duration::from_secs(10);
const OUTGOING_HANDSHAKE_REFRESH_AFTER: Duration = Duration::from_secs(5);
const TUNNEL_PORT_BASE: u16 = 20000;
const TUNNEL_PORT_SPAN: u16 = 40000;
const TELEMETRY_SCHEMA_VERSION: u8 = 1;
const DEFAULT_TELEMETRY_RUN_ID: &str = "standalone";
const DEFAULT_TELEMETRY_TOKEN: &str = "unknown";

fn encode_handshake_packet(
    public_key: &[u8; 32],
    message: &HandshakeMessage,
) -> Result<Vec<u8>, OverlayDaemonError> {
    let message_bytes = serde_json::to_vec(message)?;
    let mut out = Vec::with_capacity(4 + 1 + 32 + 4 + message_bytes.len());
    out.extend_from_slice(HANDSHAKE_MAGIC);
    out.push(HANDSHAKE_VERSION);
    out.extend_from_slice(public_key);
    out.extend_from_slice(&(message_bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(&message_bytes);
    Ok(out)
}

fn decode_handshake_packet(
    packet: &[u8],
) -> Result<(VerifyingKey, DeviceId, HandshakeMessage), OverlayDaemonError> {
    const HEADER_LEN: usize = 4 + 1 + 32 + 4;
    if packet.len() < HEADER_LEN {
        return Err(OverlayDaemonError::Handshake(
            "handshake packet too short".into(),
        ));
    }
    if &packet[..4] != HANDSHAKE_MAGIC {
        return Err(OverlayDaemonError::Handshake("invalid magic".into()));
    }
    if packet[4] != HANDSHAKE_VERSION {
        return Err(OverlayDaemonError::Handshake("version mismatch".into()));
    }
    let peer_pubkey = VerifyingKey::from_bytes(
        &packet[5..37]
            .try_into()
            .expect("fixed-size handshake public key"),
    )
    .map_err(|_| OverlayDaemonError::Handshake("invalid peer public key".into()))?;
    let peer_device_id = DeviceId::from_public_key(&peer_pubkey);
    let msg_len = u32::from_be_bytes(
        packet[37..41]
            .try_into()
            .expect("fixed-size handshake length"),
    ) as usize;
    if msg_len > MAX_HANDSHAKE_MSG_LEN {
        return Err(OverlayDaemonError::Handshake("message too large".into()));
    }
    if packet.len() != HEADER_LEN + msg_len {
        return Err(OverlayDaemonError::Handshake(
            "truncated handshake packet".into(),
        ));
    }
    let message = serde_json::from_slice(&packet[HEADER_LEN..])?;
    Ok((peer_pubkey, peer_device_id, message))
}

async fn read_handshake_packet(
    stream: &mut TcpStream,
) -> Result<(VerifyingKey, DeviceId, HandshakeMessage), OverlayDaemonError> {
    let mut header = [0u8; 41];
    stream.read_exact(&mut header).await?;
    let msg_len = u32::from_be_bytes(header[37..41].try_into().expect("fixed width")) as usize;
    if msg_len > MAX_HANDSHAKE_MSG_LEN {
        return Err(OverlayDaemonError::Handshake("message too large".into()));
    }
    let mut packet = header.to_vec();
    packet.resize(41 + msg_len, 0);
    stream.read_exact(&mut packet[41..]).await?;
    decode_handshake_packet(&packet)
}

fn sanitize_subject_token(raw: &str, fallback: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut prev_dash = false;

    for ch in raw.chars() {
        if ch.is_ascii_alphanumeric() || ch == '_' || ch == '-' {
            out.push(ch.to_ascii_lowercase());
            prev_dash = false;
        } else if !prev_dash {
            out.push('-');
            prev_dash = true;
        }
    }

    let trimmed = out.trim_matches('-');
    if trimmed.is_empty() {
        fallback.to_string()
    } else {
        trimmed.to_string()
    }
}

#[derive(Debug, Serialize)]
struct TelemetryEnvelope {
    v: u8,
    subject: String,
    ts_ms: u64,
    run_id: String,
    source: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    node: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    radio: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    peer: Option<String>,
    data: serde_json::Value,
}

#[derive(Debug)]
struct TelemetryPublisher {
    client: Option<async_nats::Client>,
    run_id: String,
    node_id: String,
    started_at: Instant,
}

impl TelemetryPublisher {
    async fn new(config: &OverlayConfig, fallback_node_id: String) -> Self {
        let run_id = config
            .telemetry
            .run_id
            .clone()
            .or_else(|| std::env::var("AVENA_RUN_ID").ok())
            .map(|id| sanitize_subject_token(&id, DEFAULT_TELEMETRY_RUN_ID))
            .unwrap_or_else(|| DEFAULT_TELEMETRY_RUN_ID.to_string());
        let node_id = config
            .telemetry
            .node_id
            .clone()
            .map(|id| sanitize_subject_token(&id, DEFAULT_TELEMETRY_TOKEN))
            .unwrap_or_else(|| sanitize_subject_token(&fallback_node_id, DEFAULT_TELEMETRY_TOKEN));

        if !config.telemetry.publish_nats {
            return Self {
                client: None,
                run_id,
                node_id,
                started_at: Instant::now(),
            };
        }

        let nats_url = config
            .telemetry
            .nats_url
            .as_ref()
            .map(|url| url.trim().to_string())
            .filter(|url| !url.is_empty())
            .or_else(|| std::env::var("AVENA_NATS_URL").ok());

        let client = match nats_url {
            Some(url) => match async_nats::connect(&url).await {
                Ok(client) => Some(client),
                Err(err) => {
                    warn!(url = %url, "Failed to connect telemetry NATS: {}", err);
                    None
                }
            },
            None => {
                warn!("Telemetry enabled but no NATS URL configured");
                None
            }
        };

        Self {
            client,
            run_id,
            node_id,
            started_at: Instant::now(),
        }
    }

    fn overlay_subject(&self, event: &str) -> String {
        let event = sanitize_subject_token(event, DEFAULT_TELEMETRY_TOKEN);
        format!(
            "avena.v1.{}.node.{}.overlay.{}",
            self.run_id, self.node_id, event
        )
    }

    fn babel_subject(&self, topic: &str) -> String {
        let topic = sanitize_subject_token(topic, DEFAULT_TELEMETRY_TOKEN);
        format!(
            "avena.v1.{}.node.{}.routing.babel.{}",
            self.run_id, self.node_id, topic
        )
    }

    async fn publish_overlay(&self, event: &str, data: serde_json::Value) {
        let subject = self.overlay_subject(event);
        self.publish_subject(subject, data).await;
    }

    async fn publish_babel_routes(&self, routes: serde_json::Value) {
        let subject = self.babel_subject("routes");
        self.publish_subject(subject, routes).await;
    }

    async fn publish_babel_neighbours(&self, neighbours: serde_json::Value) {
        let subject = self.babel_subject("neighbors");
        self.publish_subject(subject, neighbours).await;
    }

    async fn publish_subject(&self, subject: String, data: serde_json::Value) {
        let Some(client) = &self.client else {
            return;
        };

        let envelope = TelemetryEnvelope {
            v: TELEMETRY_SCHEMA_VERSION,
            subject: subject.clone(),
            ts_ms: self.started_at.elapsed().as_millis() as u64,
            run_id: self.run_id.clone(),
            source: "avena-overlay".to_string(),
            node: Some(self.node_id.clone()),
            radio: data
                .get("radio")
                .and_then(serde_json::Value::as_str)
                .map(str::to_string),
            peer: data
                .get("peer")
                .or_else(|| data.get("peer_id"))
                .and_then(serde_json::Value::as_str)
                .map(str::to_string),
            data,
        };

        let payload = match serde_json::to_vec(&envelope) {
            Ok(payload) => payload,
            Err(err) => {
                warn!(subject = %subject, "Failed to serialize telemetry event: {}", err);
                return;
            }
        };

        if let Err(err) = client.publish(subject.clone(), payload.into()).await {
            warn!(subject = %subject, "Failed to publish telemetry event: {}", err);
        }
    }
}

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

struct OverlayDaemonInner {
    config: OverlayConfig,
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
    outgoing_handshake_inflight: Mutex<HashSet<PeerPathId>>,
    outgoing_handshake_last_attempt: Mutex<HashMap<PeerPathId, Instant>>,
    cert_validator: CertValidator,
    device_cert: String,
    routing: Mutex<Option<BabeldController>>,
    overlay_route_rx_bytes: Mutex<HashMap<String, u64>>,
    telemetry: Arc<TelemetryPublisher>,
    acme: Option<AcmeRuntime>,
}

struct OverlayDaemon {
    inner: Arc<OverlayDaemonInner>,
    discovery_rx: Option<tokio::sync::broadcast::Receiver<DiscoveryEvent>>,
    handshake_listener: TcpListener,
    acme_control_rx: Option<tokio::sync::mpsc::Receiver<IncomingControlRequest>>,
    acme_discovery_rx: Option<tokio::sync::mpsc::Receiver<AcmeDiscoveryPayload>>,
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
fn resolve_local_underlay_identifier(local_ip: IpAddr) -> Result<String, OverlayDaemonError> {
    use avena_overlay::wg::linux::netlink;

    let canonical_ip = canonical_underlay_ip(local_ip);
    netlink::get_interface_name_for_ip(canonical_ip).ok_or_else(|| {
        OverlayDaemonError::Handshake(format!(
            "strict underlay resolution failed for local IP {}",
            canonical_ip
        ))
    })
}

#[cfg(not(target_os = "linux"))]
fn resolve_local_underlay_identifier(local_ip: IpAddr) -> Result<String, OverlayDaemonError> {
    Err(OverlayDaemonError::Handshake(format!(
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

impl OverlayDaemon {
    async fn new(config: OverlayConfig) -> Result<Self, OverlayDaemonError> {
        validate_interface_name(&config.interface_name)?;

        if let Err(e) = try_raise_nofile_limit() {
            warn!("Failed to raise NOFILE limit: {}", e);
        }

        let keypair = load_or_generate_keypair(&config)?;
        let device_id = keypair.device_id();
        info!(device_id = %device_id, "Initialized device identity");

        let (cert_validator, device_cert) =
            config.load_crypto().map_err(OverlayDaemonError::CertConfig)?;
        info!("Loaded device certificate");

        let wg_keys = derive_wireguard_keypair(&keypair);

        let network = config.network.clone();
        let overlay_ip = network.device_address(&device_id);
        info!(overlay_ip = %overlay_ip, "Overlay address");

        let base_tunnel =
            select_tunnel_backend(config.tunnel_mode.clone(), &config.interface_name, "base")
                .await?;
        info!(mode = ?config.tunnel_mode, "Tunnel backend selected");

        // If initialization fails after we've created/attached to a tunnel
        // interface (especially in userspace mode where this spawns
        // `wireguard-go`), make a best-effort attempt to clean up so we don't
        // leave a stray process/interface behind.
        let init_result: Result<
            (
                DiscoveryService,
                tokio::sync::broadcast::Receiver<DiscoveryEvent>,
                TcpListener,
                Option<BabeldController>,
                Option<AcmeRuntime>,
                Option<mpsc::Receiver<IncomingControlRequest>>,
                Option<mpsc::Receiver<AcmeDiscoveryPayload>>,
            ),
            OverlayDaemonError,
        > = async {
            base_tunnel.set_private_key(&*wg_keys.private).await?;
            base_tunnel.set_listen_port(config.listen_port).await?;

            assign_interface_address(&config.interface_name, overlay_ip)?;
            info!(interface = %config.interface_name, addr = %overlay_ip, "Assigned overlay address to interface");

        let mut discovery_config = config.to_discovery_config();

        // If no mDNS interfaces are explicitly configured, avoid binding mDNS
        // to the overlay interface by default. Some kernels reject sending
        // multicast from tunnel interfaces (e.g. ENOKEY / "Required key not available").
        if discovery_config.enable_mdns && discovery_config.mdns_interfaces.is_empty() {
            discovery_config.mdns_interfaces = default_mdns_interfaces(&config.interface_name);
        }
        let discovery = DiscoveryService::new(discovery_config)?;
        let discovery_rx = discovery.subscribe();
        discovery.start_mdns_browse()?;
        info!("Discovery service initialized");

            let (acme, acme_control_rx, acme_discovery_rx) = if let Some(acme_config) = config.acme.clone() {
                let (runtime, control_rx, discovery_rx) =
                    AcmeRuntime::start(acme_config, device_id).await
                        .map_err(|e| OverlayDaemonError::Acme(e.to_string()))?;
                info!(proxy = %runtime.shared_proxy_endpoint(), underlay = runtime.underlay_id(), "ACME runtime started");
                (Some(runtime), Some(control_rx), Some(discovery_rx))
            } else {
                (None, None, None)
            };

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

            Ok((
                discovery,
                discovery_rx,
                handshake_listener,
                routing,
                acme,
                acme_control_rx,
                acme_discovery_rx,
            ))
        }
        .await;

        let (discovery, discovery_rx, handshake_listener, routing, acme, acme_control_rx, acme_discovery_rx) = match init_result {
            Ok(v) => v,
            Err(e) => {
                let _ = base_tunnel.remove_interface().await;
                return Err(e);
            }
        };

        let telemetry =
            Arc::new(TelemetryPublisher::new(&config, keypair.device_id().to_string()).await);

        let inner = Arc::new(OverlayDaemonInner {
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
            outgoing_handshake_inflight: Mutex::new(HashSet::new()),
            outgoing_handshake_last_attempt: Mutex::new(HashMap::new()),
            cert_validator,
            device_cert,
            routing: Mutex::new(routing),
            overlay_route_rx_bytes: Mutex::new(HashMap::new()),
            telemetry,
            acme,
        });

        Ok(Self {
            inner,
            discovery_rx: Some(discovery_rx),
            handshake_listener,
            acme_control_rx,
            acme_discovery_rx,
        })
    }

    async fn run(&mut self) -> Result<(), OverlayDaemonError> {
        let mut discovery_rx = self
            .discovery_rx
            .take()
            .expect("discovery_rx already taken");
        let inner = Arc::clone(&self.inner);

        inner.announce_presence().await?;

        for peer in inner.discovery.resolve_static_peers().await {
            info!(peer_id = %peer.device_id, locator = %peer.locator.describe(), "Resolved static peer");
            inner.discovery.cache_discovered_peer(&peer);
            let inner_clone = Arc::clone(&inner);
            tokio::spawn(async move {
                if let Err(e) = inner_clone.handle_discovered_peer(peer).await {
                    warn!("Failed to connect to static peer: {}", e);
                }
            });
        }

        info!("avena-overlay running. Press Ctrl+C to stop.");

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

        let mut babel_snapshot_interval = tokio::time::interval(Duration::from_secs(
            inner.config.telemetry.babel_snapshot_interval_secs.max(1),
        ));
        babel_snapshot_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        babel_snapshot_interval.tick().await;

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

                                info!(peer_id = %peer.device_id, locator = %peer.locator.describe(), "Peer discovered");
                                inner
                                    .telemetry
                                    .publish_overlay(
                                        "peer_discovered",
                                        serde_json::json!({
                                            "peer_id": peer.device_id.to_string(),
                                            "locator": peer.locator.describe(),
                                        }),
                                    )
                                    .await;
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
                            inner
                                .telemetry
                                .publish_overlay(
                                    "peer_disconnected",
                                    serde_json::json!({
                                        "peer_id": device_id.to_string(),
                                        "reason": "peer_lost",
                                    }),
                                )
                                .await;
                            inner.handle_peer_lost(&device_id).await;
                        }
                        Err(e) => {
                            debug!("Discovery channel error: {}", e);
                        }
                    }
                }
                Some(payload) = async { match &mut self.acme_discovery_rx { Some(rx) => rx.recv().await, None => None } } => {
                    if payload.device_id == inner.keypair.device_id() {
                        continue;
                    }
                    let Some(acme) = &inner.acme else {
                        continue;
                    };
                    let peer = DiscoveredPeer::new(
                        payload.device_id,
                        PeerLocator::Acme {
                            underlay_id: payload.underlay_id.clone(),
                            proxy_endpoint: acme.shared_proxy_endpoint(),
                            node_name: payload.node_name.clone(),
                        },
                        payload.capabilities(),
                        avena_overlay::DiscoverySource::Acme,
                    )
                    .with_node_name(payload.node_name);
                    inner.discovery.cache_discovered_peer(&peer);
                    if let Err(err) = inner.handle_discovered_peer(peer).await {
                        warn!("Failed to handle discovered ACME peer: {}", err);
                    }
                }
                Some(request) = async { match &mut self.acme_control_rx { Some(rx) => rx.recv().await, None => None } } => {
                    let Some(acme) = &inner.acme else {
                        continue;
                    };
                    match inner.handle_incoming_acme_handshake(&request).await {
                        Ok((peer_state, response_packet)) => {
                            let device_id = peer_state.device_id;
                            let iface = peer_state.tunnel_interface.clone();
                            let mut peers = inner.peers.write().await;
                            match peers.entry(iface.clone()) {
                                Entry::Vacant(entry) => {
                                    entry.insert(peer_state);
                                    info!(peer_id = %device_id, iface = %iface, "Peer connected via incoming ACME control");
                                }
                                Entry::Occupied(mut entry) => {
                                    *entry.get_mut() = peer_state;
                                    info!(peer_id = %device_id, iface = %iface, "Peer refreshed via incoming ACME control");
                                }
                            }
                            drop(peers);
                            if let Err(err) = acme.send_control_response(device_id, request.request_id, &response_packet).await {
                                warn!(peer_id = %device_id, "Failed to send ACME control response: {}", err);
                            }
                            if let Err(err) = inner.reconcile_peer_allowed_ips().await {
                                warn!(peer_id = %device_id, "Failed to reconcile peer allowed-ips after ACME handshake: {}", err);
                            }
                        }
                        Err(err) => {
                            warn!(peer_id = %request.source, "Incoming ACME handshake failed: {}", err);
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
                            inner
                                .telemetry
                                .publish_overlay(
                                    "handshake_started",
                                    serde_json::json!({
                                        "direction": "incoming",
                                        "addr": addr.to_string(),
                                    }),
                                )
                                .await;
                            let inner_clone = Arc::clone(&inner);
                            tokio::spawn(async move {
                                let _permit = permit;
                                match inner_clone.handle_incoming_handshake(stream, addr).await {
                                    Ok(peer_state) => {
                                        let device_id = peer_state.device_id;
                                        let iface = peer_state.tunnel_interface.clone();
                                        let mut peers = inner_clone.peers.write().await;
                                        let mut inserted = false;
                                        match peers.entry(iface.clone()) {
                                            Entry::Vacant(entry) => {
                                                entry.insert(peer_state);
                                                inserted = true;
                                                info!(peer_id = %device_id, iface = %iface, "Peer connected via incoming handshake");
                                                inner_clone
                                                    .telemetry
                                                    .publish_overlay(
                                                        "peer_connected",
                                                        serde_json::json!({
                                                            "peer_id": device_id.to_string(),
                                                            "iface": iface,
                                                            "direction": "incoming",
                                                            "inserted": inserted,
                                                        }),
                                                    )
                                                    .await;
                                            }
                                            Entry::Occupied(mut entry) => {
                                                *entry.get_mut() = peer_state;
                                                info!(peer_id = %device_id, iface = %iface, "Peer refreshed via incoming handshake");
                                                inner_clone
                                                    .telemetry
                                                    .publish_overlay(
                                                        "peer_connected",
                                                        serde_json::json!({
                                                            "peer_id": device_id.to_string(),
                                                            "iface": iface,
                                                            "direction": "incoming",
                                                            "inserted": inserted,
                                                        }),
                                                    )
                                                    .await;
                                            }
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
                _ = babel_snapshot_interval.tick() => {
                    inner.publish_babel_snapshot().await;
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

#[cfg(target_os = "linux")]
fn default_mdns_interfaces(overlay_iface: &str) -> Vec<String> {
    let mut out = Vec::new();
    let dir = match std::fs::read_dir("/sys/class/net") {
        Ok(d) => d,
        Err(_) => return out,
    };

    for entry in dir.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        if name == "lo" || name == overlay_iface {
            continue;
        }
        // Skip typical Avena tunnel interface prefixes.
        if name.starts_with("av-") {
            continue;
        }
        // Only include interfaces that are likely usable.
        let operstate_path = entry.path().join("operstate");
        let operstate = std::fs::read_to_string(operstate_path)
            .unwrap_or_default()
            .trim()
            .to_string();
        if !(operstate == "up" || operstate == "unknown") {
            continue;
        }
        out.push(name);
    }

    out.sort();
    out
}

#[cfg(not(target_os = "linux"))]
fn default_mdns_interfaces(_overlay_iface: &str) -> Vec<String> {
    Vec::new()
}

async fn start_routing_controller(config: &OverlayConfig) -> Result<BabeldController, OverlayDaemonError> {
    let mut controller = BabeldController::new(config.routing.babel.clone());
    controller.start(&[&config.interface_name]).await?;
    info!("Started babeld for dynamic routing");
    Ok(controller)
}

async fn select_tunnel_backend(
    mode: TunnelMode,
    interface_name: &str,
    context: &str,
) -> Result<Arc<dyn TunnelBackend>, OverlayDaemonError> {
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

    Err(OverlayDaemonError::Tunnel(last_err.unwrap_or_else(|| {
        avena_overlay::TunnelError::InterfaceCreation(
            "no tunnel backend could create interface".into(),
        )
    })))
}

impl OverlayDaemonInner {
    async fn ensure_peer_tunnel(
        &self,
        peer_id: &DeviceId,
        local_underlay_hint: &str,
    ) -> Result<PeerTunnelBinding, OverlayDaemonError> {
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
    ) -> Result<(), OverlayDaemonError> {
        let wg_keys = derive_wireguard_keypair(&self.keypair);
        tunnel.set_private_key(&*wg_keys.private).await?;
        tunnel.set_listen_port(listen_port).await?;

        let overlay_ip = self.network.device_address(&self.keypair.device_id());
        assign_interface_address(interface_name, overlay_ip)?;

        let mut routing = self.routing.lock().await;
        let controller = routing
            .as_mut()
            .ok_or_else(|| OverlayDaemonError::Routing(RoutingError::not_running()))?;
        controller.add_interface(interface_name).await?;
        Ok(())
    }

    async fn announce_presence(&self) -> Result<(), OverlayDaemonError> {
        let capabilities = HashSet::<Capability>::new();
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
                capabilities: capabilities.clone(),
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
                    capabilities: capabilities.clone(),
                    interface_suffix: Some(idx as u8),
                };
                debug!(interface = %iface, endpoint = %announcement.wg_endpoint, "Announcing on interface");
                self.discovery.announce(&announcement).await?;
            }
        }

        if let Some(acme) = &self.acme {
            let node_name = self
                .config
                .telemetry
                .node_id
                .clone()
                .or_else(|| Some(self.keypair.device_id().to_string()));
            let payload = AcmeDiscoveryPayload::new(
                self.keypair.device_id(),
                node_name,
                &capabilities,
                acme.underlay_id().to_string(),
            );
            acme.announce_discovery(&payload)
                .await
                .map_err(|e| OverlayDaemonError::Acme(e.to_string()))?;
        }
        Ok(())
    }

    async fn handle_discovered_peer(&self, peer: DiscoveredPeer) -> Result<(), OverlayDaemonError> {
        let should_initiate = self.keypair.device_id() > peer.device_id;
        if !should_initiate {
            debug!(peer_id = %peer.device_id, "Waiting for peer to initiate");
            return Ok(());
        }

        let path_id = peer.path_id();
        let locator_desc = peer.locator.describe();

        // Decide whether this discovery event should trigger a (re)handshake.
        // We use a short cooldown because mDNS can emit frequent resolves.
        let (already_connected, last_seen_elapsed) = {
            let peers = self.peers.read().await;
            let existing = peers.values().find(|state| {
                state.device_id == peer.device_id && state.locator.as_ref() == Some(&peer.locator)
            });
            match existing {
                Some(state) => (true, Some(state.time_since_last_seen())),
                None => (false, None),
            }
        };

        if already_connected {
            if let Some(elapsed) = last_seen_elapsed {
                if elapsed < OUTGOING_HANDSHAKE_REFRESH_AFTER {
                    debug!(
                        peer_id = %peer.device_id,
                        locator = %locator_desc,
                        last_seen_ms = elapsed.as_millis(),
                        "Peer endpoint already connected and recently active"
                    );
                    return Ok(());
                }
            }
        }

        {
            let mut last_attempt = self.outgoing_handshake_last_attempt.lock().await;
            if let Some(prev) = last_attempt.get(&path_id) {
                if prev.elapsed() < OUTGOING_HANDSHAKE_COOLDOWN {
                    debug!(
                        peer_id = %peer.device_id,
                        locator = %locator_desc,
                        cooldown_ms = OUTGOING_HANDSHAKE_COOLDOWN.as_millis(),
                        "Skipping outgoing handshake due to cooldown"
                    );
                    return Ok(());
                }
            }
            last_attempt.insert(path_id.clone(), Instant::now());
        }

        let inflight_key = path_id;
        {
            let mut inflight = self.outgoing_handshake_inflight.lock().await;
            if !inflight.insert(inflight_key.clone()) {
                debug!(
                    peer_id = %peer.device_id,
                    locator = %locator_desc,
                    "Outgoing handshake already in flight for peer endpoint"
                );
                return Ok(());
            }
        }

        info!(peer_id = %peer.device_id, "Initiating handshake");
        self.telemetry
            .publish_overlay(
                "handshake_started",
                serde_json::json!({
                    "direction": "outgoing",
                    "peer_id": peer.device_id.to_string(),
                    "locator": locator_desc,
                }),
            )
            .await;

        let handshake_result = self.perform_outgoing_handshake(&peer).await;
        {
            let mut inflight = self.outgoing_handshake_inflight.lock().await;
            inflight.remove(&inflight_key);
        }
        let peer_state = handshake_result?;

        let iface = peer_state.tunnel_interface.clone();
        let mut peers = self.peers.write().await;
        match peers.entry(iface.clone()) {
            Entry::Vacant(entry) => {
                entry.insert(peer_state);
                info!(peer_id = %peer.device_id, iface = %iface, "Peer connected");
                self.telemetry
                    .publish_overlay(
                        "peer_connected",
                        serde_json::json!({
                            "peer_id": peer.device_id.to_string(),
                            "iface": iface,
                            "direction": "outgoing",
                            "inserted": true,
                        }),
                    )
                    .await;
            }
            Entry::Occupied(mut entry) => {
                *entry.get_mut() = peer_state;
                info!(peer_id = %peer.device_id, iface = %iface, "Peer refreshed");
                self.telemetry
                    .publish_overlay(
                        "peer_connected",
                        serde_json::json!({
                            "peer_id": peer.device_id.to_string(),
                            "iface": iface,
                            "direction": "outgoing",
                            "inserted": false,
                        }),
                    )
                    .await;
            }
        }
        drop(peers);

        self.reconcile_peer_allowed_ips().await?;

        Ok(())
    }

    async fn perform_outgoing_handshake(
        &self,
        peer: &DiscoveredPeer,
    ) -> Result<PeerState, OverlayDaemonError> {
        tokio::time::timeout(
            HANDSHAKE_TIMEOUT,
            self.perform_outgoing_handshake_inner(peer),
        )
        .await
        .map_err(|_| OverlayDaemonError::Timeout)?
    }

    async fn perform_outgoing_handshake_inner(
        &self,
        peer: &DiscoveredPeer,
    ) -> Result<PeerState, OverlayDaemonError> {
        match &peer.locator {
            PeerLocator::DirectIp { endpoint } => {
                let handshake_addr = peer
                    .locator
                    .handshake_address()
                    .ok_or_else(|| OverlayDaemonError::Handshake("missing direct handshake address".into()))?;
                let mut stream = TcpStream::connect(handshake_addr).await?;
                let local_underlay_hint =
                    resolve_local_underlay_identifier(stream.local_addr()?.ip())?;
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
                let packet = encode_handshake_packet(&self.keypair.public_key().to_bytes(), &local_msg)?;
                stream.write_all(&packet).await?;
                let (peer_pubkey, peer_device_id, peer_msg) = read_handshake_packet(&mut stream).await?;
                if peer_device_id != peer.device_id {
                    return Err(OverlayDaemonError::Handshake("device id mismatch".into()));
                }
                peer_msg
                    .verify(
                        &peer_pubkey,
                        &self.keypair.device_id(),
                        &self.cert_validator,
                    )
                    .map_err(|e| OverlayDaemonError::Handshake(format!("handshake verification failed: {}", e)))?;
                let peer_wg_endpoint = SocketAddr::new(canonical_underlay_ip(endpoint.ip()), peer_msg.wg_listen_port);
                self
                    .finalize_peer_handshake(
                        binding,
                        peer.device_id,
                        peer_pubkey,
                        peer_msg,
                        local_ephemeral,
                        peer_wg_endpoint,
                        peer.locator.clone(),
                    )
                    .await
            }
            PeerLocator::Acme {
                underlay_id,
                proxy_endpoint,
                ..
            } => {
                let acme = self
                    .acme
                    .as_ref()
                    .ok_or_else(|| OverlayDaemonError::Acme("ACME runtime not available".into()))?;
                let binding = self.ensure_peer_tunnel(&peer.device_id, underlay_id).await?;
                acme.register_peer_tunnel(peer.device_id, binding.listen_port).await;
                let local_ephemeral = EphemeralKeypair::generate();
                let local_msg = HandshakeMessage::create(
                    &self.keypair,
                    &local_ephemeral,
                    &peer.device_id,
                    self.wg_public,
                    binding.listen_port,
                    &self.device_cert,
                );
                let packet = encode_handshake_packet(&self.keypair.public_key().to_bytes(), &local_msg)?;
                let response = acme
                    .request_control(peer.device_id, &packet)
                    .await
                    .map_err(|e| OverlayDaemonError::Acme(e.to_string()))?;
                let (peer_pubkey, peer_device_id, peer_msg) = decode_handshake_packet(&response)?;
                if peer_device_id != peer.device_id {
                    return Err(OverlayDaemonError::Handshake("device id mismatch".into()));
                }
                peer_msg
                    .verify(
                        &peer_pubkey,
                        &self.keypair.device_id(),
                        &self.cert_validator,
                    )
                    .map_err(|e| OverlayDaemonError::Handshake(format!("handshake verification failed: {}", e)))?;
                self
                    .finalize_peer_handshake(
                        binding,
                        peer.device_id,
                        peer_pubkey,
                        peer_msg,
                        local_ephemeral,
                        *proxy_endpoint,
                        peer.locator.clone(),
                    )
                    .await
            }
        }
    }

    async fn handle_incoming_handshake(
        &self,
        stream: TcpStream,
        addr: SocketAddr,
    ) -> Result<PeerState, OverlayDaemonError> {
        tokio::time::timeout(
            HANDSHAKE_TIMEOUT,
            self.handle_incoming_handshake_inner(stream, addr),
        )
        .await
        .map_err(|_| OverlayDaemonError::Timeout)?
    }

    async fn handle_incoming_handshake_inner(
        &self,
        mut stream: TcpStream,
        addr: SocketAddr,
    ) -> Result<PeerState, OverlayDaemonError> {
        let local_underlay_hint = resolve_local_underlay_identifier(stream.local_addr()?.ip())?;

        let (peer_pubkey, peer_device_id, peer_msg) = read_handshake_packet(&mut stream).await?;

        peer_msg
            .verify(
                &peer_pubkey,
                &self.keypair.device_id(),
                &self.cert_validator,
            )
            .map_err(|e| OverlayDaemonError::Handshake(format!("handshake verification failed: {}", e)))?;

        if !self
            .nonce_cache
            .check_and_insert(peer_device_id, peer_msg.nonce)
            .await
        {
            return Err(OverlayDaemonError::Handshake("replay detected".into()));
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
        let response_packet =
            encode_handshake_packet(&self.keypair.public_key().to_bytes(), &local_msg)?;
        stream.write_all(&response_packet).await?;

        let peer_wg_endpoint = SocketAddr::new(canonical_underlay_ip(addr.ip()), peer_msg.wg_listen_port);
        self
            .finalize_peer_handshake(
                binding,
                peer_device_id,
                peer_pubkey,
                peer_msg,
                local_ephemeral,
                peer_wg_endpoint,
                PeerLocator::direct_ip(peer_wg_endpoint),
            )
            .await
    }

    async fn handle_incoming_acme_handshake(
        &self,
        request: &IncomingControlRequest,
    ) -> Result<(PeerState, Vec<u8>), OverlayDaemonError> {
        let acme = self
            .acme
            .as_ref()
            .ok_or_else(|| OverlayDaemonError::Acme("ACME runtime not available".into()))?;
        let (peer_pubkey, peer_device_id, peer_msg) = decode_handshake_packet(&request.payload)?;
        if peer_device_id != request.source {
            return Err(OverlayDaemonError::Handshake(
                "ACME control source and device id mismatch".into(),
            ));
        }
        peer_msg
            .verify(
                &peer_pubkey,
                &self.keypair.device_id(),
                &self.cert_validator,
            )
            .map_err(|e| OverlayDaemonError::Handshake(format!("handshake verification failed: {}", e)))?;
        if !self
            .nonce_cache
            .check_and_insert(peer_device_id, peer_msg.nonce)
            .await
        {
            return Err(OverlayDaemonError::Handshake("replay detected".into()));
        }

        let binding = self.ensure_peer_tunnel(&peer_device_id, acme.underlay_id()).await?;
        acme.register_peer_tunnel(peer_device_id, binding.listen_port).await;

        let local_ephemeral = EphemeralKeypair::generate();
        let local_msg = HandshakeMessage::create(
            &self.keypair,
            &local_ephemeral,
            &peer_device_id,
            self.wg_public,
            binding.listen_port,
            &self.device_cert,
        );
        let response_packet =
            encode_handshake_packet(&self.keypair.public_key().to_bytes(), &local_msg)?;
        let peer_wg_endpoint = acme.shared_proxy_endpoint();
        let peer_state = self
            .finalize_peer_handshake(
                binding,
                peer_device_id,
                peer_pubkey,
                peer_msg,
                local_ephemeral,
                peer_wg_endpoint,
                PeerLocator::Acme {
                    underlay_id: acme.underlay_id().to_string(),
                    proxy_endpoint: peer_wg_endpoint,
                    node_name: None,
                },
            )
            .await?;
        Ok((peer_state, response_packet))
    }

    async fn finalize_peer_handshake(
        &self,
        binding: PeerTunnelBinding,
        peer_device_id: DeviceId,
        peer_pubkey: VerifyingKey,
        peer_msg: HandshakeMessage,
        local_ephemeral: EphemeralKeypair,
        peer_wg_endpoint: SocketAddr,
        locator: PeerLocator,
    ) -> Result<PeerState, OverlayDaemonError> {
        let peer_ephemeral = peer_msg.ephemeral_public_key();
        let our_keys = derive_session_keys(&local_ephemeral, &peer_ephemeral);
        let peer_wg_pubkey = peer_msg.wg_pubkey;
        let peer_overlay_ip = self.network.device_address(&peer_device_id);

        let allowed_ips = universal_peer_allowed_ips();
        let peer_config = PeerConfig::new(peer_wg_pubkey)
            .with_psk(*our_keys.wireguard_psk)
            .with_allowed_ips(allowed_ips)
            .with_endpoint(peer_wg_endpoint)
            .with_keepalive(self.config.persistent_keepalive);
        binding.tunnel.add_peer(&peer_config).await?;

        if let PeerLocator::Acme { .. } = locator {
            if let Some(acme) = &self.acme {
                acme.register_peer_tunnel(peer_device_id, binding.listen_port).await;
            }
        }

        Ok(PeerState::new(
            peer_device_id,
            peer_pubkey,
            peer_wg_pubkey,
            peer_overlay_ip,
            binding.interface_name,
        )
        .with_endpoint(peer_wg_endpoint)
        .with_locator(locator))
    }

    async fn remove_tunnel_interface(
        &self,
        tunnel_interface: &str,
    ) -> Option<(DeviceId, std::net::Ipv6Addr)> {
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

        if matches!(peer.locator, Some(PeerLocator::Acme { .. })) {
            if let Some(acme) = &self.acme {
                acme.unregister_peer_tunnel(&peer.device_id, deterministic_tunnel_listen_port(&peer.tunnel_interface))
                    .await;
            }
        }

        self.peer_tunnels.lock().await.remove(tunnel_interface);

        let mut routing = self.routing.lock().await;
        if let Some(ref mut controller) = *routing {
            if let Err(e) = controller.flush_interface(tunnel_interface).await {
                warn!(peer_id = %peer.device_id, iface = %tunnel_interface, "Failed to flush interface from babeld: {}", e);
            }
        }

        if let Err(e) = remove_direct_peer_route(peer.overlay_ip) {
            if e.kind() != std::io::ErrorKind::Unsupported {
                warn!(
                    peer_id = %peer.device_id,
                    overlay_ip = %peer.overlay_ip,
                    "Failed to clear direct peer route: {}",
                    e
                );
            }
        }

        Some((peer.device_id, peer.overlay_ip))
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
            if let Some((removed_id, _overlay_ip)) =
                self.remove_tunnel_interface(&tunnel_interface).await
            {
                self.telemetry
                    .publish_overlay(
                        "peer_disconnected",
                        serde_json::json!({
                            "peer_id": removed_id.to_string(),
                            "reason": "peer_lost",
                        }),
                    )
                    .await;
            }
        }

        if let Err(e) = self.reconcile_peer_allowed_ips().await {
            warn!(peer_id = %device_id, "Failed to reconcile peer allowed-ips after peer removal: {}", e);
        }
    }

    async fn reconcile_peer_allowed_ips(&self) -> Result<(), OverlayDaemonError> {
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
                        peer.overlay_ip,
                    )
                })
                .collect::<Vec<_>>();
            (peer_count, snapshot)
        };

        info!(peer_count, "Reconciling peer allowed-ips");

        let desired_overlay_prefix_iface = self.select_overlay_prefix_interface().await;
        self.sync_overlay_prefix_route(desired_overlay_prefix_iface)
            .await;
        self.sync_direct_peer_routes(&peers);

        let tunnels = self.peer_tunnels.lock().await.clone();
        for (device_id, tunnel_interface, wg_pubkey, endpoint, _overlay_ip) in peers {
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
        let tunnel_interface = self.select_overlay_prefix_interface().await;

        self.sync_overlay_prefix_route(tunnel_interface).await;
    }

    async fn select_overlay_prefix_interface(&self) -> Option<String> {
        let peer_snapshot = {
            let peers = self.peers.read().await;
            peers
                .values()
                .map(|state| {
                    (
                        state.device_id,
                        state.tunnel_interface.clone(),
                        state.wg_pubkey,
                    )
                })
                .collect::<Vec<_>>()
        };

        if peer_snapshot.is_empty() {
            return None;
        }

        let unique_devices = peer_snapshot
            .iter()
            .map(|(device_id, _, _)| *device_id)
            .collect::<HashSet<_>>();
        if unique_devices.len() != 1 {
            return None;
        }

        if peer_snapshot.len() == 1 {
            return Some(peer_snapshot[0].1.clone());
        }

        let tunnels = self.peer_tunnels.lock().await.clone();
        let mut observations = Vec::new();
        for (_, tunnel_interface, wg_pubkey) in &peer_snapshot {
            if let Some(tunnel) = tunnels.get(tunnel_interface).cloned() {
                if let Ok(stats) = tunnel.peer_stats(wg_pubkey).await {
                    observations.push((tunnel_interface.clone(), stats.rx_bytes));
                }
            }
        }

        let mut fallback = peer_snapshot
            .iter()
            .map(|(_, tunnel_interface, _)| tunnel_interface.clone())
            .collect::<Vec<_>>();
        fallback.sort();

        if observations.is_empty() {
            return fallback.into_iter().next();
        }

        let observed_ifaces = observations
            .iter()
            .map(|(tunnel_interface, _)| tunnel_interface.clone())
            .collect::<HashSet<_>>();

        let mut rx_cache = self.overlay_route_rx_bytes.lock().await;
        rx_cache.retain(|iface, _| observed_ifaces.contains(iface));

        let mut best: Option<(u8, u64, String)> = None;
        for (tunnel_interface, rx_bytes) in observations {
            let previous = rx_cache
                .insert(tunnel_interface.clone(), rx_bytes)
                .unwrap_or(rx_bytes);
            let delta = rx_bytes.saturating_sub(previous);
            let class = if delta > 0 {
                2
            } else if rx_bytes > 0 {
                1
            } else {
                0
            };
            let score = if class == 2 { delta } else { rx_bytes };

            let candidate = (class, score, tunnel_interface);
            if best
                .as_ref()
                .map(|current| candidate > *current)
                .unwrap_or(true)
            {
                best = Some(candidate);
            }
        }

        best.map(|(_, _, tunnel_interface)| tunnel_interface)
            .or_else(|| fallback.into_iter().next())
    }

    fn sync_direct_peer_routes(
        &self,
        peers: &[(
            DeviceId,
            String,
            [u8; 32],
            Option<SocketAddr>,
            std::net::Ipv6Addr,
        )],
    ) {
        let mut per_device: HashMap<DeviceId, Vec<(String, std::net::Ipv6Addr)>> = HashMap::new();
        for (device_id, tunnel_interface, _, _, overlay_ip) in peers {
            per_device
                .entry(*device_id)
                .or_default()
                .push((tunnel_interface.clone(), *overlay_ip));
        }

        for (device_id, entries) in per_device {
            if entries.len() == 1 {
                let (tunnel_interface, overlay_ip) = &entries[0];
                if let Err(e) = ensure_direct_peer_route(tunnel_interface, *overlay_ip) {
                    if e.kind() != std::io::ErrorKind::Unsupported {
                        warn!(
                            peer_id = %device_id,
                            interface = %tunnel_interface,
                            overlay_ip = %overlay_ip,
                            "Failed to ensure direct peer route: {}",
                            e
                        );
                    }
                }
            } else {
                let overlay_ip = entries[0].1;
                if let Err(e) = remove_direct_peer_route(overlay_ip) {
                    if e.kind() != std::io::ErrorKind::Unsupported {
                        warn!(
                            peer_id = %device_id,
                            overlay_ip = %overlay_ip,
                            tunnels = entries.len(),
                            "Failed to clear direct route for multi-underlay peer: {}",
                            e
                        );
                    }
                }
            }
        }
    }

    async fn sync_overlay_prefix_route(&self, tunnel_interface: Option<String>) {
        if let Some(tunnel_interface) = tunnel_interface {
            if let Err(e) = ensure_overlay_prefix_route(&tunnel_interface, &self.network) {
                if e.kind() != std::io::ErrorKind::Unsupported {
                    warn!(
                        interface = %tunnel_interface,
                        "failed to ensure overlay prefix route: {}",
                        e
                    );
                }
            } else {
                debug!(
                    interface = %tunnel_interface,
                    prefix = %format!("{}/{}", self.network.prefix, self.network.prefix_len),
                    "ensured overlay prefix route"
                );
            }
            return;
        }

        if let Err(e) = remove_overlay_prefix_route(&self.network) {
            if e.kind() != std::io::ErrorKind::Unsupported {
                warn!(
                    prefix = %format!("{}/{}", self.network.prefix, self.network.prefix_len),
                    "failed to clear overlay prefix route: {}",
                    e
                );
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
                state.device_id == peer.device_id && state.locator.as_ref() == Some(&peer.locator)
            });
            if already_connected {
                continue;
            }

            if let Err(e) = self.handle_discovered_peer(peer.clone()).await {
                debug!(peer_id = %peer.device_id, "retrying discovered peer failed: {}", e);
            }
        }
    }

    async fn publish_babel_snapshot(&self) {
        let dump = {
            let mut routing = self.routing.lock().await;
            let Some(controller) = routing.as_mut() else {
                return;
            };

            match controller.dump().await {
                Ok(dump) => dump,
                Err(err) => {
                    debug!("failed to dump babel state for telemetry: {}", err);
                    return;
                }
            }
        };

        let routes = dump
            .routes
            .iter()
            .map(|route| {
                serde_json::json!({
                    "id": route.id.clone(),
                    "prefix": route.prefix.to_string(),
                    "installed": route.installed,
                    "metric": route.metric,
                    "via": route.via.to_string(),
                    "interface": route.interface.clone(),
                })
            })
            .collect::<Vec<_>>();
        self.telemetry
            .publish_babel_routes(serde_json::json!({ "routes": routes }))
            .await;

        let neighbours = dump
            .neighbours
            .iter()
            .map(|neighbour| {
                serde_json::json!({
                    "id": neighbour.id.clone(),
                    "address": neighbour.address.to_string(),
                    "interface": neighbour.interface.clone(),
                    "rxcost": neighbour.rxcost,
                    "txcost": neighbour.txcost,
                    "reach": neighbour.reach,
                })
            })
            .collect::<Vec<_>>();
        self.telemetry
            .publish_babel_neighbours(serde_json::json!({ "neighbours": neighbours }))
            .await;
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
                        state.last_rx_bytes,
                        state.last_tx_bytes,
                    )
                })
                .collect::<Vec<_>>()
        };

        let tunnels = self.peer_tunnels.lock().await.clone();
        let mut to_remove = HashSet::new();
        let mut stats_updates = Vec::new();

        for (device_id, wg_pubkey, tunnel_interface, last_seen, last_rx_bytes, _last_tx_bytes) in
            peer_snapshot
        {
            match tunnels.get(&tunnel_interface).cloned() {
                Some(tunnel) => match tunnel.peer_stats(&wg_pubkey).await {
                    Ok(stats) => {
                        let rx_changed = stats.rx_bytes != last_rx_bytes;
                        let handshake_recent = stats
                            .last_handshake
                            .and_then(|last_handshake| last_handshake.elapsed().ok())
                            .map(|elapsed| elapsed <= timeout)
                            .unwrap_or(false);

                        let has_activity = rx_changed || handshake_recent;

                        stats_updates.push((
                            tunnel_interface.clone(),
                            stats.rx_bytes,
                            stats.tx_bytes,
                            has_activity,
                        ));

                        if !has_activity && last_seen.elapsed() > timeout {
                            to_remove.insert((device_id, tunnel_interface.clone()));
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

        if !stats_updates.is_empty() {
            let mut peers = self.peers.write().await;
            for (tunnel_interface, rx_bytes, tx_bytes, has_activity) in stats_updates {
                if let Some(peer) = peers.get_mut(&tunnel_interface) {
                    peer.last_rx_bytes = rx_bytes;
                    peer.last_tx_bytes = tx_bytes;
                    if has_activity {
                        peer.update_last_seen();
                    }
                }
            }
        }

        let mut removed_any = false;
        for (device_id, tunnel_interface) in to_remove {
            warn!(peer_id = %device_id, iface = %tunnel_interface, "Removing dead peer tunnel");
            let removed = self.remove_tunnel_interface(&tunnel_interface).await;
            if removed.is_some() {
                self.telemetry
                    .publish_overlay(
                        "peer_disconnected",
                        serde_json::json!({
                            "peer_id": device_id.to_string(),
                            "reason": "dead_peer_timeout",
                        }),
                    )
                    .await;
            }
            removed_any |= removed.is_some();
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
        info!("Shutting down avena-overlay...");

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
            if matches!(peer.locator, Some(PeerLocator::Acme { .. })) {
                if let Some(acme) = &self.acme {
                    acme.unregister_peer_tunnel(&peer.device_id, deterministic_tunnel_listen_port(&peer.tunnel_interface))
                        .await;
                }
            }
        }

        if let Some(acme) = &self.acme {
            acme.shutdown().await;
        }

        // Stop discovery last (best-effort). This reduces noisy shutdown logs
        // from the underlying mdns daemon when the process exits.
        self.discovery.shutdown();
    }
}

fn validate_interface_name(name: &str) -> Result<(), OverlayDaemonError> {
    if name.is_empty() {
        return Err(OverlayDaemonError::Config("interface name cannot be empty".into()));
    }
    if name.len() > 15 {
        return Err(OverlayDaemonError::Config(
            "interface name too long (max 15 chars)".into(),
        ));
    }
    if name.starts_with('-') {
        return Err(OverlayDaemonError::Config(
            "interface name cannot start with '-'".into(),
        ));
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return Err(OverlayDaemonError::Config(
            "interface name contains invalid characters".into(),
        ));
    }
    Ok(())
}

fn load_or_generate_keypair(config: &OverlayConfig) -> Result<DeviceKeypair, OverlayDaemonError> {
    if let Some(ref path) = config.keypair_path {
        if path.exists() {
            let bytes = std::fs::read(path)?;
            if bytes.len() != 32 {
                return Err(OverlayDaemonError::Config("invalid keypair file size".into()));
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
fn ensure_overlay_prefix_route(
    interface_name: &str,
    network: &NetworkConfig,
) -> Result<(), std::io::Error> {
    use avena_overlay::wg::linux::netlink;

    netlink::replace_ipv6_route(interface_name, network.prefix, network.prefix_len).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("replace overlay prefix route: {e}"),
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

#[cfg(target_os = "linux")]
fn remove_overlay_prefix_route(network: &NetworkConfig) -> Result<(), std::io::Error> {
    use avena_overlay::wg::linux::netlink;

    match netlink::delete_ipv6_route(network.prefix, network.prefix_len) {
        Ok(()) => Ok(()),
        Err(WgError::InterfaceNotFound(_)) => Ok(()),
        // When the route doesn't exist, Linux often returns ESRCH (errno 3).
        Err(WgError::NetlinkError(message))
            if message.contains("(errno 3)") || message.contains("os error 3") =>
        {
            Ok(())
        }
        Err(e) => Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("delete overlay prefix route: {e}"),
        )),
    }
}

#[cfg(not(target_os = "linux"))]
fn remove_overlay_prefix_route(_network: &NetworkConfig) -> Result<(), std::io::Error> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "requires Linux",
    ))
}

#[cfg(target_os = "linux")]
fn ensure_direct_peer_route(
    interface_name: &str,
    peer_addr: std::net::Ipv6Addr,
) -> Result<(), std::io::Error> {
    use avena_overlay::wg::linux::netlink;

    netlink::replace_ipv6_route(interface_name, peer_addr, 128).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("replace direct peer route: {e}"),
        )
    })
}

#[cfg(not(target_os = "linux"))]
fn ensure_direct_peer_route(
    _interface_name: &str,
    _peer_addr: std::net::Ipv6Addr,
) -> Result<(), std::io::Error> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "requires Linux",
    ))
}

#[cfg(target_os = "linux")]
fn remove_direct_peer_route(peer_addr: std::net::Ipv6Addr) -> Result<(), std::io::Error> {
    use avena_overlay::wg::linux::netlink;

    match netlink::delete_ipv6_route(peer_addr, 128) {
        Ok(()) => Ok(()),
        Err(WgError::InterfaceNotFound(_)) => Ok(()),
        Err(WgError::NetlinkError(message))
            if message.contains("(errno 3)") || message.contains("os error 3") =>
        {
            Ok(())
        }
        Err(e) => Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("delete direct peer route: {e}"),
        )),
    }
}

#[cfg(not(target_os = "linux"))]
fn remove_direct_peer_route(_peer_addr: std::net::Ipv6Addr) -> Result<(), std::io::Error> {
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
enum OverlayDaemonError {
    Config(String),
    CertConfig(avena_overlay::ConfigError),
    Tunnel(avena_overlay::TunnelError),
    Discovery(avena_overlay::DiscoveryError),
    Acme(String),
    Routing(RoutingError),
    Io(std::io::Error),
    Handshake(String),
    Json(serde_json::Error),
    Timeout,
}

impl std::fmt::Display for OverlayDaemonError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OverlayDaemonError::Config(e) => write!(f, "config error: {}", e),
            OverlayDaemonError::CertConfig(e) => write!(f, "certificate config error: {}", e),
            OverlayDaemonError::Tunnel(e) => write!(f, "tunnel error: {}", e),
            OverlayDaemonError::Discovery(e) => write!(f, "discovery error: {}", e),
            OverlayDaemonError::Acme(e) => write!(f, "acme error: {}", e),
            OverlayDaemonError::Routing(e) => write!(f, "routing error: {}", e),
            OverlayDaemonError::Io(e) => write!(f, "io error: {}", e),
            OverlayDaemonError::Handshake(e) => write!(f, "handshake error: {}", e),
            OverlayDaemonError::Json(e) => write!(f, "json error: {}", e),
            OverlayDaemonError::Timeout => write!(f, "handshake timeout"),
        }
    }
}

impl std::error::Error for OverlayDaemonError {}

impl From<avena_overlay::TunnelError> for OverlayDaemonError {
    fn from(e: avena_overlay::TunnelError) -> Self {
        OverlayDaemonError::Tunnel(e)
    }
}

impl From<avena_overlay::DiscoveryError> for OverlayDaemonError {
    fn from(e: avena_overlay::DiscoveryError) -> Self {
        OverlayDaemonError::Discovery(e)
    }
}

impl From<RoutingError> for OverlayDaemonError {
    fn from(e: RoutingError) -> Self {
        OverlayDaemonError::Routing(e)
    }
}

impl From<std::io::Error> for OverlayDaemonError {
    fn from(e: std::io::Error) -> Self {
        OverlayDaemonError::Io(e)
    }
}

impl From<serde_json::Error> for OverlayDaemonError {
    fn from(e: serde_json::Error) -> Self {
        OverlayDaemonError::Json(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[tokio::test]
    async fn routing_startup_is_fatal_when_babel_binary_is_missing() {
        let mut config = OverlayConfig::default();
        config.routing.babel.binary_path = PathBuf::from("/definitely/missing/babeld");

        let err = start_routing_controller(&config).await.unwrap_err();
        assert!(matches!(err, OverlayDaemonError::Routing(_)));
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

    #[test]
    fn telemetry_subject_tokens_are_sanitized() {
        let publisher = TelemetryPublisher {
            client: None,
            run_id: sanitize_subject_token("Run ID 01", DEFAULT_TELEMETRY_RUN_ID),
            node_id: sanitize_subject_token("Node.ID", DEFAULT_TELEMETRY_TOKEN),
            started_at: Instant::now(),
        };

        assert_eq!(
            publisher.overlay_subject("peer.connected!"),
            "avena.v1.run-id-01.node.node-id.overlay.peer-connected"
        );
        assert_eq!(
            publisher.babel_subject("NEIGHBORS/active"),
            "avena.v1.run-id-01.node.node-id.routing.babel.neighbors-active"
        );
    }

    #[test]
    fn telemetry_subject_tokens_use_fallback_when_empty() {
        assert_eq!(
            sanitize_subject_token("", DEFAULT_TELEMETRY_TOKEN),
            "unknown"
        );
        assert_eq!(
            sanitize_subject_token("...", DEFAULT_TELEMETRY_TOKEN),
            "unknown"
        );
    }
}

#[tokio::main]
async fn main() {
    let filter = tracing_subscriber::EnvFilter::from_default_env()
        .add_directive(tracing::Level::INFO.into())
        // Suppress noisy warnings from netlink-packet-route on newer kernels.
        .add_directive("netlink_packet_route=error".parse().unwrap());

    tracing_subscriber::fmt().with_env_filter(filter).init();

    let mut args = std::env::args_os();
    let program = args
        .next()
        .and_then(|arg| arg.into_string().ok())
        .unwrap_or_else(|| "avena-overlay".to_string());
    let default_config_path = PathBuf::from("/etc/avena/avena-overlay.toml");
    let config_path = args
        .next()
        .map(PathBuf::from)
        .unwrap_or_else(|| default_config_path.clone());

    if args.next().is_some() {
        error!("Too many arguments. Usage: {} <config-path>", program);
        std::process::exit(2);
    }

    if !config_path.exists() {
        if config_path == default_config_path {
            error!(
                "Configuration file not found at default path {}. Usage: {} <config-path>",
                config_path.display(),
                program
            );
        } else {
            error!("Configuration file not found: {}", config_path.display());
        }
        std::process::exit(1);
    }

    let config = match OverlayConfig::load_from_file(&config_path) {
        Ok(c) => {
            info!(path = %config_path.display(), "Loaded configuration");
            c
        }
        Err(e) => {
            error!("Failed to load config {}: {}", config_path.display(), e);
            std::process::exit(1);
        }
    };

    match OverlayDaemon::new(config).await {
        Ok(mut daemon) => {
            if let Err(e) = daemon.run().await {
                error!("avena-overlay error: {}", e);
                std::process::exit(1);
            }
        }
        Err(e) => {
            error!("Failed to initialize avena-overlay: {}", e);
            std::process::exit(1);
        }
    }
}
