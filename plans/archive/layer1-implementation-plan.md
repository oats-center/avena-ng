# Avena Overlay Network (Layer 1) Implementation Plan

## Overview

This document specifies the implementation plan for `avena-overlay`, the foundational networking layer providing encrypted, authenticated IP connectivity over heterogeneous physical links.

## Crate Structure

```
avena-overlay/
├── Cargo.toml
├── src/
│   ├── lib.rs
│   ├── identity/
│   │   ├── mod.rs
│   │   ├── device_id.rs
│   │   ├── keypair.rs
│   │   └── derived.rs
│   ├── crypto/
│   │   ├── mod.rs
│   │   ├── handshake.rs
│   │   ├── signatures.rs
│   │   └── certs.rs
│   ├── discovery/
│   │   ├── mod.rs
│   │   ├── mdns.rs
│   │   └── static_peers.rs
│   ├── tunnel/
│   │   ├── mod.rs
│   │   ├── backend.rs
│   │   ├── kernel.rs
│   │   └── userspace.rs
│   ├── routing/
│   │   ├── mod.rs
│   │   └── babel.rs
│   ├── container/
│   │   ├── mod.rs
│   │   ├── veth.rs
│   │   ├── routing.rs
│   │   ├── quadlet.rs
│   │   └── bridge.rs
│   └── address.rs
└── bin/
    ├── avenad.rs
    └── avena-sidecar.rs
```

---

## Phase 1: Core Types and Identity

### 1.1 `identity/device_id.rs`

```rust
/// 128-bit device identifier derived from public key
/// DeviceId = SHA256(pk)[0..16], encoded as base32
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct DeviceId([u8; 16]);

impl DeviceId {
    pub fn from_public_key(pk: &Ed25519PublicKey) -> Self;
    pub fn to_base32(&self) -> String;
    pub fn from_base32(s: &str) -> Result<Self, DecodeError>;
    pub fn to_ipv6_suffix(&self) -> [u8; 8]; // For overlay address derivation
}

impl fmt::Display for DeviceId { /* base32 */ }
impl fmt::Debug for DeviceId { /* truncated for readability */ }
```

### 1.2 `identity/keypair.rs`

```rust
pub struct DeviceKeypair {
    ed25519: Ed25519Keypair,  // Signing key
    device_id: DeviceId,
}

impl DeviceKeypair {
    pub fn generate() -> Self;
    pub fn from_seed(seed: &[u8; 32]) -> Self;
    pub fn device_id(&self) -> DeviceId;
    pub fn public_key(&self) -> &Ed25519PublicKey;
    pub fn sign(&self, message: &[u8]) -> Ed25519Signature;

    // Persistence
    pub fn to_bytes(&self) -> Zeroizing<[u8; 32]>;
    pub fn from_bytes(bytes: &[u8; 32]) -> Self;
}
```

### 1.3 `identity/derived.rs`

Key derivation for nested workloads (capability attenuation).

```rust
/// Derive a child keypair for a workload
pub fn derive_workload_keypair(
    parent: &DeviceKeypair,
    workload_id: &str,
) -> DeviceKeypair;

// Uses HKDF with parent seed + workload_id as info
// Child DeviceId is independent (derived from child pk)
```

### 1.4 `address.rs`

```rust
/// Overlay network configuration
pub struct NetworkConfig {
    pub prefix: Ipv6Addr,  // e.g., fd00:avena::
    pub prefix_len: u8,    // typically /48
}

impl NetworkConfig {
    /// Derive overlay IPv6 from DeviceId
    pub fn device_address(&self, id: &DeviceId) -> Ipv6Addr;

    /// Derive workload address (different subnet)
    pub fn workload_address(&self, host_id: &DeviceId, workload_idx: u16) -> Ipv6Addr;
}
```

---

## Phase 2: Cryptographic Handshake

### 2.1 `crypto/handshake.rs`

Per-session key derivation tying Wireguard to Avena identity.

```rust
/// Ephemeral X25519 keypair for session establishment
pub struct EphemeralKeypair {
    x25519: X25519StaticSecret,
    public: X25519PublicKey,
}

/// Message sent during tunnel handshake
#[derive(Serialize, Deserialize)]
pub struct HandshakeMessage {
    pub ephemeral_pubkey: [u8; 32],
    pub nonce: [u8; 32],
    pub signature: Ed25519Signature,  // Signs (ephemeral_pubkey || nonce || peer_id)
}

impl HandshakeMessage {
    pub fn create(
        device: &DeviceKeypair,
        ephemeral: &EphemeralKeypair,
        peer_id: &DeviceId,
    ) -> Self;

    pub fn verify(
        &self,
        peer_pubkey: &Ed25519PublicKey,
        local_id: &DeviceId,
    ) -> Result<(), HandshakeError>;
}

/// Derive Wireguard keys from completed handshake
pub struct SessionKeys {
    pub wireguard_private: [u8; 32],
    pub wireguard_psk: [u8; 32],
}

pub fn derive_session_keys(
    local_ephemeral: &EphemeralKeypair,
    peer_ephemeral: &X25519PublicKey,
    initiator: bool,
) -> SessionKeys;
```

### 2.2 `crypto/signatures.rs`

Thin wrappers ensuring consistent usage.

```rust
pub use ed25519_dalek::{Signature as Ed25519Signature, VerifyingKey as Ed25519PublicKey};

pub fn verify_signature(
    pubkey: &Ed25519PublicKey,
    message: &[u8],
    signature: &Ed25519Signature,
) -> Result<(), SignatureError>;
```

### 2.3 `crypto/certs.rs`

Certificate chain validation. avenad configured with trusted root CA at startup. Revocation deferred.

```rust
pub struct CertificateChain {
    pub leaf: Certificate,
    pub intermediates: Vec<Certificate>,
}

pub struct CertValidator {
    trusted_root: Certificate,
}

impl CertValidator {
    pub fn new(trusted_root: Certificate) -> Self;

    /// Verify chain from leaf to trusted root
    pub fn validate_chain(&self, chain: &CertificateChain) -> Result<(), CertError>;

    /// Verify certificate is not expired
    pub fn check_expiry(&self, cert: &Certificate) -> Result<(), CertError>;
}
```

---

## Phase 3: Tunnel Backend Abstraction

### 3.1 `tunnel/backend.rs`

```rust
#[async_trait]
pub trait TunnelBackend: Send + Sync {
    /// Create or get the Wireguard interface
    async fn ensure_interface(&self, name: &str) -> Result<(), TunnelError>;

    /// Add a peer with derived session keys
    async fn add_peer(&self, peer: &PeerConfig) -> Result<(), TunnelError>;

    /// Remove a peer
    async fn remove_peer(&self, pubkey: &[u8; 32]) -> Result<(), TunnelError>;

    /// Update peer endpoint (mobility)
    async fn update_endpoint(
        &self,
        pubkey: &[u8; 32],
        endpoint: SocketAddr,
    ) -> Result<(), TunnelError>;

    /// Get peer statistics (for dead peer detection)
    async fn peer_stats(&self, pubkey: &[u8; 32]) -> Result<PeerStats, TunnelError>;

    /// Get interface listen port
    async fn listen_port(&self) -> Result<u16, TunnelError>;
}

#[derive(Clone)]
pub struct PeerConfig {
    pub wireguard_pubkey: [u8; 32],
    pub psk: Option<[u8; 32]>,
    pub allowed_ips: Vec<IpNet>,
    pub endpoint: Option<SocketAddr>,
    pub persistent_keepalive: Option<u16>,
}

pub struct PeerStats {
    pub last_handshake: Option<SystemTime>,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}
```

### 3.2 `tunnel/kernel.rs`

Linux kernel Wireguard via `defguard_wireguard_rs`.

```rust
use defguard_wireguard_rs::{WGApi, Kernel};

pub struct KernelBackend {
    api: WGApi<Kernel>,
    interface_name: String,
}

impl KernelBackend {
    pub fn new(interface_name: &str) -> Result<Self, TunnelError> {
        let api = WGApi::<Kernel>::new(interface_name.to_string())?;
        api.create_interface()?;
        Ok(Self { api, interface_name: interface_name.to_string() })
    }
}

#[async_trait]
impl TunnelBackend for KernelBackend {
    // Wraps WGApi<Kernel> methods
    // Requires CAP_NET_ADMIN
}
```

### 3.3 `tunnel/userspace.rs`

Userspace Wireguard for unprivileged contexts (sidecar) via `defguard_wireguard_rs`.

```rust
use defguard_wireguard_rs::{WGApi, Userspace};

pub struct UserspaceBackend {
    api: WGApi<Userspace>,
    interface_name: String,
}

impl UserspaceBackend {
    pub fn new(interface_name: &str) -> Result<Self, TunnelError> {
        let api = WGApi::<Userspace>::new(interface_name.to_string())?;
        api.create_interface()?;
        Ok(Self { api, interface_name: interface_name.to_string() })
    }
}

#[async_trait]
impl TunnelBackend for UserspaceBackend {
    // Wraps WGApi<Userspace> methods
    // Uses embedded boringtun, no CAP_NET_ADMIN needed
}
```

---

## Phase 4: Peer Discovery

### 4.1 `discovery/mod.rs`

```rust
/// Discovered peer information
#[derive(Clone, Debug)]
pub struct DiscoveredPeer {
    pub device_id: DeviceId,
    pub endpoint: SocketAddr,
    pub capabilities: HashSet<Capability>,
    pub source: DiscoverySource,
    pub discovered_at: Instant,
}

#[derive(Clone, Debug)]
pub enum DiscoverySource {
    Mdns,
    Static,
    Gossip,  // Future: learned via gossip
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Capability {
    Relay,          // Will forward messages
    WorkloadSpawn,  // Can run containers
    DeviceIssue,    // Can sign device certs
    Gateway,        // Has backhaul connectivity
}

/// Unified discovery service
pub struct DiscoveryService {
    mdns: Option<MdnsDiscovery>,
    static_peers: StaticPeers,
    tx: broadcast::Sender<DiscoveryEvent>,
}

pub enum DiscoveryEvent {
    PeerDiscovered(DiscoveredPeer),
    PeerLost(DeviceId),
}

impl DiscoveryService {
    pub fn new(config: DiscoveryConfig) -> Self;
    pub fn subscribe(&self) -> broadcast::Receiver<DiscoveryEvent>;
    pub async fn run(&self) -> Result<(), DiscoveryError>;

    /// Register this device for discovery by others
    pub async fn announce(&self, local: &LocalAnnouncement) -> Result<(), DiscoveryError>;
}
```

### 4.2 `discovery/mdns.rs`

```rust
pub struct MdnsDiscovery {
    // Uses mdns-sd or similar
}

impl MdnsDiscovery {
    pub fn new(interface: Option<&str>) -> Result<Self, MdnsError>;

    /// Advertise: _avena._udp.local
    /// TXT records: avena-id=<base32>, wg-endpoint=<ip:port>, cap=relay,gateway
    pub async fn advertise(&self, announcement: &LocalAnnouncement) -> Result<(), MdnsError>;

    /// Browse for peers
    pub async fn browse(&self) -> impl Stream<Item = DiscoveredPeer>;
}

pub struct LocalAnnouncement {
    pub device_id: DeviceId,
    pub wg_endpoint: SocketAddr,
    pub capabilities: HashSet<Capability>,
}
```

### 4.3 `discovery/static_peers.rs`

```rust
pub struct StaticPeers {
    peers: Vec<StaticPeerConfig>,
}

#[derive(Clone, Deserialize)]
pub struct StaticPeerConfig {
    pub device_id: Option<DeviceId>,  // Optional if DNS resolves to single peer
    pub endpoint: String,              // IP:port or hostname:port
    pub capabilities: HashSet<Capability>,
}

impl StaticPeers {
    pub fn from_config(peers: Vec<StaticPeerConfig>) -> Self;
    pub async fn resolve(&self) -> Vec<DiscoveredPeer>;
}
```

---

## Phase 5: Routing Integration

### 5.1 `routing/mod.rs`

```rust
pub struct Route {
    pub prefix: IpNet,
    pub next_hop: Option<Ipv6Addr>,
    pub interface: String,
    pub metric: u32,
}
```

### 5.2 `routing/babel.rs`

Babel/FRR integration via vtysh. Babel has no YANG model, so gRPC/mgmtd is not an option.

```rust
pub struct BabelRouting {
    vtysh_path: PathBuf,
    config_path: PathBuf,  // /etc/frr/frr.conf
}

impl BabelRouting {
    pub fn new(config: BabelConfig) -> Result<Self, RoutingError>;

    /// Write babel config to frr.conf and reload
    pub async fn apply_config(&self) -> Result<(), RoutingError>;

    /// Add an interface to babel
    pub async fn add_interface(&self, name: &str) -> Result<(), RoutingError>;

    /// Remove an interface from babel
    pub async fn remove_interface(&self, name: &str) -> Result<(), RoutingError>;

    /// Announce a route via redistribute
    pub async fn announce_route(&self, prefix: IpNet) -> Result<(), RoutingError>;

    /// Get current routing table (vtysh -c "show ipv6 route json")
    pub async fn routes(&self) -> Result<Vec<Route>, RoutingError>;

    /// Get babel-specific state (vtysh -c "show babel route" - text parsing)
    pub async fn babel_routes(&self) -> Result<Vec<BabelRoute>, RoutingError>;
}

#[derive(Deserialize)]
pub struct BabelConfig {
    pub vtysh_path: PathBuf,
    pub config_path: PathBuf,
    pub hello_interval: Duration,
    pub update_interval: Duration,
}
```

---

## Phase 6: Container Networking

For Addressable workloads requiring overlay IPs. Uses Quadlet (systemd integration) for container lifecycle management.

### 6.1 `container/mod.rs`

```rust
/// Network namespace setup for workloads
pub struct WorkloadNetwork {
    pub host_veth: String,      // e.g., veth-<workload>
    pub container_veth: String, // e.g., eth0 inside container
    pub overlay_ip: Ipv6Addr,
    pub gateway: Ipv6Addr,      // Host's veth link-local
    pub netns: String,
}

pub struct ContainerNetworking {
    overlay_prefix: IpNet,
    internet_iface: String,     // Host's internet-facing interface
}

impl ContainerNetworking {
    pub fn new(config: ContainerNetConfig) -> Result<Self, NetError>;

    /// One-time setup: enable forwarding, NAT rule
    pub async fn init_host_networking(&self) -> Result<(), NetError>;

    /// Setup network for an Addressable workload
    pub async fn setup_workload(
        &self,
        workload_id: &str,
        overlay_ip: Ipv6Addr,
        netns: &str,
    ) -> Result<WorkloadNetwork, NetError>;

    /// Teardown workload network
    pub async fn teardown_workload(&self, workload_id: &str) -> Result<(), NetError>;
}
```

### 6.2 `container/veth.rs`

```rust
pub async fn create_veth_pair(
    host_name: &str,
    container_name: &str,
    container_netns: &str,
) -> Result<(), VethError>;

pub async fn assign_address(
    interface: &str,
    addr: Ipv6Addr,
    prefix_len: u8,
    netns: Option<&str>,
) -> Result<(), VethError>;

pub async fn delete_veth(name: &str) -> Result<(), VethError>;
```

### 6.3 `container/routing.rs`

Host networking setup for workload internet access.

```rust
/// One-time host setup (called on avenad startup)
pub async fn init_host_routing(
    overlay_prefix: &IpNet,
    internet_iface: &str,
) -> Result<(), RoutingError> {
    // Enable IPv6 forwarding
    // sysctl net.ipv6.conf.all.forwarding=1

    // NAT workload traffic to internet
    // ip6tables -t nat -A POSTROUTING -s <overlay_prefix> -o <internet_iface> -j MASQUERADE
}

/// Per-workload route setup (inside workload netns)
pub async fn setup_workload_routes(
    netns: &str,
    gateway: &Ipv6Addr,
) -> Result<(), RoutingError> {
    // Default route via host's veth end
    // ip -n <netns> -6 route add default via <gateway> dev eth0
}
```

**Traffic flow:**
- Overlay destinations → host forwards to WG tunnels (Babel routes)
- Non-overlay destinations → host forwards to internet interface (NAT'd)

### 6.4 `container/quadlet.rs`

Quadlet integration for workload lifecycle.

```rust
pub struct QuadletManager {
    unit_dir: PathBuf,  // /etc/containers/systemd/
}

impl QuadletManager {
    pub fn new(unit_dir: PathBuf) -> Self;

    /// Write .container file and reload systemd
    pub async fn create_workload(&self, workload: &WorkloadSpec) -> Result<(), QuadletError>;

    /// Remove .container file and stop unit
    pub async fn remove_workload(&self, workload_id: &str) -> Result<(), QuadletError>;

    /// Start workload via systemctl
    pub async fn start(&self, workload_id: &str) -> Result<(), QuadletError>;

    /// Stop workload via systemctl
    pub async fn stop(&self, workload_id: &str) -> Result<(), QuadletError>;
}
```

### 6.5 `container/bridge.rs`

Optional bridge for multiple workloads on same host.

```rust
pub struct BridgeManager {
    bridge_name: String,
}

impl BridgeManager {
    pub fn new(name: &str) -> Result<Self, BridgeError>;
    pub async fn add_interface(&self, iface: &str) -> Result<(), BridgeError>;
    pub async fn remove_interface(&self, iface: &str) -> Result<(), BridgeError>;
}
```

---

## Phase 7: Daemon Structure

### 7.1 `bin/avenad.rs`

```rust
struct Avenad {
    config: AvenadConfig,
    keypair: DeviceKeypair,
    network: NetworkConfig,

    // Subsystems
    tunnel: Arc<dyn TunnelBackend>,
    routing: BabelRouting,
    discovery: DiscoveryService,
    container_net: ContainerNetworking,

    // State
    peers: RwLock<HashMap<DeviceId, PeerState>>,
    workloads: RwLock<HashMap<String, WorkloadState>>,
}

struct PeerState {
    device_id: DeviceId,
    wg_pubkey: [u8; 32],
    endpoint: Option<SocketAddr>,
    overlay_ip: Ipv6Addr,
    connected_at: Instant,
    last_seen: Instant,
}

enum WorkloadState {
    Messaging,  // No network setup needed
    Addressable {
        overlay_ip: Ipv6Addr,
        sidecar_pid: u32,
        network: WorkloadNetwork,
    },
}

impl Avenad {
    async fn run(&self) -> Result<(), AvenadError> {
        tokio::select! {
            _ = self.discovery_loop() => {},
            _ = self.peer_management_loop() => {},
            _ = self.dead_peer_detection_loop() => {},
            _ = self.workload_management_loop() => {},
            _ = signal::ctrl_c() => {},
        }
        Ok(())
    }

    async fn handle_discovered_peer(&self, peer: DiscoveredPeer) -> Result<(), AvenadError>;
    async fn establish_tunnel(&self, peer: &DiscoveredPeer) -> Result<PeerState, AvenadError>;
    async fn teardown_tunnel(&self, device_id: &DeviceId) -> Result<(), AvenadError>;

    // Workload management
    async fn spawn_sidecar(&self, workload: &WorkloadSpec) -> Result<(), AvenadError>;
    async fn push_peer_to_sidecar(&self, workload_id: &str, peer: &PeerConfig) -> Result<(), AvenadError>;
}
```

### 7.2 `bin/avena-sidecar.rs`

Minimal binary for Addressable workloads.

```rust
struct AvenaSidecar {
    keypair: DeviceKeypair,  // Derived from host
    overlay_ip: Ipv6Addr,
    tunnel: Arc<dyn TunnelBackend>,  // Userspace only
    nats: async_nats::Client,
}

impl AvenaSidecar {
    async fn run(&self) -> Result<(), SidecarError> {
        // Subscribe to control subject with JWT from host
        // avena.sidecar.<workload_id>.control
        let mut control = self.nats.subscribe("avena.sidecar.*.control").await?;

        tokio::select! {
            Some(msg) = control.next() => self.handle_control(msg).await?,
            _ = signal::ctrl_c() => {},
        }
        Ok(())
    }
}

// Control messages via NATS (JSON)
// - AddPeer { pubkey, endpoint, allowed_ips }
// - RemovePeer { pubkey }
// - UpdateEndpoint { pubkey, endpoint }
// - Shutdown
```

---

## Implementation Order

### Milestone 0: Replace defguard_wireguard_rs (NEXT)

Replace `defguard_wireguard_rs` with a custom `wg` module to:
- Reduce dependency footprint (drop unused BSD/macOS/Windows code)
- Prepare modular structure for future Android/macOS/Windows support

#### Module Structure

```
src/wg/
├── mod.rs              # Public API, re-exports
├── error.rs            # WgError type
├── types.rs            # Host, Peer, Key, IpAddrMask, PeerStats
├── uapi.rs             # UAPI text protocol (shared by all userspace)
│
├── userspace/
│   ├── mod.rs          # UserspaceBackend - spawn wireguard-go, WgBackend impl
│   └── socket.rs       # Unix socket to /var/run/wireguard/
│
└── linux/
    ├── mod.rs          # KernelBackend impl
    └── netlink.rs      # Netlink implementation for kernel WireGuard
```

#### API

```rust
pub use error::WgError;
pub use types::{Host, Peer, Key, IpAddrMask, PeerStats};

pub trait WgBackend: Send + Sync {
    fn create_interface(&self) -> Result<(), WgError>;
    fn remove_interface(&self) -> Result<(), WgError>;
    fn read_host(&self) -> Result<Host, WgError>;
    fn configure_peer(&self, peer: &Peer) -> Result<(), WgError>;
    fn remove_peer(&self, pubkey: &Key) -> Result<(), WgError>;
}

pub fn userspace(name: &str) -> Result<impl WgBackend, WgError>;

#[cfg(target_os = "linux")]
pub fn kernel(name: &str) -> Result<impl WgBackend, WgError>;
```

#### Dependencies

```toml
# Core (all platforms)
thiserror = "2.0"
x25519-dalek = { version = "2", features = ["getrandom", "static_secrets"] }

# Linux kernel netlink
[target.'cfg(target_os = "linux")'.dependencies]
netlink-packet-core = "0.8"
netlink-packet-generic = "0.4"
netlink-packet-route = "0.25"
netlink-packet-wireguard = "0.2"
netlink-sys = "0.8"
```

#### Tasks

1. Create `src/wg/error.rs` - WgError enum
2. Create `src/wg/types.rs` - Host, Peer, Key, IpAddrMask with UAPI serialization
3. Create `src/wg/uapi.rs` - parse_uapi(), as_uapi() protocol handling
4. Create `src/wg/userspace/socket.rs` - Unix socket to /var/run/wireguard/
5. Create `src/wg/userspace/mod.rs` - spawn wireguard-go, WgBackend impl
6. Create `src/wg/linux/netlink.rs` - netlink implementation (adapt from defguard)
7. Create `src/wg/linux/mod.rs` - KernelBackend impl
8. Create `src/wg/mod.rs` - public API, feature gates
9. Update `tunnel/kernel.rs` to use `wg::kernel()`
10. Update `tunnel/userspace.rs` to use `wg::userspace()`
11. Remove `defguard_wireguard_rs` from Cargo.toml
12. Verify all tests pass (see Testing Requirements below)

#### Future Platform Support

```
src/wg/
├── android/
│   └── mod.rs          # JNI bindings to wireguard-android
├── macos/
│   └── mod.rs          # Network Extension API
└── windows/
    └── mod.rs          # WinTUN/WireGuard-Windows
```

#### Testing Requirements

Prerequisites:
- `wireguard-go` installed with `CAP_NET_ADMIN`: `sudo setcap cap_net_admin+ep $(which wireguard-go)`
- Kernel WireGuard module loaded: `sudo modprobe wireguard`

```bash
# Unit tests (no privileges needed)
cargo test

# Userspace tests - use unshare for automatic cleanup
unshare -rn cargo test userspace -- --ignored

# Kernel tests - require real root (user namespaces cannot access kernel WireGuard)
sudo cargo test kernel -- --ignored
```

---

### Milestone 1: Identity & Crypto
1. `identity/device_id.rs` - DeviceId type with base32 encoding
2. `identity/keypair.rs` - DeviceKeypair with Ed25519
3. `crypto/handshake.rs` - X25519 session key derivation
4. `address.rs` - Overlay IP derivation
5. Unit tests for all

### Milestone 2: Tunnel Abstraction (Week 2)
1. `tunnel/backend.rs` - TunnelBackend trait
2. `tunnel/kernel.rs` - Kernel Wireguard via netlink
3. Integration test: create interface, add peer, verify connectivity

### Milestone 3: Discovery (Week 3)
1. `discovery/static_peers.rs` - Static peer resolution
2. `discovery/mdns.rs` - mDNS discovery
3. `discovery/mod.rs` - Unified discovery service
4. Integration test: two processes discover each other

### Milestone 4: Minimal avenad (Week 4)
1. `bin/avenad.rs` - Basic daemon structure
2. Discovery → handshake → tunnel flow
3. Manual testing: two avenad instances connect

### Milestone 5: Routing Integration (Week 5)
1. `routing/babel.rs` - Babel via vtysh
2. Route announcements for overlay IPs
3. Multi-hop routing test

### Milestone 6: Container Networking (Week 6)
1. `container/veth.rs` - veth pair creation
2. `container/mod.rs` - WorkloadNetwork setup
3. `tunnel/userspace.rs` - Userspace Wireguard backend

### Milestone 7: Sidecar (Week 7)
1. `bin/avena-sidecar.rs` - Sidecar binary
2. Control channel protocol (Unix socket)
3. Host → sidecar peer push flow
4. End-to-end test: host + Addressable workload

---

## Dependencies

```toml
[dependencies]
# Crypto
ed25519-dalek = "2"
x25519-dalek = "2"
sha2 = "0.10"
hkdf = "0.12"
zeroize = { version = "1", features = ["derive"] }
rand = "0.8"

# Encoding
base32 = "0.5"
serde = { version = "1", features = ["derive"] }
serde_json = "1"

# Networking
tokio = { version = "1", features = ["full"] }
socket2 = "0.5"
ipnet = "2"

# Wireguard (custom wg module - see Milestone 0)
# No external WireGuard crate - using custom implementation
# Linux netlink deps are platform-specific (see Milestone 0)

# Discovery
mdns-sd = "0.11"  # or async-mdns

# Linux networking
rtnetlink = "0.14"  # netlink for routes/interfaces
netlink-packet-route = "0.19"

# Async
async-trait = "0.1"
futures = "0.3"
tokio-stream = "0.1"

# Logging
tracing = "0.1"
tracing-subscriber = "0.3"

# Config
toml = "0.8"
```

---

## Testing Strategy

- **Unit tests**: All crypto, encoding, address derivation
- **Integration tests**:
  - Two avenad instances on same machine (different network namespaces)
  - Discovery → tunnel → ping flow
- **Multi-node tests**:
  - Docker Compose with 3+ nodes
  - Verify Babel route convergence
  - Verify multi-hop connectivity
