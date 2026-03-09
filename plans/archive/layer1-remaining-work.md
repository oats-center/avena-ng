# Avena Overlay Network - Remaining Implementation Plan

## Current State Summary

### Complete (Milestones 0-4 + Basic Daemon)

| Component | Status | Notes |
|-----------|--------|-------|
| **wg module** | ✅ Complete | Custom WireGuard abstraction (replaced defguard_wireguard_rs) |
| **identity** | ✅ Complete | DeviceId, DeviceKeypair, workload key derivation |
| **crypto** | ✅ Complete | Handshakes, certificates, HKDF key derivation |
| **tunnel** | ✅ Complete | TunnelBackend trait + kernel/userspace implementations |
| **discovery** | ✅ Complete | mDNS + static peers, DiscoveryService |
| **address** | ✅ Complete | NetworkConfig, IPv6 overlay addressing |
| **avena-overlay** | ✅ Functional | Basic daemon with discovery→handshake→tunnel flow |

### Gaps in Current Implementation

1. **IP/Route management uses shell commands** - `avena_overlay.rs` calls `ip` binary instead of rtnetlink
2. **Certificate exchange not in handshake** - Design doc specifies cert chain validation during tunnel establishment
3. **No Babel routing** - Only direct peer routes added, no mesh routing

---

## Remaining Work

### Phase 5: Routing Integration (Babel via FRR/vtysh)

Per design doc: Babel (RFC 8966) via FRR provides IP-layer routing. Babel has no YANG model, so gRPC/mgmtd is not available—must use vtysh.

### Phase 6: Container Networking

For Addressable workloads requiring overlay IPs. Uses Quadlet for container lifecycle.

### Phase 7: Sidecar

Minimal binary for Addressable workloads with userspace WireGuard.

### Improvements to Existing Code

Replace shell commands with proper netlink APIs.

---

## Implementation Tasks

### Task 1: Replace Shell Commands with rtnetlink

**Goal:** Replace `ip` command invocations in avena-overlay with rtnetlink crate calls.

**Files:**
- `src/netlink/mod.rs` (new)
- `src/netlink/address.rs` (new)
- `src/netlink/route.rs` (new)
- `src/bin/avena_overlay.rs` (modify)

**Subtasks:**

1.1. Create `src/netlink/mod.rs` with public API:
```rust
pub mod address;
pub mod route;
pub use address::{add_address, remove_address};
pub use route::{add_route, remove_route};
```

1.2. Create `src/netlink/address.rs`:
- `add_address(iface: &str, addr: Ipv6Addr, prefix_len: u8) -> Result<(), NetlinkError>`
- `remove_address(iface: &str, addr: Ipv6Addr) -> Result<(), NetlinkError>`
- `set_link_up(iface: &str) -> Result<(), NetlinkError>`

1.3. Create `src/netlink/route.rs`:
- `add_route(prefix: IpNet, iface: &str, gateway: Option<Ipv6Addr>) -> Result<(), NetlinkError>`
- `remove_route(prefix: IpNet, iface: &str) -> Result<(), NetlinkError>`

1.4. Update avena_overlay.rs:
- Replace `assign_interface_address()` with netlink calls
- Replace `add_peer_route()` with netlink calls

1.5. Add rtnetlink dependency to Cargo.toml

**Tests:** Unit tests for address/route operations (ignored, require root/netns)

---

### Task 2: Certificate Exchange in Handshake

**Goal:** Add certificate chain validation during tunnel establishment per design doc Phase 1 (Tunnel Establishment).

**Files:**
- `src/bin/avena_overlay.rs` (modify)
- `src/daemon/mod.rs` (new or modify)

**Subtasks:**

2.1. Add `trusted_root: Option<PathBuf>` to OverlayConfig

2.2. Load and validate root CA on startup

2.3. Extend handshake protocol:
- After HANDSHAKE_MAGIC + VERSION, exchange certificate chains
- Validate peer cert chain against trusted root
- Verify device_id matches cert public key hash

2.4. Update HandshakeMessage to include optional cert chain (backward compatible)

**Decision needed:** Should this be mandatory or optional? Design doc says "avena-overlay configured with trusted root CA at startup" but current implementation works without certs.

---

### Task 3: Routing Module (Babel Integration)

**Goal:** Create routing module for Babel/FRR integration via vtysh.

**Files:**
- `src/routing/mod.rs` (new)
- `src/routing/babel.rs` (new)

**Subtasks:**

3.1. Create `src/routing/mod.rs`:
```rust
pub mod babel;
pub use babel::{BabelRouting, BabelConfig, Route, BabelRoute};
```

3.2. Create `src/routing/babel.rs`:
```rust
pub struct BabelConfig {
    pub vtysh_path: PathBuf,
    pub config_path: PathBuf,
    pub hello_interval: Duration,
    pub update_interval: Duration,
}

pub struct BabelRouting { ... }

impl BabelRouting {
    pub fn new(config: BabelConfig) -> Result<Self, RoutingError>;
    pub async fn apply_config(&self) -> Result<(), RoutingError>;
    pub async fn add_interface(&self, name: &str) -> Result<(), RoutingError>;
    pub async fn remove_interface(&self, name: &str) -> Result<(), RoutingError>;
    pub async fn announce_route(&self, prefix: IpNet) -> Result<(), RoutingError>;
    pub async fn routes(&self) -> Result<Vec<Route>, RoutingError>;
    pub async fn babel_routes(&self) -> Result<Vec<BabelRoute>, RoutingError>;
}
```

3.3. Implement vtysh command execution:
- Write FRR config to file
- Execute `vtysh -c "configure terminal"` commands
- Parse `show ipv6 route json` output
- Parse `show babel route` text output

3.4. Add routing config to OverlayConfig:
```rust
pub babel: Option<BabelConfig>,
```

3.5. Integrate with avena-overlay main loop:
- On startup: add overlay interface to babel
- Announce own overlay prefix

**Tests:** Integration tests with mock vtysh or real FRR in container

---

### Task 4: Container Networking Module

**Goal:** Create container networking primitives for Addressable workloads.

**Files:**
- `src/container/mod.rs` (new)
- `src/container/veth.rs` (new)
- `src/container/routing.rs` (new)
- `src/container/bridge.rs` (new)

**Subtasks:**

4.1. Create `src/container/veth.rs`:
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
Uses rtnetlink with netns support.

4.2. Create `src/container/routing.rs`:
```rust
pub async fn init_host_routing(
    overlay_prefix: &IpNet,
    internet_iface: &str,
) -> Result<(), RoutingError>;

pub async fn setup_workload_routes(
    netns: &str,
    gateway: &Ipv6Addr,
) -> Result<(), RoutingError>;
```

4.3. Create `src/container/bridge.rs`:
```rust
pub struct BridgeManager { bridge_name: String }

impl BridgeManager {
    pub fn new(name: &str) -> Result<Self, BridgeError>;
    pub async fn add_interface(&self, iface: &str) -> Result<(), BridgeError>;
    pub async fn remove_interface(&self, iface: &str) -> Result<(), BridgeError>;
}
```

4.4. Create `src/container/mod.rs`:
```rust
pub struct WorkloadNetwork {
    pub host_veth: String,
    pub container_veth: String,
    pub overlay_ip: Ipv6Addr,
    pub gateway: Ipv6Addr,
    pub netns: String,
}

pub struct ContainerNetworking { ... }

impl ContainerNetworking {
    pub fn new(config: ContainerNetConfig) -> Result<Self, NetError>;
    pub async fn init_host_networking(&self) -> Result<(), NetError>;
    pub async fn setup_workload(
        &self,
        workload_id: &str,
        overlay_ip: Ipv6Addr,
        netns: &str,
    ) -> Result<WorkloadNetwork, NetError>;
    pub async fn teardown_workload(&self, workload_id: &str) -> Result<(), NetError>;
}
```

**Tests:** Integration tests in network namespaces

---

### Task 5: Quadlet Integration

**Goal:** Add Quadlet support for container lifecycle management.

**Files:**
- `src/container/quadlet.rs` (new)

**Subtasks:**

5.1. Define WorkloadSpec struct (from design doc):
```rust
pub struct WorkloadSpec {
    pub id: WorkloadId,
    pub image: String,
    pub env: HashMap<String, String>,
    pub mounts: Vec<MountSpec>,
    pub network_mode: NetworkMode,
    pub permitted_publish: Vec<SubjectPattern>,
    pub permitted_subscribe: Vec<SubjectPattern>,
    // ...
}

pub enum NetworkMode {
    Messaging,
    Addressable,
}
```

5.2. Create QuadletManager:
```rust
pub struct QuadletManager {
    unit_dir: PathBuf,  // /etc/containers/systemd/
}

impl QuadletManager {
    pub fn new(unit_dir: PathBuf) -> Self;
    pub async fn create_workload(&self, workload: &WorkloadSpec) -> Result<(), QuadletError>;
    pub async fn remove_workload(&self, workload_id: &str) -> Result<(), QuadletError>;
    pub async fn start(&self, workload_id: &str) -> Result<(), QuadletError>;
    pub async fn stop(&self, workload_id: &str) -> Result<(), QuadletError>;
}
```

5.3. Generate .container files:
```ini
[Container]
Image=<image>
Environment=<env>
Network=none  # or specific netns
...

[Service]
Restart=always

[Install]
WantedBy=default.target
```

5.4. Integrate with systemd via D-Bus or `systemctl` commands

**Tests:** Unit tests for .container file generation

---

### Task 6: Avena Sidecar Binary

**Goal:** Create minimal sidecar binary for Addressable workloads.

**Files:**
- `src/bin/avena_sidecar.rs` (new)

**Subtasks:**

6.1. Define sidecar control protocol (NATS messages):
```rust
enum SidecarControl {
    AddPeer { pubkey: [u8; 32], endpoint: SocketAddr, allowed_ips: Vec<IpNet> },
    RemovePeer { pubkey: [u8; 32] },
    UpdateEndpoint { pubkey: [u8; 32], endpoint: SocketAddr },
    Shutdown,
}
```

6.2. Create AvenaSidecar struct:
```rust
struct AvenaSidecar {
    keypair: DeviceKeypair,  // Derived from host
    overlay_ip: Ipv6Addr,
    tunnel: UserspaceBackend,  // Always userspace
    // NATS client for control channel
}

impl AvenaSidecar {
    async fn new(config: SidecarConfig) -> Result<Self, SidecarError>;
    async fn run(&mut self) -> Result<(), SidecarError>;
    async fn handle_control(&self, msg: SidecarControl) -> Result<(), SidecarError>;
}
```

6.3. Implement control channel:
- Read derived keypair from env/file (passed by host)
- Subscribe to `avena.sidecar.<workload_id>.control`
- Process AddPeer/RemovePeer/UpdateEndpoint messages
- Configure userspace WireGuard accordingly

6.4. Add binary to Cargo.toml:
```toml
[[bin]]
name = "avena-sidecar"
path = "src/bin/avena_sidecar.rs"
```

**Note:** NATS dependency needed. Consider whether to add full NATS or use simpler Unix socket protocol initially.

**Tests:** Integration tests with mock control channel

---

### Task 7: Host-Sidecar Communication in `avena-overlay`

**Goal:** Enable avena-overlay to spawn and control sidecars for Addressable workloads.

**Files:**
- `src/daemon/sidecar.rs` (new)
- `src/bin/avena_overlay.rs` (modify)

**Subtasks:**

7.1. Create SidecarManager:
```rust
pub struct SidecarManager {
    sidecars: HashMap<String, SidecarHandle>,
}

pub struct SidecarHandle {
    workload_id: String,
    overlay_ip: Ipv6Addr,
    derived_keypair: DeviceKeypair,
    control_subject: String,
}

impl SidecarManager {
    pub async fn spawn_sidecar(
        &mut self,
        workload: &WorkloadSpec,
        host_keypair: &DeviceKeypair,
        network: &NetworkConfig,
    ) -> Result<SidecarHandle, SidecarError>;

    pub async fn push_peer(
        &self,
        workload_id: &str,
        peer: &PeerConfig,
    ) -> Result<(), SidecarError>;

    pub async fn shutdown_sidecar(&mut self, workload_id: &str) -> Result<(), SidecarError>;
}
```

7.2. Derive workload keypairs:
```rust
let workload_keypair = derive_workload_keypair(&host_keypair, workload_id);
let workload_ip = network.workload_address(&host_id, workload_idx);
```

7.3. Integrate with avena-overlay:
- Track Addressable workloads
- When new peer discovered, push to relevant sidecars
- When workload terminates, cleanup sidecar

---

## Implementation Order

```
Task 1: rtnetlink (foundation)
    ↓
Task 3: Routing/Babel (mesh networking)
    ↓
Task 2: Certificate exchange (security)
    ↓
Task 4: Container networking (workload support)
    ↓
Task 5: Quadlet (container lifecycle)
    ↓
Task 6: Sidecar binary (Addressable workloads)
    ↓
Task 7: Host-sidecar integration (complete flow)
```

**Rationale:**
1. rtnetlink is foundational—used by everything else
2. Babel enables multi-hop routing (current impl only does direct peers)
3. Certs add security for production use
4. Container networking needed before sidecars
5. Quadlet manages container lifecycle
6. Sidecar binary for Addressable mode
7. Host integration ties it together

---

## Dependencies to Add

```toml
# For Task 1 (rtnetlink)
rtnetlink = "0.14"
futures = "0.3"

# For Task 6 (NATS - if using NATS for sidecar control)
# async-nats = "0.35"

# Alternative: Unix socket for sidecar control (no new deps)
```

---

## Testing Strategy

| Task | Test Type | Requirements |
|------|-----------|--------------|
| 1 | Integration | Root or network namespace |
| 2 | Unit + Integration | Mock certs, real handshake |
| 3 | Integration | FRR/Babel in container |
| 4 | Integration | Network namespaces |
| 5 | Unit | Mock systemd |
| 6 | Integration | Real userspace WG |
| 7 | Integration | Full daemon + sidecar |

---

## Open Questions for Implementation

1. **Sidecar control channel:** NATS (per design doc) or Unix socket (simpler, no new deps)?
   - Design doc specifies NATS with JWT scoping
   - Unix socket is simpler for initial implementation
   - **Recommendation:** Start with Unix socket, add NATS later

2. **Certificate exchange timing:**
   - Add to existing handshake protocol (breaking change)?
   - Or make optional/versioned?
   - **Recommendation:** Version the handshake, make certs optional in v2

3. **Babel integration depth:**
   - Just add interface and announce prefix?
   - Or full route table monitoring for multi-hop?
   - **Recommendation:** Start minimal, expand as needed
