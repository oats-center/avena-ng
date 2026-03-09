# Babeld Integration Plan for `avena-overlay`

## Problem Statement

The current `avena-overlay` implementation adds static /128 routes for each directly-connected peer. This works for 2-node scenarios but fails for multi-hop routing:

```
Node A ←→ Node B ←→ Node C
```

Node A has no route to Node C because:
1. Routes are added only when a direct WireGuard tunnel forms
2. There's no dynamic routing protocol to propagate routes through B

The `linear_three_hop.toml` and `star_gateway.toml` scenarios fail because of this.

## Solution: Integrate babeld

Use babeld (the reference Babel RFC 8966 implementation) as an external process with socket-based control from `avena-overlay`.

### Why babeld over FRR?

| Aspect | babeld | FRR |
|--------|--------|-----|
| Binary size | ~50KB | ~20MB+ |
| Dependencies | None | Full routing suite |
| Control interface | Unix socket, text protocol | vtysh (CLI tool) |
| IPv6 support | Native dual-stack | Yes |
| Complexity | Single-purpose | Multi-protocol |

### Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      avena-overlay                           │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐ │
│  │  Discovery  │  │   Tunnel    │  │  BabeldController   │ │
│  │  (mDNS)     │  │  (WireGuard)│  │  (new module)       │ │
│  └──────┬──────┘  └──────┬──────┘  └──────────┬──────────┘ │
│         │                │                     │            │
│         │                │         ┌───────────┴──────────┐ │
│         │                │         │ Unix Socket IPC      │ │
│         │                │         │ /run/avena/babel.sock│ │
└─────────┼────────────────┼─────────┼─────────────────────┬─┘
          │                │         │                     │
          │                │         ▼                     │
          │                │    ┌─────────┐                │
          │                │    │ babeld  │                │
          │                │    │ process │                │
          │                │    └────┬────┘                │
          │                │         │                     │
          ▼                ▼         ▼                     │
     ┌─────────────────────────────────────┐               │
     │         Linux Kernel                 │               │
     │  ┌─────────┐  ┌──────────────────┐  │               │
     │  │ avena0  │  │  Routing Table   │◄─┼───────────────┘
     │  │ (WG)    │  │  (managed by     │  │   babeld manages
     │  └─────────┘  │   babeld)        │  │   routes directly
     │               └──────────────────┘  │
     └─────────────────────────────────────┘
```

**Key insight:** babeld directly manages the kernel routing table via its own netlink. `avena-overlay` doesn't need to add/remove routes—just tell babeld which interfaces to participate in.

---

## Implementation Tasks

### Task 1: Create `src/routing/mod.rs` Module

**Purpose:** Abstract routing control, starting with babeld backend.

```rust
// src/routing/mod.rs
pub mod babeld;
pub mod error;

pub use babeld::{BabeldController, BabeldConfig};
pub use error::RoutingError;
```

**Files to create:**
- `src/routing/mod.rs`
- `src/routing/error.rs`
- `src/routing/babeld.rs`

---

### Task 2: Implement `BabeldController`

**File:** `src/routing/babeld.rs`

```rust
use std::path::PathBuf;
use tokio::net::UnixStream;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

pub struct BabeldConfig {
    pub socket_path: PathBuf,
    pub binary_path: PathBuf,
    pub hello_interval: u16,      // default: 4000ms
    pub update_interval: u16,     // default: 16000ms
}

impl Default for BabeldConfig {
    fn default() -> Self {
        Self {
            socket_path: PathBuf::from("/run/avena/babel.sock"),
            binary_path: PathBuf::from("/usr/sbin/babeld"),
            hello_interval: 4000,
            update_interval: 16000,
        }
    }
}

pub struct BabeldController {
    config: BabeldConfig,
    process: Option<tokio::process::Child>,
    stream: Option<UnixStream>,
}

impl BabeldController {
    pub fn new(config: BabeldConfig) -> Self;

    /// Start babeld process with given interfaces
    pub async fn start(&mut self, interfaces: &[&str]) -> Result<(), RoutingError>;

    /// Stop babeld process
    pub async fn stop(&mut self) -> Result<(), RoutingError>;

    /// Add interface to babel routing domain
    pub async fn add_interface(&mut self, name: &str) -> Result<(), RoutingError>;

    /// Remove interface from babel routing domain
    pub async fn flush_interface(&mut self, name: &str) -> Result<(), RoutingError>;

    /// Get current routes learned via babel
    pub async fn dump(&mut self) -> Result<BabelDump, RoutingError>;

    /// Subscribe to route/neighbor changes
    pub async fn monitor(&mut self) -> Result<BabelEventStream, RoutingError>;
}
```

**babeld command to spawn:**
```bash
babeld -G /run/avena/babel.sock \
       -d 1 \
       -h 4000 \
       -H 4000 \
       avena0
```

Options:
- `-G <socket>`: Read-write control socket
- `-d 1`: Debug level (log route changes)
- `-h <ms>`: Hello interval for wireless interfaces
- `-H <ms>`: Hello interval for wired interfaces
- Interface list: which interfaces to route over

---

### Task 3: Implement Socket Protocol Parser

**babeld protocol format:**

Connection response:
```
BABEL 1.0
version babeld-1.13.1
host somehost
my-id aa:bb:cc:dd:ee:ff:00:11
ok
```

Commands:
- `dump` → outputs routes, neighbors, xroutes, then `ok`
- `interface <name>` → add interface dynamically
- `flush interface <name>` → remove interface
- `monitor` → stream updates until `unmonitor`
- `quit` → close connection

Response lines:
```
add interface avena0 up true ipv6 fe80::1%avena0
add neighbour 12ab34cd address fe80::2 if avena0 reach ffff rxcost 256 txcost 256
add route 12ab34cd prefix fd00:a0e0:a000::1/128 installed yes metric 256 via fe80::2 if avena0
add xroute prefix fd00:a0e0:a000::/48 metric 0
ok
```

**Parsing strategy:**
```rust
pub enum BabelMessage {
    Interface { name: String, up: bool, ipv6: Option<Ipv6Addr> },
    Neighbour { id: String, address: Ipv6Addr, interface: String, rxcost: u16, txcost: u16 },
    Route { id: String, prefix: IpNet, installed: bool, metric: u16, via: Ipv6Addr, interface: String },
    Xroute { prefix: IpNet, metric: u16 },
}

pub struct BabelDump {
    pub interfaces: Vec<BabelInterface>,
    pub neighbours: Vec<BabelNeighbour>,
    pub routes: Vec<BabelRoute>,
    pub xroutes: Vec<BabelXroute>,
}

fn parse_babel_line(line: &str) -> Option<BabelMessage>;
```

---

### Task 4: Extend `OverlayConfig`

**File:** `src/daemon/config.rs`

Add routing configuration:

```rust
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct RoutingConfig {
    #[serde(default = "default_routing_enabled")]
    pub enable_babel: bool,

    #[serde(default)]
    pub babel: BabeldConfig,
}

fn default_routing_enabled() -> bool {
    true  // Enable by default for mesh routing
}
```

Add to `OverlayConfig`:
```rust
pub struct OverlayConfig {
    // ... existing fields ...

    #[serde(default)]
    pub routing: RoutingConfig,
}
```

Example TOML:
```toml
[routing]
enable_babel = true

[routing.babel]
socket_path = "/run/avena/babel.sock"
hello_interval = 4000
```

---

### Task 5: Integrate into `avena-overlay` Event Loop

**File:** `src/bin/avena_overlay.rs`

Changes to `OverlayDaemon::new()`:
```rust
// After tunnel setup, before discovery
let routing = if config.routing.enable_babel {
    let mut controller = BabeldController::new(config.routing.babel.clone());
    controller.start(&[&config.interface_name]).await?;
    Some(controller)
} else {
    None
};
```

Changes to `OverlayDaemonInner`:
```rust
struct OverlayDaemonInner {
    // ... existing fields ...
    routing: Option<BabeldController>,
}
```

**Remove static route calls:**

In `perform_outgoing_handshake_inner()` and `handle_incoming_handshake_inner()`:
```rust
// REMOVE this line:
// add_peer_route(&self.config.interface_name, peer_overlay_ip)?;

// Babel will learn the route automatically via the WireGuard interface
```

**Shutdown handling:**
```rust
async fn shutdown(&self) {
    // ... existing peer cleanup ...

    if let Some(ref mut routing) = self.routing {
        if let Err(e) = routing.stop().await {
            warn!("Failed to stop babeld: {}", e);
        }
    }
}
```

---

### Task 6: Update WireGuard Peer allowed_ips

**Problem:** Currently peers have `allowed_ips = [peer_ip/128]`. For multi-hop routing, this needs to include routes learned via babel.

**Solution:** Monitor babel routes and update WireGuard peer allowed_ips when routes change.

In the event loop:
```rust
// New branch in select!
Some(event) = routing_events.recv() => {
    match event {
        BabelEvent::RouteAdded { prefix, via, interface } => {
            // Find WireGuard peer by next-hop address
            // Update allowed_ips to include the new prefix
        }
        BabelEvent::RouteRemoved { prefix, .. } => {
            // Remove prefix from peer allowed_ips
        }
    }
}
```

**Alternative (simpler, recommended for v1):**
Set `allowed_ips = [::/0]` for all peers and let the kernel routing table (managed by babel) decide. This is less secure but simpler.

For v1, use the simpler approach. Security hardening can come later with proper prefix filtering.

---

### Task 7: Testbed Support

**File:** Update `avena-testbed` to install/configure babeld

The testbed creates network namespaces. Each namespace needs:
1. babeld binary available (copy or bind-mount)
2. Socket directory (`/run/avena/`) created
3. babeld started by avena-overlay automatically

Testbed changes:
- Ensure babeld is in PATH for namespace processes
- Create `/run/avena/` in each namespace before starting avena-overlay

---

## Implementation Order

```
Task 1: Create routing module structure
    │
    ▼
Task 2: Implement BabeldController (spawn/stop)
    │
    ▼
Task 3: Implement socket protocol parser
    │
    ▼
Task 4: Extend OverlayConfig
    │
    ▼
Task 5: Integrate into avena-overlay (basic - just spawn babeld)
    │
    ▼
Task 6: Update allowed_ips (v1: use ::/0, simple)
    │
    ▼
Task 7: Testbed support
    │
    ▼
Test: linear_three_hop.toml should pass
```

---

## Testing Strategy

### Unit Tests
- `BabelMessage` parsing
- Config serialization

### Integration Tests (require babeld + root/netns)
- `BabeldController::start()` / `stop()`
- `dump()` returns valid data
- Interface add/flush

### Scenario Tests
- `two_node_basic.toml` — should still pass (no multi-hop)
- `linear_three_hop.toml` — **this is the goal**
- `star_gateway.toml` — multi-path routing
- `mobile_relay.toml` — dynamic topology changes

---

## Dependencies

No new crate dependencies required. We're using:
- `tokio::process` (already available)
- `tokio::net::UnixStream` (already available)
- `tokio::io` for async reading (already available)

babeld must be installed on the system (`/usr/sbin/babeld`).

---

## Open Questions

1. **allowed_ips strategy:**
   - Simple: `::/0` for all peers (less secure, babel decides routing)
   - Complex: Mirror babel routes to WireGuard allowed_ips (more secure, more code)
   - **Recommendation:** Start with `::/0`, harden later

2. **babeld process supervision:**
   - Should avena-overlay restart babeld if it crashes?
   - **Recommendation:** Yes, simple respawn with backoff

3. **Testbed babeld installation:**
   - Require babeld in system PATH?
   - Bundle babeld in testbed?
   - **Recommendation:** Require system babeld, document in README

---

## Success Criteria

1. `linear_three_hop.toml` passes — ping from A to C works through B
2. `star_gateway.toml` passes — all nodes can reach each other
3. Routes converge within 30 seconds of topology change
4. Clean shutdown (babeld process terminates)
5. No regressions in `two_node_basic.toml`
