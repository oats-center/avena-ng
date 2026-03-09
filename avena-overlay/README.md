# avena-overlay

Encrypted, authenticated IP connectivity overlay network library and daemon.

## Overview

avena-overlay creates a WireGuard-based mesh network where devices:

- Derive deterministic identities from Ed25519 keypairs
- Map identities to stable IPv6 overlay addresses
- Discover peers via mDNS or static configuration
- Perform authenticated handshakes yielding WireGuard keys
- Establish encrypted tunnels (kernel or userspace WireGuard)

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     avena-overlay                           │
├─────────────────────────────────────────────────────────────┤
│  identity   │  crypto    │  discovery  │  tunnel            │
│  ─────────  │  ────────  │  ─────────  │  ──────            │
│  DeviceId   │  Handshake │  mDNS       │  TunnelBackend     │
│  Keypair    │  Certs     │  Static     │  ├─ Kernel         │
│  Workload   │  Sessions  │  Events     │  └─ Userspace      │
├─────────────────────────────────────────────────────────────┤
│                     wg (WireGuard)                          │
│  ─────────────────────────────────────────────────────────  │
│  Types │ UAPI │ Linux netlink │ Userspace (wireguard-go)    │
└─────────────────────────────────────────────────────────────┘
```

## Modules

| Module      | Purpose                                                 |
| ----------- | ------------------------------------------------------- |
| `identity`  | Ed25519 device keypairs and stable 16-byte identifiers  |
| `address`   | Deterministic IPv6 overlay address derivation (ULA /48) |
| `crypto`    | Handshakes, certificates, HKDF key derivation           |
| `discovery` | mDNS and static peer discovery with event broadcast     |
| `tunnel`    | Backend-agnostic WireGuard tunnel management            |
| `wg`        | Low-level WireGuard types, UAPI, kernel netlink         |
| `daemon`    | Configuration and peer state for `avena-overlay`        |

## Usage

Quick start on physical hosts: `GETTING_STARTED_PHYSICAL.md`

### Library

```rust
use avena_overlay::{DeviceKeypair, NetworkConfig, derive_wireguard_keypair};

// Generate or load device identity
let device = DeviceKeypair::generate();
let device_id = device.device_id();

// Derive overlay address
let network = NetworkConfig::default_ula();
let overlay_ip = network.device_address(&device_id);

// Derive WireGuard keys
let wg_keys = derive_wireguard_keypair(&device);
```

### Binaries

**avena-overlay** - The overlay network daemon

```bash
cargo run --bin avena-overlay
```

**avena-keygen** - Key generation utility

```bash
# Generate random keypair
cargo run --bin avena-keygen -- generate

# Deterministic from seed
cargo run --bin avena-keygen -- from-seed <64-char-hex>

# Load from file
cargo run --bin avena-keygen -- from-file /path/to/key
```

## Building

```bash
cargo build --release
```

## Testing

```bash
cargo test
```
