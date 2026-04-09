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

- IP/mDNS physical host quick start: `getting-started.md`
- Mixed IP + ACME quick start: `acme-getting-started.md`

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

## Containerized deployment

For an overlay-only sidecar image, build from `container/Containerfile` and run it with the provided quadlet unit:

```bash
podman build -t localhost/avena-overlay:latest -f avena-overlay/container/Containerfile .
```

Copy the image to another machine:

```bash
podman save localhost/avena-overlay:latest -o /tmp/avena-overlay.tar
scp /tmp/avena-overlay.tar remote:/tmp/
ssh remote podman load -i /tmp/avena-overlay.tar
```

Quadlet files live under `avena-overlay/container/quadlet/`.
Install `avena-overlay.container` there as needed, then place your runtime config, certs, and device keypair in `/etc/avena/`.

The overlay sidecar publishes:

- UDP `51820` for WireGuard data
- TCP `51821` for handshake control

If you change `listen_port`, publish `listen_port` and `listen_port + 1` instead.

Run your normal `nats-server` container in the same network namespace as the overlay sidecar so it can use the overlay-provided networking.
Publish `4222` from that sibling container if you want NATS reachable from outside the host.

Example quadlet for the NATS sidecar is included at `avena-overlay/container/quadlet/avena-nats.container.example`:

```ini
[Unit]
Description=NATS using avena-overlay network namespace

[Container]
Image=docker.io/library/nats:latest
ContainerName=avena-nats
Network=avena-overlay.container
PublishPort=4222:4222/tcp

[Service]
Restart=always

[Install]
WantedBy=default.target
```

Remote nodes that should publish to that NATS server need `telemetry.nats_url = "nats://<host-ip>:4222"`.

The GitHub Actions workflow publishes `ghcr.io/<owner>/avena-overlay` on pushes to `main` and tags matching `v*`.
Use `podman pull ghcr.io/<owner>/avena-overlay:latest` on hosts that should run the quadlet unit.
If the package is private, run `podman login ghcr.io` first.

## Release binaries

Tag pushes publish tarball assets for `avena-overlay` on both `x86_64-unknown-linux-gnu` and `aarch64-unknown-linux-gnu`.

Example asset names:

- `avena-overlay-x86_64-unknown-linux-gnu.tar.gz`
- `avena-overlay-aarch64-unknown-linux-gnu.tar.gz`

Install by unpacking the tarball and copying `avena-overlay` into your PATH.
