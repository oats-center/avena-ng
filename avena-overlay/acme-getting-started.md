# `avena-overlay` ACME Quick Start

Minimal runbook for a node that should speak to both normal IP/mDNS peers and ACME/C-V2X peers at the same time.

This assumes:

- the `acme` helper binary is already installed on the node,
- the ACME radio interface is visible to Linux,
- `babeld` and WireGuard prerequisites from `getting-started.md` are already satisfied,
- device key/cert/root cert files already exist under `/etc/avena/`.

## 1) Start from the mixed example config

Use `examples/mixed-ip-acme.toml` as the base shape.

Copy it to the host:

```bash
sudo mkdir -p /etc/avena
sudo cp mixed-ip-acme.toml /etc/avena/avena-overlay.toml
```

Adjust these fields before first run:

- `interface_name`: the base overlay interface name for the node
- `keypair_path`, `trusted_root_cert`, `device_cert`: your real credential paths
- `discovery.mdns_interfaces`: the normal IP NICs that should do mDNS, for example `eth0`
- `telemetry.node_id`: human-readable node name to advertise over ACME discovery
- `acme.interface`: the real MK6/C-V2X interface name, for example `cv2x0`
- `acme.binary_path`: the actual path to the helper binary on that host

## 2) Understand what the ACME block does

The `[acme]` block enables the shared-medium backend.

- `name` is the logical underlay name used inside `avena-overlay`
- `event_port` must match across all ACME nodes on the same channel
- `wg_proxy_port` is the shared local UDP endpoint all ACME-backed WireGuard peers target
- `tx_local_port` and `rx_local_port` are the local helper-facing ports for the external `acme` TX/RX processes
- `announce_interval_ms` controls ACME discovery rebroadcast
- `control_timeout_ms` controls ACME handshake request/response timeout

If you are translating from `scripts/debug-start.sh` / `acme2wg.py`, the field mapping is:

- `listen_port` = `WG_PORT`
- `wg_proxy_port` = `WG_ENDPOINT_PORT`
- `tx_local_port` = `ACME_TX_PORT`
- `rx_local_port` = `ACME_RX_PORT`

The proven default tuple from the demo is therefore:

- `listen_port = 51820`
- `wg_proxy_port = 51821`
- `tx_local_port = 51831`
- `rx_local_port = 51832`

If your helper uses different defaults, change those values consistently on every ACME node.

## 3) Mixed-mode behavior

With the example config:

- normal IP peers are still discovered over mDNS on `discovery.mdns_interfaces`
- ACME peers are discovered over the shared ACME channel
- both kinds of peers become normal overlay neighbors, and Babel can route between them

If a node should be ACME-only, set:

```toml
[discovery]
enable_mdns = false
mdns_interfaces = []
```

and keep the `[acme]` block.

## 4) First start

Run with debug logging the first time:

```bash
sudo RUST_LOG=debug /usr/local/bin/avena-overlay /etc/avena/avena-overlay.toml
```

Useful startup lines to look for:

- `Discovery service initialized`
- `ACME runtime started`
- `Handshake listener bound`
- `Started babeld for dynamic routing`
- `Peer discovered`
- `Peer connected`

## 5) First validation checklist

On the node:

```bash
sudo wg show
ip -6 addr show
ip -6 route show
```

What you want to see:

- the base interface, for example `avena0`, exists
- per-peer `av-...` interfaces appear as neighbors are learned
- both IP-backed and ACME-backed peers show up as WireGuard peers
- Babel installs overlay routes through those interfaces

## 6) ACME-specific troubleshooting

- No `ACME runtime started` log:
  - `acme.binary_path` is wrong, or the helper is not executable
- ACME discovery never appears:
  - `acme.interface` is wrong
  - `event_port` does not match between nodes
  - the radio helper is not actually receiving on that channel
- IP peers work but ACME peers do not:
  - confirm the helper TX/RX pair can run on the platform
  - confirm the radio interface is present before startup
  - confirm all ACME nodes use the same `destination` and `event_port`
- ACME peers discover but do not connect:
  - increase `control_timeout_ms`
  - check for helper stderr in the `avena-overlay` logs

## 7) Recommended first hardware test

Use two ACME-capable nodes and one normal LAN-only node.

1. Bring up the LAN-only node with normal `getting-started.md` config.
2. Bring up the two ACME-capable nodes with the mixed config.
3. Verify the ACME nodes still discover LAN peers over mDNS.
4. Verify the ACME nodes discover each other over ACME.
5. Verify Babel installs routes spanning both underlays.
6. Ping overlay addresses across all three nodes.

That is the simplest end-to-end validation that the mixed IP + ACME path is behaving as intended.
