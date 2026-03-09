# avena-overlay Physical Hosts Quick Start

Minimal runbook to bring up `avena-overlay` on a few real Linux hosts.

This is the fastest path from zero to first overlay ping.

## Assumptions

- 3 Linux hosts on the same L2 network (same VLAN/subnet).
- You can run commands as root (or with equivalent capabilities).
- mDNS is allowed on the LAN (UDP 5353 multicast).
- You are using the default overlay prefix `fd00:a0e0:a000::/48`.

Example hostnames used below: `node1`, `node2`, `node3`.

## 1) Install host dependencies

On each host:

```bash
sudo apt-get update
sudo apt-get install -y wireguard-tools babeld
```

Optional fallback backend support:

```bash
sudo apt-get install -y wireguard-go
```

Open firewall ports on each host:

- UDP `51820` (WireGuard data plane)
- TCP `51821` (Avena handshake control plane)
- UDP `5353` multicast (mDNS discovery)

## 2) Build binaries once

On a build machine with Rust toolchain:

```bash
cd /path/to/avena
cargo build --release -p avena-overlay --bin avena-overlay --bin avena-keygen
```

Copy binaries to each host:

```bash
scp target/release/avena-overlay target/release/avena-keygen node1:/usr/local/bin/
scp target/release/avena-overlay target/release/avena-keygen node2:/usr/local/bin/
scp target/release/avena-overlay target/release/avena-keygen node3:/usr/local/bin/
```

## 3) Create PKI and per-node credentials

On your admin machine:

```bash
mkdir -p ./avena-bootstrap
cd ./avena-bootstrap

# Root CA key + cert
/usr/local/bin/avena-keygen generate ca.key > ca.meta
/usr/local/bin/avena-keygen cert init-ca ca.key root.cert > ca.cert.meta

# Node keys + certs (repeat per node)
/usr/local/bin/avena-keygen generate node1.key > node1.meta
/usr/local/bin/avena-keygen cert issue ca.key root.cert node1.key node1.cert > node1.cert.meta

/usr/local/bin/avena-keygen generate node2.key > node2.meta
/usr/local/bin/avena-keygen cert issue ca.key root.cert node2.key node2.cert > node2.cert.meta

/usr/local/bin/avena-keygen generate node3.key > node3.meta
/usr/local/bin/avena-keygen cert issue ca.key root.cert node3.key node3.cert > node3.cert.meta
```

Each `nodeX.meta` contains that node's `device_id` and `overlay_ip`.

Distribute credentials:

- Every node gets the same `root.cert`.
- Each node gets its own `nodeX.key` and `nodeX.cert`.

Example for `node1`:

```bash
ssh node1 'sudo mkdir -p /etc/avena && sudo chown root:root /etc/avena'
scp root.cert node1.key node1.cert node1:/tmp/
ssh node1 'sudo mv /tmp/root.cert /etc/avena/root.cert && sudo mv /tmp/node1.key /etc/avena/device.key && sudo mv /tmp/node1.cert /etc/avena/device.cert && sudo chmod 600 /etc/avena/device.key /etc/avena/device.cert && sudo chmod 644 /etc/avena/root.cert'
```

Repeat for `node2`/`node3` with their own key/cert files.

## 4) Create config on each node

Find the underlay NIC name (example command):

```bash
ip route get 1.1.1.1 | awk '/dev/ {print $5; exit}'
```

Create `/etc/avena/avena-overlay.toml` on each host:

```toml
interface_name = "avena0"
tunnel_mode = "prefer_kernel"
listen_port = 51820
keypair_path = "/etc/avena/device.key"
trusted_root_cert = "/etc/avena/root.cert"
device_cert = "/etc/avena/device.cert"
persistent_keepalive = 5
dead_peer_timeout_secs = 30

[network]
prefix = "fd00:a0e0:a000::"
prefix_len = 48

[discovery]
enable_mdns = true
mdns_interfaces = ["eth0"]
presence_reannounce_interval_ms = 1000
peer_retry_interval_ms = 250

[routing.babel]
socket_path = "/run/avena/babel.sock"
binary_path = "/usr/sbin/babeld"
hello_interval = 1000
update_interval = 4000
```

Change `mdns_interfaces` to the real NIC for each host.

## 5) Start daemon

Manual start:

```bash
sudo RUST_LOG=info /usr/local/bin/avena-overlay /etc/avena/avena-overlay.toml
```

You should see logs like:

- `Loaded device certificate`
- `Handshake listener bound`
- `Started babeld for dynamic routing`
- `Peer discovered` / `Peer connected`

## 6) Verify connectivity

On each host:

```bash
ip -6 addr show avena0
sudo wg show avena0
```

From `node1`, ping `node2` overlay IP (from `node2.meta`):

```bash
ping -6 <node2_overlay_ip>
```

## Common issues

- No peers discovered:
  - mDNS blocked on network/firewall, or wrong `mdns_interfaces`.
- Startup fails with routing error:
  - `babeld` missing or wrong path (`routing.babel.binary_path`).
- Handshake/data never established:
  - TCP `51821` and UDP `51820` not open end-to-end.
- Interface creation fails:
  - run as root (or grant required net admin capabilities).

## Next step

After this baseline works, move to static peer config for cross-subnet/WAN setups and add a systemd unit for persistent service management.
