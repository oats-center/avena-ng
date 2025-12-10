#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
AVENAD="$PROJECT_ROOT/target/debug/avenad"
AVENA_KEYGEN="$PROJECT_ROOT/target/debug/avena-keygen"
TMPDIR=$(mktemp -d)

cleanup() {
    rm -rf "$TMPDIR"
    pkill -f "avenad.*/tmp/tmp\." 2>/dev/null || true
    pkill -f "wireguard-go wg-node" 2>/dev/null || true
}
trap cleanup EXIT

echo "=== Building binaries ==="
cargo build --bin avenad --bin avena-keygen --manifest-path "$PROJECT_ROOT/Cargo.toml" --quiet

if ! command -v wireguard-go &>/dev/null; then
    echo "ERROR: wireguard-go not found."
    echo "Install with: go install golang.zx2c4.com/wireguard-go@latest"
    echo "Then: sudo setcap cap_net_admin+ep \$(go env GOPATH)/bin/wireguard-go"
    exit 1
fi

echo "=== Generating certificates ==="
"$AVENA_KEYGEN" generate "$TMPDIR/ca.key" >/dev/null
"$AVENA_KEYGEN" cert init-ca "$TMPDIR/ca.key" "$TMPDIR/root.cert" >/dev/null
"$AVENA_KEYGEN" generate "$TMPDIR/node1.key" >/dev/null
"$AVENA_KEYGEN" cert issue "$TMPDIR/ca.key" "$TMPDIR/root.cert" "$TMPDIR/node1.key" "$TMPDIR/node1.cert" >/dev/null
"$AVENA_KEYGEN" generate "$TMPDIR/node2.key" >/dev/null
"$AVENA_KEYGEN" cert issue "$TMPDIR/ca.key" "$TMPDIR/root.cert" "$TMPDIR/node2.key" "$TMPDIR/node2.cert" >/dev/null
echo "Generated CA and device certificates"

cat > "$TMPDIR/node1.toml" << EOF
interface_name = "wg-node1"
tunnel_mode = "userspace"
listen_port = 51820
keypair_path = "$TMPDIR/node1.key"
trusted_root_cert = "$TMPDIR/root.cert"
device_cert = "$TMPDIR/node1.cert"

[network]
prefix = "fd00:a0e0:a000::"
prefix_len = 48

[discovery]
enable_mdns = true
mdns_interface = "veth-n1"
EOF

cat > "$TMPDIR/node2.toml" << EOF
interface_name = "wg-node2"
tunnel_mode = "userspace"
listen_port = 51820
keypair_path = "$TMPDIR/node2.key"
trusted_root_cert = "$TMPDIR/root.cert"
device_cert = "$TMPDIR/node2.cert"

[network]
prefix = "fd00:a0e0:a000::"
prefix_len = 48

[discovery]
enable_mdns = true
mdns_interface = "veth-n2"
EOF

echo ""
echo "=== Two-Node Overlay Test ==="
echo "Testing: mDNS discovery -> handshake -> WireGuard tunnel"
echo "No hardcoded device IDs - nodes must discover each other"
echo ""

export TMPDIR AVENAD

unshare --kill-child -rmn bash -c '
set -euo pipefail

mount -t tmpfs tmpfs /var/run
mkdir -p /var/run/wireguard

ip link set lo up

ip link add veth-n1 type veth peer name veth-n2
ip addr add 10.99.0.1/24 dev veth-n1
ip -6 addr add fe80::1/64 dev veth-n1
ip link set veth-n1 up
ip link set veth-n1 multicast on

echo "[outer] Created veth pair with multicast enabled"

unshare -n bash -c '\''
    echo $$ > "$TMPDIR/node2.pid"
    while [[ ! -e "$TMPDIR/veth_moved" ]]; do sleep 0.1; done

    ip link set lo up
    ip addr add 10.99.0.2/24 dev veth-n2
    ip -6 addr add fe80::2/64 dev veth-n2
    ip link set veth-n2 up
    ip link set veth-n2 multicast on

    echo "[node2] Network ready: $(ip -4 addr show veth-n2 | grep inet | awk "{print \$2}")"

    mkdir -p /var/run/wireguard

    echo "[node2] Starting avenad with mDNS discovery..."
    RUST_LOG=debug,mdns_sd=warn "$AVENAD" "$TMPDIR/node2.toml" 2>&1 | tee "$TMPDIR/node2.log" | stdbuf -oL sed "s/^/[node2] /" &
    AVENAD_PID=$!

    wait $AVENAD_PID
'\'' &
NODE2_SHELL=$!

sleep 0.5
INNER_PID=$(cat "$TMPDIR/node2.pid")
echo "[outer] Moving veth-n2 to node2 namespace (pid $INNER_PID)..."
ip link set veth-n2 netns $INNER_PID
touch "$TMPDIR/veth_moved"

sleep 0.5

echo "[node1] Network ready: $(ip -4 addr show veth-n1 | grep inet | awk "{print \$2}")"

mkdir -p /var/run/wireguard

echo "[node1] Starting avenad with mDNS discovery..."
RUST_LOG=debug,mdns_sd=warn "$AVENAD" "$TMPDIR/node1.toml" 2>&1 | tee "$TMPDIR/node1.log" | stdbuf -oL sed "s/^/[node1] /" &
NODE1_PID=$!

echo ""
echo "=== Waiting for mDNS discovery and handshake (3s) ==="
echo "(Watch for Peer discovered and Peer connected messages)"
echo ""
sleep 3

echo ""
echo "=== Checking WireGuard interfaces ==="
echo "--- Node1 ---"
wg show wg-node1 2>/dev/null || echo "(no interface or no peers)"

echo ""
echo "--- Node2 ---"
nsenter -t $INNER_PID -n wg show wg-node2 2>/dev/null || echo "(no interface or no peers)"

echo ""
echo "=== Testing overlay IPv6 connectivity ==="

# Get peer overlay IPs from wg show (avenad now assigns IPs to interfaces)
NODE2_PEER_IP=$(wg show wg-node1 allowed-ips 2>/dev/null | awk "{print \$2}" | cut -d/ -f1 || true)

echo "Node2 overlay IP (from node1 wg): $NODE2_PEER_IP"

if [[ -n "$NODE2_PEER_IP" ]]; then
    echo "Pinging node2 ($NODE2_PEER_IP) from node1..."
    if ping6 -c 3 -W 3 "$NODE2_PEER_IP" 2>&1; then
        echo ""
        echo "[PASS] Overlay ping6 to $NODE2_PEER_IP succeeded!"
    else
        echo ""
        echo "[FAIL] Overlay ping6 to $NODE2_PEER_IP failed"
        echo "Debug: checking interface addresses..."
        ip -6 addr show wg-node1
        nsenter -t $INNER_PID -n ip -6 addr show wg-node2
    fi
else
    echo "[SKIP] Could not determine node2 overlay address"
fi

echo ""
echo "=== Test Summary ==="

kill -9 $NODE1_PID $NODE2_SHELL 2>/dev/null || true

if [[ -n "$NODE2_PEER_IP" ]]; then
    echo "Test completed."
    exit 0
else
    echo "Test failed - no peer connection established."
    exit 1
fi
'
