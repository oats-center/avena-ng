# Avena Testbed Implementation Plan

## Overview

A standalone test harness (`avena-testbed`) for simulating multi-node Avena overlay networks with configurable topologies, link conditions, and event timelines. Enables repeatable scenario-based testing for CI and development.

## Design Decisions (from brainstorming)

| Decision | Choice |
|----------|--------|
| Fidelity | Fast mode (namespaces + tc/netem), ns-3 interface deferred |
| Config format | TOML scenario files |
| Topologies | Linear, star, mobile relay, full mesh |
| Integration | Standalone `avena-testbed` CLI binary |
| Link model | Simple params: latency_ms, bandwidth_kbps, loss_percent |
| Metrics | Structured jsonl event logs |
| PKI | Auto-generate ephemeral CA + device certs |
| Timeline | Declarative events |
| CI | Self-hosted runner with root/cap_net_admin |

---

## Crate Structure

```
avena-paper/
├── avena-overlay/         # Existing crate (dependency)
│   └── ...
└── avena-testbed/         # New separate crate
    ├── Cargo.toml
    ├── src/
    │   ├── lib.rs
    │   ├── scenario.rs    # TOML config parsing
    │   ├── topology.rs    # Network namespace management
    │   ├── links.rs       # tc/netem link shaping
    │   ├── events.rs      # Timeline event execution
    │   ├── metrics.rs     # jsonl structured logging
    │   ├── pki.rs         # Ephemeral cert generation
    │   └── runner.rs      # Orchestration logic
    ├── src/bin/
    │   └── avena-testbed.rs   # CLI entry point
    └── scenarios/         # Example scenario files
        ├── two_node_basic.toml
        ├── linear_three_hop.toml
        ├── star_gateway.toml
        └── mobile_relay.toml
```

---

## Phase 1: Scenario Configuration Schema

### 1.1 `testbed/scenario.rs`

```rust
#[derive(Deserialize)]
pub struct Scenario {
    pub name: String,
    pub description: Option<String>,
    pub duration_secs: u64,
    pub nodes: Vec<NodeConfig>,
    pub links: Vec<LinkConfig>,
    pub events: Vec<Event>,
    pub assertions: Vec<Assertion>,
}

#[derive(Deserialize)]
pub struct NodeConfig {
    pub id: String,                    // e.g., "gateway", "tractor-1", "sensor-a"
    pub capabilities: Vec<String>,     // relay, gateway, workload_spawn
    pub start_delay_secs: Option<f64>, // When node comes online
}

#[derive(Deserialize)]
pub struct LinkConfig {
    pub endpoints: (String, String),   // Node IDs
    pub latency_ms: u32,
    pub bandwidth_kbps: u32,
    pub loss_percent: f32,
    pub enabled: bool,                 // Initial state
}

#[derive(Deserialize)]
pub struct Event {
    pub at_secs: f64,
    pub action: EventAction,
}

#[derive(Deserialize)]
#[serde(tag = "type")]
pub enum EventAction {
    DisconnectLink { link: String },     // "A-B" format
    ConnectLink { link: String },
    ModifyLink { link: String, latency_ms: Option<u32>, loss_percent: Option<f32> },
    StopNode { node: String },
    StartNode { node: String },
}

#[derive(Deserialize)]
pub struct Assertion {
    pub at_secs: f64,
    pub condition: AssertCondition,
}

#[derive(Deserialize)]
#[serde(tag = "type")]
pub enum AssertCondition {
    NodesConnected { nodes: Vec<String> },
    Ping { from: String, to: String, timeout_ms: u32 },
    PeerCount { node: String, count: usize },
}
```

### 1.2 Example Scenario: `mobile_relay.toml`

```toml
name = "mobile-relay-store-forward"
description = "Tests DTN store-and-forward via mobile relay"
duration_secs = 60

[[nodes]]
id = "gateway"
capabilities = ["relay", "gateway"]

[[nodes]]
id = "sensor"
capabilities = []

[[nodes]]
id = "tractor"
capabilities = ["relay"]
start_delay_secs = 5.0

[[links]]
endpoints = ["gateway", "tractor"]
latency_ms = 10
bandwidth_kbps = 100000
loss_percent = 0.0
enabled = false  # Tractor starts disconnected from gateway

[[links]]
endpoints = ["tractor", "sensor"]
latency_ms = 5
bandwidth_kbps = 50000
loss_percent = 0.0
enabled = false  # Tractor starts away from sensor

[[events]]
at_secs = 10.0
action = { type = "ConnectLink", link = "tractor-sensor" }

[[events]]
at_secs = 20.0
action = { type = "DisconnectLink", link = "tractor-sensor" }

[[events]]
at_secs = 30.0
action = { type = "ConnectLink", link = "gateway-tractor" }

[[assertions]]
at_secs = 15.0
condition = { type = "NodesConnected", nodes = ["tractor", "sensor"] }

[[assertions]]
at_secs = 40.0
condition = { type = "Ping", from = "gateway", to = "sensor", timeout_ms = 5000 }
```

---

## Phase 2: Network Namespace Management

### 2.1 `testbed/topology.rs`

```rust
pub struct TestTopology {
    nodes: HashMap<String, NodeInstance>,
    veth_pairs: Vec<VethPair>,
}

pub struct NodeInstance {
    pub id: String,
    pub netns: String,              // Network namespace name
    pub avenad_process: Option<Child>,
    pub overlay_ip: Ipv6Addr,
    pub config_path: PathBuf,
}

pub struct VethPair {
    pub link_id: String,
    pub veth_a: String,
    pub veth_b: String,
    pub node_a: String,
    pub node_b: String,
}

impl TestTopology {
    pub fn new() -> Self;

    /// Create network namespaces and veth pairs
    pub async fn setup(&mut self, scenario: &Scenario) -> Result<(), TestError>;

    /// Start avenad in each namespace
    pub async fn start_nodes(&mut self, pki: &TestPki) -> Result<(), TestError>;

    /// Clean up namespaces and processes
    pub async fn teardown(&mut self) -> Result<(), TestError>;

    /// Execute command in node's namespace
    pub async fn exec_in_node(&self, node: &str, cmd: &[&str]) -> Result<Output, TestError>;
}
```

### 2.2 Namespace Setup Flow

```bash
# For each node:
ip netns add avena-test-{node_id}
ip link add veth-{node_a}-{node_b}-a type veth peer name veth-{node_a}-{node_b}-b
ip link set veth-{node_a}-{node_b}-a netns avena-test-{node_a}
ip link set veth-{node_a}-{node_b}-b netns avena-test-{node_b}

# Inside each namespace:
ip netns exec avena-test-{node_id} ip link set lo up
ip netns exec avena-test-{node_id} ip addr add 10.{subnet}.{node}.1/24 dev veth-...
ip netns exec avena-test-{node_id} ip link set veth-... up
```

---

## Phase 3: Link Shaping

### 3.1 `testbed/links.rs`

```rust
pub struct LinkManager {
    links: HashMap<String, LinkState>,
}

pub struct LinkState {
    pub config: LinkConfig,
    pub veth_a: String,
    pub veth_b: String,
    pub netns_a: String,
    pub netns_b: String,
    pub enabled: bool,
}

impl LinkManager {
    /// Apply tc/netem rules to a link
    pub async fn configure_link(&self, link_id: &str, config: &LinkConfig) -> Result<(), TestError>;

    /// Enable/disable link (bring veth up/down)
    pub async fn set_link_enabled(&mut self, link_id: &str, enabled: bool) -> Result<(), TestError>;

    /// Modify link parameters at runtime
    pub async fn modify_link(&self, link_id: &str,
                             latency_ms: Option<u32>,
                             loss_percent: Option<f32>) -> Result<(), TestError>;
}
```

### 3.2 tc/netem Commands

```bash
# Apply latency and loss
ip netns exec {netns} tc qdisc add dev {veth} root netem \
    delay {latency_ms}ms \
    loss {loss_percent}%

# Bandwidth limiting (tbf)
ip netns exec {netns} tc qdisc add dev {veth} parent 1:1 handle 10: tbf \
    rate {bandwidth_kbps}kbit \
    burst 32kbit \
    latency 400ms

# Disable link (bring down)
ip netns exec {netns} ip link set {veth} down
```

---

## Phase 4: Event Timeline Execution

### 4.1 `testbed/events.rs`

```rust
pub struct EventExecutor {
    topology: Arc<Mutex<TestTopology>>,
    links: Arc<Mutex<LinkManager>>,
    metrics: Arc<MetricsLogger>,
}

impl EventExecutor {
    pub async fn run_timeline(&self, events: &[Event], assertions: &[Assertion]) -> Result<TestResult, TestError> {
        let start = Instant::now();
        let mut event_iter = events.iter().peekable();
        let mut assert_iter = assertions.iter().peekable();

        loop {
            let elapsed = start.elapsed().as_secs_f64();

            // Execute due events
            while event_iter.peek().map(|e| e.at_secs <= elapsed).unwrap_or(false) {
                let event = event_iter.next().unwrap();
                self.execute_event(event).await?;
            }

            // Check due assertions
            while assert_iter.peek().map(|a| a.at_secs <= elapsed).unwrap_or(false) {
                let assertion = assert_iter.next().unwrap();
                self.check_assertion(assertion).await?;
            }

            if event_iter.peek().is_none() && assert_iter.peek().is_none() {
                break;
            }

            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        Ok(TestResult { passed: true, .. })
    }

    async fn execute_event(&self, event: &Event) -> Result<(), TestError>;
    async fn check_assertion(&self, assertion: &Assertion) -> Result<(), TestError>;
}
```

---

## Phase 5: Metrics & Logging

### 5.1 `testbed/metrics.rs`

```rust
pub struct MetricsLogger {
    output: Mutex<BufWriter<File>>,
}

#[derive(Serialize)]
pub struct MetricEvent {
    pub timestamp_ms: u64,
    pub event_type: String,
    pub node: Option<String>,
    pub data: serde_json::Value,
}

impl MetricsLogger {
    pub fn new(output_path: &Path) -> Result<Self, io::Error>;

    pub fn log(&self, event: MetricEvent) -> Result<(), io::Error>;

    // Predefined event types
    pub fn log_node_started(&self, node: &str, overlay_ip: &Ipv6Addr);
    pub fn log_peer_discovered(&self, node: &str, peer: &str);
    pub fn log_peer_connected(&self, node: &str, peer: &str, handshake_ms: u64);
    pub fn log_link_changed(&self, link: &str, enabled: bool);
    pub fn log_assertion_result(&self, assertion: &str, passed: bool);
}
```

### 5.2 Example jsonl Output

```json
{"timestamp_ms":0,"event_type":"scenario_started","data":{"name":"mobile-relay"}}
{"timestamp_ms":100,"event_type":"node_started","node":"gateway","data":{"overlay_ip":"fd00:a0e0:a000::1"}}
{"timestamp_ms":5100,"event_type":"node_started","node":"tractor","data":{"overlay_ip":"fd00:a0e0:a000::2"}}
{"timestamp_ms":10000,"event_type":"link_changed","data":{"link":"tractor-sensor","enabled":true}}
{"timestamp_ms":10250,"event_type":"peer_discovered","node":"tractor","data":{"peer":"sensor"}}
{"timestamp_ms":10450,"event_type":"peer_connected","node":"tractor","data":{"peer":"sensor","handshake_ms":200}}
{"timestamp_ms":15000,"event_type":"assertion_result","data":{"condition":"NodesConnected","passed":true}}
```

---

## Phase 6: PKI Generation

### 6.1 `testbed/pki.rs`

```rust
pub struct TestPki {
    pub ca_key: DeviceKeypair,
    pub root_cert: Certificate,
    pub node_certs: HashMap<String, (DeviceKeypair, Certificate)>,
    pub temp_dir: TempDir,
}

impl TestPki {
    /// Generate ephemeral CA and node certificates
    pub fn generate(nodes: &[NodeConfig]) -> Result<Self, PkiError> {
        let temp_dir = TempDir::new("avena-testbed")?;
        let ca_key = DeviceKeypair::generate();
        let root_cert = Certificate::self_signed(&ca_key, Duration::from_secs(3600))?;

        let mut node_certs = HashMap::new();
        for node in nodes {
            let node_key = DeviceKeypair::generate();
            let node_cert = Certificate::issue(&ca_key, &root_cert, &node_key,
                                                &node.capabilities)?;
            node_certs.insert(node.id.clone(), (node_key, node_cert));
        }

        Ok(Self { ca_key, root_cert, node_certs, temp_dir })
    }

    /// Write cert files for a node
    pub fn write_node_files(&self, node: &str) -> Result<NodePaths, io::Error>;
}

pub struct NodePaths {
    pub key_path: PathBuf,
    pub cert_path: PathBuf,
    pub root_cert_path: PathBuf,
}
```

---

## Phase 7: CLI Binary

### 7.1 `bin/avena-testbed.rs`

```rust
use clap::Parser;

#[derive(Parser)]
#[command(name = "avena-testbed")]
#[command(about = "Avena overlay network test harness")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run a test scenario
    Run {
        /// Path to scenario TOML file
        scenario: PathBuf,

        /// Output path for metrics jsonl
        #[arg(short, long, default_value = "metrics.jsonl")]
        output: PathBuf,

        /// Keep namespaces after test (for debugging)
        #[arg(long)]
        keep_namespaces: bool,
    },

    /// Validate scenario file syntax
    Validate {
        scenario: PathBuf,
    },

    /// List available example scenarios
    Examples,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Run { scenario, output, keep_namespaces } => {
            let runner = TestRunner::new()?;
            runner.run_scenario(&scenario, &output, keep_namespaces).await?;
        }
        Commands::Validate { scenario } => {
            Scenario::load(&scenario)?;
            println!("✓ Scenario is valid");
        }
        Commands::Examples => {
            // List bundled example scenarios
        }
    }

    Ok(())
}
```

---

## Phase 8: avenad Metrics Enhancement

To support metrics collection, avenad needs structured log output:

### 8.1 Add Structured Events

```rust
// In avenad.rs, emit structured events alongside tracing logs

#[derive(Serialize)]
#[serde(tag = "event")]
pub enum AvenadEvent {
    PeerDiscovered { peer_id: String, endpoint: String, source: String },
    HandshakeStarted { peer_id: String },
    HandshakeCompleted { peer_id: String, duration_ms: u64 },
    HandshakeFailed { peer_id: String, error: String },
    PeerConnected { peer_id: String, overlay_ip: String },
    PeerDisconnected { peer_id: String, reason: String },
}

impl Avenad {
    fn emit_event(&self, event: AvenadEvent) {
        if let Ok(json) = serde_json::to_string(&event) {
            println!("AVENA_EVENT:{}", json);
        }
    }
}
```

### 8.2 Testbed Captures Events

The testbed runner captures stdout from avenad processes and parses `AVENA_EVENT:` lines into the metrics log.

---

## Implementation Order

### Milestone 1: Core Infrastructure
1. `testbed/scenario.rs` - TOML parsing and validation
2. `testbed/pki.rs` - Certificate generation (reuse avena-keygen logic)
3. Basic `bin/avena-testbed.rs` with `validate` command
4. Add example scenario files

### Milestone 2: Topology Management
1. `testbed/topology.rs` - Namespace creation/teardown
2. Veth pair setup between nodes
3. Generate avenad config files per node
4. Start/stop avenad processes in namespaces

### Milestone 3: Link Shaping
1. `testbed/links.rs` - tc/netem wrapper
2. Link enable/disable via veth up/down
3. Runtime link modification

### Milestone 4: Event Timeline
1. `testbed/events.rs` - Event loop executor
2. Assertion checking logic
3. `testbed/runner.rs` - Full orchestration

### Milestone 5: Metrics
1. `testbed/metrics.rs` - jsonl logger
2. Stdout parsing for AVENA_EVENT lines
3. Timing measurements

### Milestone 6: Integration
1. `run` command implementation
2. Example scenarios for each topology type
3. CI integration (self-hosted runner script)

---

## Future Work (Deferred)

### ns-3 Integration Interface

```rust
pub trait NetworkBackend: Send + Sync {
    async fn setup_topology(&mut self, scenario: &Scenario) -> Result<(), Error>;
    async fn set_link_enabled(&mut self, link: &str, enabled: bool) -> Result<(), Error>;
    async fn modify_link(&mut self, link: &str, params: LinkParams) -> Result<(), Error>;
    async fn teardown(&mut self) -> Result<(), Error>;
}

pub struct NamespaceBackend { /* current implementation */ }
pub struct Ns3Backend { /* future: ns-3 integration */ }
```

### Metrics to Add (from design.tex RQs)

- **RQ1**: Workload convergence time across scenarios
- **RQ2**: CRDT conflict rates during partitions
- **RQ3**: Link formation/teardown timing, topology scalability
- **RQ4**: Bandwidth reduction from geo-filtering

---

## Files to Create/Modify

| File | Action |
|------|--------|
| `avena-testbed/Cargo.toml` | Create - new crate with avena-overlay dependency |
| `avena-testbed/src/lib.rs` | Create |
| `avena-testbed/src/scenario.rs` | Create |
| `avena-testbed/src/topology.rs` | Create |
| `avena-testbed/src/links.rs` | Create |
| `avena-testbed/src/events.rs` | Create |
| `avena-testbed/src/metrics.rs` | Create |
| `avena-testbed/src/pki.rs` | Create |
| `avena-testbed/src/runner.rs` | Create |
| `avena-testbed/src/bin/avena-testbed.rs` | Create |
| `avena-testbed/scenarios/*.toml` | Create - example scenarios |
| `avena-overlay/src/bin/avenad.rs` | Modify - add AVENA_EVENT output |

## Dependencies (avena-testbed/Cargo.toml)

```toml
[package]
name = "avena-testbed"
version = "0.1.0"
edition = "2021"

[[bin]]
name = "avena-testbed"
path = "src/bin/avena-testbed.rs"

[dependencies]
avena-overlay = { path = "../avena-overlay" }
clap = { version = "4", features = ["derive"] }
tempfile = "3"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
toml = "0.8"
tokio = { version = "1", features = ["full", "process"] }
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter"] }
thiserror = "2"
```

## CI Script (self-hosted runner)

```bash
#!/bin/bash
# avena-testbed/ci/run-testbed.sh
set -euo pipefail

cargo build -p avena-testbed -p avena-overlay --bins

for scenario in avena-testbed/scenarios/*.toml; do
    echo "Running: $scenario"
    ./target/debug/avena-testbed run "$scenario" \
        --output "results/$(basename "$scenario" .toml).jsonl"
done

echo "All scenarios passed"
```
