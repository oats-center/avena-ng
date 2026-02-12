# Layer 1 Active Roadmap

## Scope

Finish and harden Avena Layer 1 behavior against the architecture described in `docs/`.

## Merged Inputs

This roadmap consolidates previously split planning content from:

- `archive/layer1-implementation-plan.md`
- `archive/layer1-remaining-work.md`
- `archive/avena-testbed-implementation-plan.md`
- `archive/babeld-integration.md`
- `tech-debt.md`

## Current Baseline (Already Landed)

- Userspace WireGuard startup/process lifecycle hardening.
- Startup readiness checks in testbed runner.
- Assertion timing and retry behavior hardening in testbed events.
- Babel controller integration and per-tunnel peer programming reconciliation.
- Babel is now hard-required at daemon startup (no optional disable path).
- Babel interface programming uses tunnel unicast mode.
- Scenario execution coverage for `two_node_basic`, `linear_three_hop`, `star_gateway`, and `mobile_relay`.
- Mobility convergence telemetry now logged:
  - underlay up -> first peer connected
  - underlay up -> first successful overlay ping
- M2 kickoff landed:
  - deterministic per-(peer, underlay-name) tunnel interface identity (`av-<hash8>`),
  - handshake payload now carries tunnel listen-port metadata,
  - peer state now tracks logical tunnel interface identity.
- M2 data-path landed:
  - peer traffic now programs true per-(peer, underlay) tunnel backends,
  - endpoint wiring now honors per-tunnel listen ports from handshake metadata,
  - peer teardown now removes per-tunnel WireGuard interfaces and flushes Babel interfaces.
- M3 landed:
  - peer AllowedIPs now uses universal `::/0` per Chapter 2,
  - tunnel mode selection is explicit (`kernel`, `userspace`, `prefer_kernel`),
  - strict local underlay interface resolution is used for tunnel identity input.

## Remaining High-Priority Gaps

1. **WireGuard allowed-ips final model (M3) - completed**
   - Decision locked: implement spec-aligned `AllowedIPs = ::/0` on peer interfaces.
   - Code now uses universal `::/0` allowed-ips for per-(peer, underlay) tunnels.
   - Chapter 2 now explicitly documents why `::/0` is required for routed multi-hop and failover behavior.

2. **Per-(peer, underlay) tunnel model validation (Step 4)**
   - Core implementation now uses true per-(peer, underlay) interfaces end-to-end.
   - Remaining work: add/expand dedicated dual-underlay scenario coverage to prove failover behavior and guard regressions.

3. **Babel tunnel/unicast control details**
   - Controller now programs `interface <name> type tunnel unicast true split-horizon true`.
   - Remaining work: validate behavior against multi-underlay and failover scenarios.

4. **Scenario determinism**
   - `mobile_relay` flakiness was reduced by retry/reannounce tuning and allowed-ips reconciliation on duplicate handshakes.
   - Remaining work: tighten assertion-window policy so failures are based on scenario deadlines, not fixed probe budgets.

5. **Documentation synchronization**
   - Keep `docs/chapters/08-status.tex` aligned with implemented behavior at each milestone.

## Execution Status (Current Iteration)

- [x] Step 1: M3 `::/0` AllowedIPs implementation + Chapter 2 rationale update.
- [x] Step 2: Introduce explicit tunnel mode tri-state (`kernel`, `userspace`, `prefer_kernel`).
- [x] Step 3: Switch tunnel identity input to strict stable underlay identifier (no IP-hint fallback).
- [ ] Step 4: Add dual-underlay/failover + churn scenarios and gates.
- [ ] Step 5: Synchronize `docs/chapters/08-status.tex` and close roadmap deltas.

Step 5 progress so far:
- `docs/chapters/08-status.tex` updated for M2/M3/tri-state/strict-underlay behavior.
- Final Step 5 closeout will happen after Step 4 scenario evidence is added.

## Step 4 Detailed Test Plan (Per Test)

### Test 4.1: Scenario schema supports multiple parallel links between same node pair

Goal:
- Enable dual-underlay modeling for the same peer pair without link-id collisions.

TDD plan:
- Add optional explicit link ID field in scenario `[[links]]`.
- Add parser/validation unit tests for duplicate endpoint pairs with distinct IDs.
- Add link manager/topology tests to ensure event references target explicit IDs.

Acceptance:
- Two links between the same endpoints can be created, referenced, connected, and disconnected independently.

### Test 4.2: Dual-underlay same-peer baseline scenario

Goal:
- Prove two simultaneous underlay links to the same peer can be established.

TDD plan:
- Add new scenario (e.g. `dual_underlay_same_peer.toml`) with two links between nodes A and B.
- Add assertions that connectivity is up and remains stable once both links are active.
- Add log/metric checks for two distinct tunnel interface activations for the same peer.

Acceptance:
- Scenario passes and demonstrates two distinct per-underlay tunnel interfaces for the same peer identity.

### Test 4.3: Dual-underlay failover scenario

Goal:
- Verify traffic survives loss of one underlay path when an alternate path to same peer remains.

TDD plan:
- Extend dual-underlay scenario with timeline events:
  - disconnect link A, assert ping continuity,
  - reconnect link A, disconnect link B, assert ping continuity.
- Add assertion timing windows to avoid brittle probe-budget failures.

Acceptance:
- Both single-link failure phases retain end-to-end ping connectivity.

### Test 4.4: Churn and lifecycle cleanup scenario

Goal:
- Validate repeated link churn does not leak tunnel interfaces/process resources and reconverges each time.

TDD plan:
- Add scenario with repeated connect/disconnect cycles on dual links.
- Add assertions for post-churn connectivity.
- Add debug snapshots (interfaces/routes/wg state) on failure for diagnosis.

Acceptance:
- Scenario passes across repeated cycles with stable connectivity and no persistent stale tunnel state after cleanup.

## Validation Gates

- `cargo test -p avena-overlay -p avena-testbed`
- `avena-testbed/scenarios/two_node_basic.toml`
- `avena-testbed/scenarios/linear_three_hop.toml`
- `avena-testbed/scenarios/star_gateway.toml`
- `avena-testbed/scenarios/mobile_relay.toml`

## Ownership of Truth

- Architecture/design intent: `docs/`
- Implementation/debt tracking: `plans/tech-debt.md`
- Execution roadmap: this file
