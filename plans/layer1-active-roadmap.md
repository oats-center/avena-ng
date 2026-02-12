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
- Babel controller integration and adaptive peer allowed-ips reconciliation.
- Babel is now hard-required at daemon startup (no optional disable path).
- Babel interface programming uses tunnel unicast mode.
- Scenario execution coverage for `two_node_basic`, `linear_three_hop`, `star_gateway`, and `mobile_relay`.
- Mobility convergence telemetry now logged:
  - underlay up -> first peer connected
  - underlay up -> first successful overlay ping

## Remaining High-Priority Gaps

1. **WireGuard allowed-ips final model**
   - Current implementation uses adaptive `/128` plus optional overlay prefix behavior.
   - Finalize policy by either:
     - implementing route-mirroring into allowed-ips, or
     - revising design text to the selected production strategy.

2. **Per-(peer, underlay) tunnel model**
   - Current implementation remains effectively single-interface-per-node for most paths.
   - Implement true per-(peer, underlay) interfaces and route selection semantics.

3. **Babel tunnel/unicast control details**
   - Controller now programs `interface <name> type tunnel unicast true split-horizon true`.
   - Remaining work: validate behavior against multi-underlay and failover scenarios.

4. **Scenario determinism**
   - `mobile_relay` flakiness was reduced by retry/reannounce tuning and allowed-ips reconciliation on duplicate handshakes.
   - Remaining work: tighten assertion-window policy so failures are based on scenario deadlines, not fixed probe budgets.

5. **Documentation synchronization**
   - Keep `docs/chapters/08-status.tex` aligned with implemented behavior at each milestone.

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
