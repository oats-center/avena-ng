# Avena Technical Debt Tracker

Items deferred to keep v1 implementations simple. Address before production.

---

## TD-001: WireGuard allowed_ips Security

**Status:** Deferred
**Added:** 2024-12-11
**Component:** avena-overlay / routing

**Current State:**
When Babel is enabled, allowed_ips uses a heuristic:
- Leaf nodes (exactly one peer) use `::/0` to permit multi-hop egress.
- Multi-peer nodes constrain peers to their overlay `/128` to avoid WireGuard peer-selection ambiguity.
- Each peer also gets the peer’s link-local `/128` so Babel control traffic can be delivered over WireGuard.
Kernel routes to direct peers are still installed explicitly because netlink WG config does not add routes for allowed_ips.

**Risk:**
Any authenticated peer can route traffic to any overlay destination. A compromised node could intercept traffic destined for other nodes.

**Proper Solution:**
Mirror babel routes to WireGuard allowed_ips. When babel learns a route `fd00::X/128 via fe80::Y`, update the WireGuard peer with that link-local address to include `fd00::X/128` in its allowed_ips.

**Complexity:** Medium - requires:
- Monitoring babel route changes via `monitor` command
- Mapping next-hop link-local addresses to WireGuard peer pubkeys
- Dynamically updating WireGuard peer configs

**References:**
- `plans/babeld-integration.md` Task 6

---

## TD-002: Certificate Exchange Timing

**Status:** Deferred
**Added:** 2024-12-11
**Component:** crypto / handshake

**Current State:**
Certificates are exchanged during handshake but this was added to existing protocol. Design doc specifies full chain validation should gate tunnel establishment.

**Risk:**
Protocol versioning may be needed. Current implementation works but may not match design doc precisely.

**Proper Solution:**
Review handshake protocol against design doc Section 5.3 (Tunnel Establishment). Ensure certificate chain validation happens at correct phase.

**References:**
- `plans/layer1-remaining-work.md` Task 2
- `docs/design.tex` lines 356-461

---

## TD-003: Babel Parameter Tuning

**Status:** Open Question
**Added:** 2024-12-11
**Component:** routing / babeld

**Current State:**
Using default babel hello/update intervals (4s/16s). These are reasonable for general mesh networks.

**Risk:**
Suboptimal convergence time for specific use cases:
- Agricultural: slow-moving vehicles, can tolerate longer intervals
- V2X: fast-moving vehicles, may need shorter intervals

**Proper Solution:**
Profile convergence time under realistic mobility patterns. Consider:
- Making intervals configurable per deployment
- Different profiles (agricultural vs V2X)

**References:**
- `docs/design.tex` OQ-1, OQ-2 (lines 1604-1605)

---

## TD-004: Babeld Process Supervision

**Status:** Needs Implementation
**Added:** 2024-12-11
**Component:** routing / babeld

**Current State:**
Plan says avena-overlay should restart babeld if it crashes. Not yet implemented.

**Risk:**
If babeld dies, routing stops working but avena-overlay continues running. Silent failure.

**Proper Solution:**
- Monitor babeld process in event loop
- Restart with exponential backoff on crash
- Log prominently when babeld is unhealthy

---

## TD-005: Babel Control Plane Over WireGuard

**Status:** Needs Validation / Hardening
**Added:** 2025-12-12
**Component:** routing / babeld / WireGuard

**Current State:**
Babeld defaults to link-local multicast (`ff02::1:6`) for hellos/updates, but WireGuard does not forward multicast. To bridge this, avena-overlay now:
- assigns deterministic link-local addresses on WG interfaces,
- includes each peer’s link-local `/128` in allowed_ips, and
- runs a small UDP/6696 multicast relay that forwards local multicast Babel packets to peers’ link-local addresses.
This is unverified in a stable environment and was flaky in the nested-unshare testbed container.

**Risk:**
- Multi-hop routing fails if relay or link-local policy breaks.
- Relay may interfere with unicast Babel traffic on some kernels (bind/REUSE semantics).
- Potential for duplicated control traffic or feedback loops if forwarding rules are wrong.

**Proper Solution:**
Decide and implement the final control-plane strategy:
- Preferred: implement TD-001 “mirror Babel routes into allowed_ips”, then remove the `::/0` heuristic and multicast relay entirely.
- Alternative: configure babeld interfaces as `type tunnel` with `unicast true` via config/`-C` statements so updates are sent unicast; still requires a neighbour-discovery strategy for Hellos (multicast relay or a babeld patch for explicit neighbours).
Validate multi-hop on real namespaces, then delete interim relay/heuristics if not needed.

**References:**
- `plans/babeld-integration.md`
- `docs/design.tex` multi-hop routing sections

---

## TD-006: allowed_ips Heuristic Race Under Concurrent Handshakes

**Status:** Needs Validation
**Added:** 2025-12-12
**Component:** avena-overlay / WireGuard policy

**Current State:**
When Babel is enabled, allowed_ips decisions depend on the current peer count. Two concurrent handshakes can briefly observe an empty peer set and both assign `::/0`, reintroducing overlap ambiguity. A best-effort reconciliation pass now runs after each peer insert.

**Risk:**
Transient `::/0` overlap can cause WireGuard to select the wrong peer for direct traffic, breaking single-hop reachability and delaying convergence.

**Proper Solution:**
Centralize allowed_ips policy updates under a single serialized path:
- lock peers + WG updates together when adding/removing peers,
- compute the full allowed_ips set for all peers from one snapshot,
- apply updates atomically (or in deterministic order).
Add a test that forces overlapping handshakes and asserts no simultaneous `::/0` assignment.

**References:**
- `avena-overlay/src/bin/avena_overlay.rs`

---

## TD-007: Testbed Namespace / nsenter Flakiness

**Status:** Open Question
**Added:** 2025-12-12
**Component:** avena-testbed

**Current State:**
`linear_three_hop.toml` is flaky in constrained environments: the testbed sometimes fails to `nsenter` a child netns (`/proc/<pid>/ns/net` missing). This makes direct-peer and multi-hop assertions unreliable in CI-like sandboxes.

**Risk:**
False negatives in tests and very hard-to-debug routing regressions.

**Proper Solution:**
Improve robustness of the testbed:
- switch fixed-time waits to condition-based readiness checks,
- ensure child namespace processes stay alive for the full scenario (pidfds or explicit supervision),
- add retry/backoff around `nsenter` when safe.

**References:**
- `avena-testbed/scenarios/linear_three_hop.toml`
- `plans/babeld-integration.md`

---

## TD-008: Multi-Underlay WireGuard Interfaces (Per Identity)

**Status:** Needs Implementation
**Added:** 2025-12-12
**Component:** avena-overlay / overlay / routing

**Current State:**
v1 uses a single WireGuard device per identity and attaches all peers to it. This collapses multiple physical underlay links into one logical interface, so Babel cannot represent "the same peer via WiFi" vs "the same peer via cellular" as distinct links with distinct metrics.

**Risk:**
- IP layer cannot choose among multiple physical links to the same peer.
- Link-cost inputs (latency/loss/bandwidth/$/bit/energy) cannot be applied per underlay interface.
- Multi-hop debugging gets harder because "peer connectivity" and "link quality" are conflated.

**Proper Solution:**
Implement "one WireGuard interface per physical underlay interface per identity":
- Extend config to declare underlay interfaces, each with a WireGuard device name and listen ports.
- Bind discovery results to the underlay interface they arrived on.
- On handshake completion, program the peer into the correct per-underlay WireGuard device.
- Allow the same peer overlay `/128` to exist on multiple WireGuard devices (parallel links), and let Babel/kernel metrics select the active route.
- Extend diagnostics (avenactl) to report per-underlay link state and telemetry.
- Add/extend testbed scenarios to exercise dual-link-to-same-peer behavior.

**References:**
- `../docs/design.tex`
- `plans/babeld-integration.md`

---

## TD-009: Feed Physical Telemetry Into Babel Link Metrics

**Status:** Needs Implementation
**Added:** 2025-12-12
**Component:** routing / metrics / gossip

**Current State:**
Physical telemetry (latency, loss, bandwidth, monetary cost, energy cost, peer energy state) is propagated at higher layers, but Babel interface costs are not dynamically derived from it. With multiple underlays available, route selection can drift from operator intent.

**Risk:**
- Babel may choose the wrong underlay when multiple links exist.
- Messaging-layer cost-aware routing cannot depend on the IP layer to pick the best physical link to a chosen next-hop.

**Proper Solution:**
- Define a stable mapping from physical telemetry -> Babel interface cost (and any per-neighbor penalties).
- Update Babel costs dynamically with rate limiting and hysteresis (FRR via `vtysh` or a control socket).
- Validate with a testbed scenario that presents two parallel underlays with different costs and asserts route selection flips when costs cross.

**References:**
- `../docs/design.tex`

---

## Template for New Items

```markdown
## TD-XXX: Title

**Status:** Deferred | Open Question | Needs Implementation
**Added:** YYYY-MM-DD
**Component:** module name

**Current State:**
What we're doing now.

**Risk:**
What could go wrong.

**Proper Solution:**
What we should do eventually.

**References:**
- Related files/docs
```
