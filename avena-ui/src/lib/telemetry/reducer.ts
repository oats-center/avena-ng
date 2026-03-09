import type {
  AssertionResult,
  NeighborState,
  OverlayLinkState,
  PositionSample,
  RadioState,
  RouteState,
  ScenarioBridge,
  ScenarioInventory,
  ScenarioLink,
  ScenarioNode,
  StartupMetric,
  TelemetryEnvelope,
  TelemetryViewState
} from './types';

const SCENARIO_SUBJECT = /^avena\.v1\.([^.]+)\.scenario$/;
const OVERLAY_SUBJECT = /^avena\.v1\.([^.]+)\.node\.([^.]+)\.overlay\.([^.]+)$/;
const ROUTES_SUBJECT = /^avena\.v1\.([^.]+)\.node\.([^.]+)\.routing\.babel\.routes$/;
const NEIGHBORS_SUBJECT = /^avena\.v1\.([^.]+)\.node\.([^.]+)\.routing\.babel\.neighbors$/;
const ASSERTION_SUBJECT = /^avena\.v1\.([^.]+)\.testbed\.assertion_result$/;
const STARTUP_METRIC_SUBJECT = /^avena\.v1\.([^.]+)\.metrics\.startup$/;

export function createEmptyViewState(runId: string): TelemetryViewState {
  return {
    runId,
    nodes: {},
    radios: {},
    overlayLinks: {},
    routesByNode: {},
    neighborsByNode: {},
    assertions: [],
    startupMetrics: {}
  };
}

export function applyEnvelope(state: TelemetryViewState, envelope: TelemetryEnvelope): TelemetryViewState {
  if (!state.runId) {
    state.runId = envelope.run_id;
  }

  applyScenarioInventory(state, envelope);
  applyNs3Telemetry(state, envelope);
  applyOverlayTelemetry(state, envelope);
  applyRoutingTelemetry(state, envelope);
  applyAssertionTelemetry(state, envelope);
  applyStartupMetricTelemetry(state, envelope);

  return state;
}

function applyScenarioInventory(state: TelemetryViewState, envelope: TelemetryEnvelope): void {
  if (!SCENARIO_SUBJECT.test(envelope.subject)) {
    return;
  }

  const data = toObject(envelope.data);
  const nodes = toArray(data.nodes)
    .map((item): ScenarioNode | null => {
      const record = toObject(item);
      const id = asString(record.id);
      if (!id) {
        return null;
      }

      return {
        id,
        radioProfile: asString(record.radio_profile),
        radios: toArray(record.radios)
          .map((radio) => asString(radio))
          .filter((radio): radio is string => Boolean(radio))
      };
    })
    .filter((node): node is ScenarioNode => node !== null);

  const links = toArray(data.links)
    .map((item): ScenarioLink | null => {
      const record = toObject(item);
      const id = asString(record.id);
      if (!id) {
        return null;
      }
      return {
        id,
        endpoints: toArray(record.endpoints)
          .map((endpoint) => asString(endpoint))
          .filter((endpoint): endpoint is string => Boolean(endpoint)),
        medium: asString(record.medium)
      };
    })
    .filter((link): link is ScenarioLink => link !== null);

  const bridges = toArray(data.bridges)
    .map((item): ScenarioBridge | null => {
      const record = toObject(item);
      const id = asString(record.id);
      if (!id) {
        return null;
      }
      return {
        id,
        members: toArray(record.members)
          .map((member) => asString(member))
          .filter((member): member is string => Boolean(member)),
        medium: asString(record.medium)
      };
    })
    .filter((bridge): bridge is ScenarioBridge => bridge !== null);

  const scenario: ScenarioInventory = {
    name: asString(data.name) ?? 'scenario',
    durationSecs: asNumber(data.duration_secs) ?? 0,
    backend: asString(data.backend) ?? 'unknown',
    nodes,
    links,
    bridges
  };

  state.scenario = scenario;

  for (const node of nodes) {
    if (!state.nodes[node.id]) {
      state.nodes[node.id] = {
        id: node.id,
        trail: []
      };
    }

    for (const radio of node.radios) {
      const key = `${node.id}:${radio}`;
      if (!state.radios[key]) {
        state.radios[key] = {
          key,
          node: node.id,
          radio,
          status: 'declared',
          lastSeenMs: envelope.ts_ms
        };
      }
    }
  }
}

function applyNs3Telemetry(state: TelemetryViewState, envelope: TelemetryEnvelope): void {
  if (!envelope.subject.includes('.ns3.')) {
    return;
  }

  const data = toObject(envelope.data);
  const eventType = asString(data.type);
  if (!eventType) {
    return;
  }

  if (eventType === 'realtime') {
    state.realtimeLagMs = asNumber(data.lag_ms) ?? state.realtimeLagMs;
    state.lastRealtimeMs = envelope.ts_ms;
    return;
  }

  if (eventType === 'mobility') {
    const nodeId = envelope.node ?? asString(data.node);
    const x = asNumber(data.x_m);
    const y = asNumber(data.y_m);
    const z = asNumber(data.z_m) ?? 0;
    if (!nodeId || x === undefined || y === undefined) {
      return;
    }

    const sample: PositionSample = {
      tsMs: envelope.ts_ms,
      x_m: x,
      y_m: y,
      z_m: z
    };

    const track = state.nodes[nodeId] ?? { id: nodeId, trail: [] };
    track.latest = sample;
    track.trail = [...track.trail, sample].slice(-120);
    state.nodes[nodeId] = track;
    return;
  }

  if (eventType === 'l2') {
    const nodeId = envelope.node ?? asString(data.node);
    const radioId = envelope.radio ?? asString(data.radio);
    if (!nodeId || !radioId) {
      return;
    }

    const key = `${nodeId}:${radioId}`;
    const prior = state.radios[key];
    const status = asString(data.event) ?? 'l2_update';
    const next: RadioState = {
      key,
      node: nodeId,
      radio: radioId,
      band: asString(data.band) ?? prior?.band,
      channel: asNumber(data.channel) ?? prior?.channel,
      network: asString(data.network) ?? prior?.network,
      status,
      lastSeenMs: envelope.ts_ms
    };
    state.radios[key] = next;
  }
}

function applyOverlayTelemetry(state: TelemetryViewState, envelope: TelemetryEnvelope): void {
  const match = envelope.subject.match(OVERLAY_SUBJECT);
  if (!match) {
    return;
  }

  const [, , nodeId, eventName] = match;
  const data = toObject(envelope.data);
  const peerId = envelope.peer ?? asString(data.peer_id) ?? asString(data.peer);
  if (!peerId) {
    return;
  }

  const key = edgeKey(nodeId, peerId);
  const prior = state.overlayLinks[key];
  const link: OverlayLinkState = {
    key,
    node: prior?.node ?? (nodeId <= peerId ? nodeId : peerId),
    peer: prior?.peer ?? (nodeId <= peerId ? peerId : nodeId),
    status: eventName,
    lastSeenMs: envelope.ts_ms
  };
  state.overlayLinks[key] = link;
}

function applyRoutingTelemetry(state: TelemetryViewState, envelope: TelemetryEnvelope): void {
  let match = envelope.subject.match(ROUTES_SUBJECT);
  if (match) {
    const nodeId = match[2];
    const data = toObject(envelope.data);
    const routes = toArray(data.routes)
      .map((entry): RouteState | null => {
        const route = toObject(entry);
        const id = asString(route.id);
        const prefix = asString(route.prefix);
        const via = asString(route.via);
        const iface = asString(route.interface);
        const metric = asNumber(route.metric);
        const installed = asBoolean(route.installed);
        if (!id || !prefix || !via || !iface || metric === undefined) {
          return null;
        }

        return {
          node: nodeId,
          id,
          prefix,
          via,
          interface: iface,
          metric,
          installed: installed ?? false,
          tsMs: envelope.ts_ms
        };
      })
      .filter((route): route is RouteState => route !== null);

    state.routesByNode[nodeId] = routes;
    return;
  }

  match = envelope.subject.match(NEIGHBORS_SUBJECT);
  if (!match) {
    return;
  }

  const nodeId = match[2];
  const data = toObject(envelope.data);
  const source = toArray(data.neighbours).length > 0 ? toArray(data.neighbours) : toArray(data.neighbors);
  const neighbors = source
    .map((entry): NeighborState | null => {
      const neighbor = toObject(entry);
      const id = asString(neighbor.id);
      const address = asString(neighbor.address);
      const iface = asString(neighbor.interface);
      const rxCost = asNumber(neighbor.rxcost);
      const txCost = asNumber(neighbor.txcost);
      const reach = asString(neighbor.reach);
      if (!id || !address || !iface || rxCost === undefined || txCost === undefined) {
        return null;
      }

      return {
        node: nodeId,
        id,
        address,
        interface: iface,
        rxCost,
        txCost,
        reach: reach ?? '-',
        tsMs: envelope.ts_ms
      };
    })
    .filter((neighbor): neighbor is NeighborState => neighbor !== null);

  state.neighborsByNode[nodeId] = neighbors;
}

function applyAssertionTelemetry(state: TelemetryViewState, envelope: TelemetryEnvelope): void {
  if (!ASSERTION_SUBJECT.test(envelope.subject)) {
    return;
  }

  const data = toObject(envelope.data);
  const condition = asString(data.condition);
  const passed = asBoolean(data.passed);
  if (!condition || passed === undefined) {
    return;
  }

  const result: AssertionResult = {
    tsMs: envelope.ts_ms,
    condition,
    passed,
    atSecs: asNumber(data.at_secs)
  };
  state.assertions = [...state.assertions, result].slice(-200);
}

function applyStartupMetricTelemetry(state: TelemetryViewState, envelope: TelemetryEnvelope): void {
  if (!STARTUP_METRIC_SUBJECT.test(envelope.subject)) {
    return;
  }

  const data = toObject(envelope.data);
  const node = envelope.node ?? asString(data.node);
  const metric = asString(data.metric);
  const valueMs = asNumber(data.value_ms);
  const observedMs = asNumber(data.observed_ms);
  if (!node || !metric || valueMs === undefined || observedMs === undefined) {
    return;
  }

  const key = `${node}:${metric}`;
  const startupMetric: StartupMetric = {
    key,
    node,
    metric,
    valueMs,
    observedMs
  };

  state.startupMetrics[key] = startupMetric;
}

function edgeKey(a: string, b: string): string {
  return a <= b ? `${a}<->${b}` : `${b}<->${a}`;
}

function toObject(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    return {};
  }
  return value as Record<string, unknown>;
}

function toArray(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

function asString(value: unknown): string | undefined {
  return typeof value === 'string' ? value : undefined;
}

function asNumber(value: unknown): number | undefined {
  if (typeof value === 'number' && Number.isFinite(value)) {
    return value;
  }
  if (typeof value === 'string' && value.trim()) {
    const parsed = Number(value);
    if (Number.isFinite(parsed)) {
      return parsed;
    }
  }
  return undefined;
}

function asBoolean(value: unknown): boolean | undefined {
  return typeof value === 'boolean' ? value : undefined;
}
