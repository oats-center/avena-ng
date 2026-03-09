export interface TelemetryEnvelope {
  v: number;
  subject: string;
  ts_ms: number;
  run_id: string;
  source: string;
  node?: string;
  radio?: string;
  peer?: string;
  data: Record<string, unknown>;
}

export interface ScenarioInventory {
  name: string;
  durationSecs: number;
  backend: string;
  nodes: ScenarioNode[];
  links: ScenarioLink[];
  bridges: ScenarioBridge[];
}

export interface ScenarioNode {
  id: string;
  radioProfile?: string;
  radios: string[];
}

export interface ScenarioLink {
  id: string;
  endpoints: string[];
  medium?: string;
}

export interface ScenarioBridge {
  id: string;
  members: string[];
  medium?: string;
}

export interface PositionSample {
  tsMs: number;
  x_m: number;
  y_m: number;
  z_m: number;
}

export interface NodeTrack {
  id: string;
  latest?: PositionSample;
  trail: PositionSample[];
}

export interface RadioState {
  key: string;
  node: string;
  radio: string;
  band?: string;
  channel?: number;
  network?: string;
  status: string;
  lastSeenMs: number;
}

export interface OverlayLinkState {
  key: string;
  node: string;
  peer: string;
  status: string;
  lastSeenMs: number;
}

export interface RouteState {
  node: string;
  id: string;
  prefix: string;
  via: string;
  interface: string;
  metric: number;
  installed: boolean;
  tsMs: number;
}

export interface NeighborState {
  node: string;
  id: string;
  address: string;
  interface: string;
  rxCost: number;
  txCost: number;
  reach: string;
  tsMs: number;
}

export interface AssertionResult {
  tsMs: number;
  condition: string;
  passed: boolean;
  atSecs?: number;
}

export interface StartupMetric {
  key: string;
  node: string;
  metric: string;
  valueMs: number;
  observedMs: number;
}

export interface TelemetryViewState {
  runId: string;
  scenario?: ScenarioInventory;
  realtimeLagMs?: number;
  lastRealtimeMs?: number;
  nodes: Record<string, NodeTrack>;
  radios: Record<string, RadioState>;
  overlayLinks: Record<string, OverlayLinkState>;
  routesByNode: Record<string, RouteState[]>;
  neighborsByNode: Record<string, NeighborState[]>;
  assertions: AssertionResult[];
  startupMetrics: Record<string, StartupMetric>;
}
