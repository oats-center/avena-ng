<script lang="ts">
  import { onDestroy } from 'svelte';
  import { buildDemoReplay } from '$lib/telemetry/demo';
  import { connectTelemetry, jetstreamStreamName, type TelemetryConnection } from '$lib/telemetry/nats';
  import { applyEnvelope, createEmptyViewState } from '$lib/telemetry/reducer';
  import type {
    NeighborState,
    OverlayLinkState,
    RouteState,
    TelemetryEnvelope,
    TelemetryViewState
  } from '$lib/telemetry/types';

  type Mode = 'live' | 'replay';

  let runId = defaultRunId();
  let serverUrl = 'ws://127.0.0.1:9222';
  let streamNameOverride = '';
  let mode: Mode = 'live';
  let replayMs = 0;

  let status = 'idle';
  let statusDetail = 'Disconnected';
  let errorMessage = '';

  let connection: TelemetryConnection | null = null;
  let events: TelemetryEnvelope[] = [];
  let liveView: TelemetryViewState = createEmptyViewState(runId);
  let currentView: TelemetryViewState = liveView;

  let maxTs = 0;
  let nodeTracks = Object.values(currentView.nodes);
  let radioRows = Object.values(currentView.radios);
  let overlayRows = Object.values(currentView.overlayLinks);
  let routeRows: RouteState[] = [];
  let neighborRows: NeighborState[] = [];
  let startupRows = Object.values(currentView.startupMetrics);
  let assertionPassCount = 0;

  let mapBounds = {
    minX: -10,
    maxX: 10,
    minY: -10,
    maxY: 10,
    spanX: 20,
    spanY: 20
  };

  let overlayNodeIds: string[] = [];
  let overlayNodeLayout: Record<string, { x: number; y: number }> = {};

  $: maxTs = events.length > 0 ? events[events.length - 1].ts_ms : 0;
  $: if (mode === 'live') {
    replayMs = maxTs;
  }
  $: currentView = mode === 'live' ? liveView : buildStateForTs(replayMs);
  $: nodeTracks = Object.values(currentView.nodes).sort((a, b) => a.id.localeCompare(b.id));
  $: radioRows = Object.values(currentView.radios).sort((a, b) => a.key.localeCompare(b.key));
  $: overlayRows = Object.values(currentView.overlayLinks).sort((a, b) => a.key.localeCompare(b.key));
  $: routeRows = Object.values(currentView.routesByNode)
    .flat()
    .sort((a, b) => a.node.localeCompare(b.node) || a.metric - b.metric);
  $: neighborRows = Object.values(currentView.neighborsByNode)
    .flat()
    .sort((a, b) => a.node.localeCompare(b.node) || a.id.localeCompare(b.id));
  $: startupRows = Object.values(currentView.startupMetrics).sort((a, b) => a.key.localeCompare(b.key));
  $: assertionPassCount = currentView.assertions.filter((assertion) => assertion.passed).length;
  $: mapBounds = computeMapBounds(nodeTracks);
  $: overlayNodeIds = collectOverlayNodes(currentView, overlayRows);
  $: overlayNodeLayout = computeOverlayLayout(overlayNodeIds, 420, 260);

  onDestroy(async () => {
    await disconnect();
  });

  async function connectLive(): Promise<void> {
    await disconnect();
    resetSession(runId);

    status = 'connecting';
    statusDetail = `Connecting to ${serverUrl}`;
    errorMessage = '';

    try {
      connection = await connectTelemetry({
        serverUrl,
        runId,
        onEnvelope: (envelope) => {
          ingestEnvelope(envelope);
        },
        onError: (error) => {
          errorMessage = error.message;
        }
      });
      status = 'connected';
      statusDetail = `Live subscription on avena.v1.${runId}.>`;
    } catch (error) {
      status = 'error';
      statusDetail = 'Connection failed';
      errorMessage = error instanceof Error ? error.message : 'Failed to connect';
      connection = null;
    }
  }

  async function disconnect(): Promise<void> {
    if (!connection) {
      return;
    }

    await connection.close();
    connection = null;
    status = 'idle';
    statusDetail = 'Disconnected';
  }

  async function loadJetStreamReplay(): Promise<void> {
    if (!connection) {
      errorMessage = 'Connect to NATS first, then load replay.';
      return;
    }

    status = 'loading';
    statusDetail = 'Loading JetStream replay';
    errorMessage = '';

    try {
      const replay = await connection.loadReplay({
        streamName: streamNameOverride.trim() || undefined,
        maxMessages: 6000
      });

      events = replay;
      liveView = buildStateForTs(Number.MAX_SAFE_INTEGER);
      mode = 'replay';
      replayMs = maxTs;
      status = 'replay';
      statusDetail = `Loaded ${replay.length} events from ${effectiveStreamName()}`;
    } catch (error) {
      status = 'error';
      statusDetail = 'JetStream replay failed';
      errorMessage = error instanceof Error ? error.message : 'Replay request failed';
    }
  }

  async function loadDemo(): Promise<void> {
    await disconnect();
    resetSession(runId);

    events = buildDemoReplay(runId);
    liveView = buildStateForTs(Number.MAX_SAFE_INTEGER);
    mode = 'replay';
    replayMs = maxTs;
    status = 'demo';
    statusDetail = 'Loaded deterministic demo timeline';
    errorMessage = '';
  }

  function resetSession(nextRunId: string): void {
    events = [];
    liveView = createEmptyViewState(nextRunId);
    replayMs = 0;
  }

  function ingestEnvelope(envelope: TelemetryEnvelope): void {
    if (!envelope || envelope.run_id !== runId) {
      return;
    }

    if (events.length === 0 || envelope.ts_ms >= events[events.length - 1].ts_ms) {
      events = [...events, envelope];
    } else {
      events = [...events, envelope].sort((a, b) => a.ts_ms - b.ts_ms);
    }

    const next = cloneView(liveView);
    applyEnvelope(next, envelope);
    liveView = next;
  }

  function buildStateForTs(ts: number): TelemetryViewState {
    const replay = createEmptyViewState(runId);
    for (const envelope of events) {
      if (envelope.ts_ms > ts) {
        break;
      }
      applyEnvelope(replay, envelope);
    }
    return replay;
  }

  function cloneView(view: TelemetryViewState): TelemetryViewState {
    if (typeof structuredClone === 'function') {
      return structuredClone(view);
    }
    return JSON.parse(JSON.stringify(view)) as TelemetryViewState;
  }

  function effectiveStreamName(): string {
    const trimmed = streamNameOverride.trim();
    return trimmed || jetstreamStreamName(runId);
  }

  function defaultRunId(): string {
    const now = new Date();
    return `run-${now.getUTCFullYear()}${pad(now.getUTCMonth() + 1)}${pad(now.getUTCDate())}-${pad(
      now.getUTCHours()
    )}${pad(now.getUTCMinutes())}${pad(now.getUTCSeconds())}`;
  }

  function pad(value: number): string {
    return value.toString().padStart(2, '0');
  }

  function computeMapBounds(
    tracks: Array<{ latest?: { x_m: number; y_m: number }; trail: Array<{ x_m: number; y_m: number }> }>
  ): {
    minX: number;
    maxX: number;
    minY: number;
    maxY: number;
    spanX: number;
    spanY: number;
  } {
    const points = tracks.flatMap((track) => {
      const latest = track.latest ? [{ x_m: track.latest.x_m, y_m: track.latest.y_m }] : [];
      return [...track.trail.map((sample) => ({ x_m: sample.x_m, y_m: sample.y_m })), ...latest];
    });

    if (points.length === 0) {
      return {
        minX: -10,
        maxX: 10,
        minY: -10,
        maxY: 10,
        spanX: 20,
        spanY: 20
      };
    }

    const xs = points.map((point) => point.x_m);
    const ys = points.map((point) => point.y_m);
    const minX = Math.min(...xs);
    const maxX = Math.max(...xs);
    const minY = Math.min(...ys);
    const maxY = Math.max(...ys);
    const spanX = Math.max(4, maxX - minX);
    const spanY = Math.max(4, maxY - minY);

    return {
      minX,
      maxX,
      minY,
      maxY,
      spanX,
      spanY
    };
  }

  function mapX(x: number): number {
    const padding = 36;
    const width = 560 - padding * 2;
    return padding + ((x - mapBounds.minX) / mapBounds.spanX) * width;
  }

  function mapY(y: number): number {
    const padding = 26;
    const height = 290 - padding * 2;
    return 290 - (padding + ((y - mapBounds.minY) / mapBounds.spanY) * height);
  }

  function trailPoints(samples: Array<{ x_m: number; y_m: number }>): string {
    if (samples.length === 0) {
      return '';
    }
    return samples.map((sample) => `${mapX(sample.x_m)},${mapY(sample.y_m)}`).join(' ');
  }

  function collectOverlayNodes(
    view: TelemetryViewState,
    links: OverlayLinkState[]
  ): string[] {
    const ids = new Set<string>();
    for (const node of Object.keys(view.nodes)) {
      ids.add(node);
    }
    for (const link of links) {
      ids.add(link.node);
      ids.add(link.peer);
    }
    return Array.from(ids).sort();
  }

  function computeOverlayLayout(
    nodes: string[],
    width: number,
    height: number
  ): Record<string, { x: number; y: number }> {
    const centerX = width / 2;
    const centerY = height / 2;
    const radius = Math.max(70, Math.min(width, height) / 2 - 42);
    const layout: Record<string, { x: number; y: number }> = {};

    if (nodes.length === 0) {
      return layout;
    }

    nodes.forEach((id, index) => {
      const angle = (Math.PI * 2 * index) / nodes.length - Math.PI / 2;
      layout[id] = {
        x: centerX + Math.cos(angle) * radius,
        y: centerY + Math.sin(angle) * radius
      };
    });

    return layout;
  }

  function radioStatusClass(status: string): string {
    if (status.includes('ready') || status.includes('connected')) {
      return 'status-good';
    }
    if (status.includes('disconnected')) {
      return 'status-bad';
    }
    return 'status-neutral';
  }

  function linkStatusClass(status: string): string {
    if (status === 'peer_connected') {
      return 'status-good';
    }
    if (status === 'peer_disconnected') {
      return 'status-bad';
    }
    return 'status-neutral';
  }

  function formatMs(value?: number): string {
    if (value === undefined) {
      return '-';
    }
    return `${Math.round(value)} ms`;
  }
</script>

<svelte:head>
  <title>Avena UI v0</title>
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <link
    rel="stylesheet"
    href="https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500;600;700&family=IBM+Plex+Mono:wght@400;600&display=swap"
  />
</svelte:head>

<main class="shell">
  <section class="hero panel">
    <div class="hero-top">
      <div>
        <h1>Avena Telemetry Cockpit</h1>
        <p>
          Live NATS telemetry and JetStream replay for ns-3 underlay, overlay peers, and Babel route
          state.
        </p>
      </div>
      <div class="status-pill status-{status}">
        <span>{status.toUpperCase()}</span>
        <small>{statusDetail}</small>
      </div>
    </div>

    <div class="controls">
      <label>
        <span>Run ID</span>
        <input bind:value={runId} placeholder="run-20260303-120000" />
      </label>

      <label>
        <span>NATS WebSocket URL</span>
        <input bind:value={serverUrl} placeholder="ws://127.0.0.1:9222" />
      </label>

      <label>
        <span>JetStream Stream (optional)</span>
        <input
          bind:value={streamNameOverride}
          placeholder={jetstreamStreamName(runId)}
          title="Default stream name is derived from the run id"
        />
      </label>
    </div>

    <div class="actions">
      <button class="primary" on:click={connectLive}>Connect Live</button>
      <button class="ghost" on:click={loadJetStreamReplay}>Load JetStream Replay</button>
      <button class="ghost" on:click={loadDemo}>Load Demo</button>
      <button class="ghost" on:click={disconnect}>Disconnect</button>
    </div>

    <div class="timeline">
      <div>
        <strong>Timeline</strong>
        <span>{mode === 'live' ? 'Live mode' : 'Replay mode'} · {events.length} events cached</span>
      </div>

      <div class="timeline-controls">
        <button class:active={mode === 'live'} on:click={() => (mode = 'live')}>Live</button>
        <button class:active={mode === 'replay'} on:click={() => (mode = 'replay')}>Replay</button>
        <input
          type="range"
          min="0"
          max={Math.max(1, maxTs)}
          step="100"
          bind:value={replayMs}
          disabled={mode !== 'replay'}
        />
        <code>{formatMs(replayMs)}</code>
      </div>
    </div>

    {#if errorMessage}
      <p class="error">{errorMessage}</p>
    {/if}

    <p class="hint">Effective replay stream: <code>{effectiveStreamName()}</code></p>
  </section>

  <section class="summary-grid">
    <article class="panel metric">
      <h2>Nodes</h2>
      <strong>{Object.keys(currentView.nodes).length}</strong>
      <small>{currentView.scenario?.backend ?? 'unknown backend'}</small>
    </article>

    <article class="panel metric">
      <h2>Realtime Lag</h2>
      <strong>{formatMs(currentView.realtimeLagMs)}</strong>
      <small>Latest ns3 realtime report</small>
    </article>

    <article class="panel metric">
      <h2>Overlay Links</h2>
      <strong>{overlayRows.length}</strong>
      <small>
        {overlayRows.filter((row) => row.status === 'peer_connected').length} currently connected
      </small>
    </article>

    <article class="panel metric">
      <h2>Assertions</h2>
      <strong>{assertionPassCount}/{currentView.assertions.length}</strong>
      <small>Pass/total assertion results</small>
    </article>
  </section>

  <section class="grid">
    <article class="panel map-panel">
      <h2>Map View</h2>
      <svg viewBox="0 0 560 290" role="img" aria-label="Node positions">
        <rect x="0" y="0" width="560" height="290" rx="12" class="map-bg" />
        {#each nodeTracks as node}
          {#if node.trail.length > 1}
            <polyline class="trail" points={trailPoints(node.trail)} />
          {/if}
          {#if node.latest}
            <circle class="dot" cx={mapX(node.latest.x_m)} cy={mapY(node.latest.y_m)} r="6" />
            <text class="label" x={mapX(node.latest.x_m) + 8} y={mapY(node.latest.y_m) - 8}>
              {node.id}
            </text>
          {/if}
        {/each}
      </svg>
    </article>

    <article class="panel">
      <h2>Underlay Radios</h2>
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Node</th>
              <th>Radio</th>
              <th>Band</th>
              <th>Channel</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            {#if radioRows.length === 0}
              <tr><td colspan="5" class="empty">No radio telemetry yet</td></tr>
            {:else}
              {#each radioRows as radio}
                <tr>
                  <td>{radio.node}</td>
                  <td>{radio.radio}</td>
                  <td>{radio.band ?? '-'}</td>
                  <td>{radio.channel ?? '-'}</td>
                  <td><span class={radioStatusClass(radio.status)}>{radio.status}</span></td>
                </tr>
              {/each}
            {/if}
          </tbody>
        </table>
      </div>
    </article>

    <article class="panel">
      <h2>Overlay Graph</h2>
      <svg viewBox="0 0 420 260" role="img" aria-label="Overlay peer graph">
        <rect x="0" y="0" width="420" height="260" rx="12" class="graph-bg" />

        {#each overlayRows as link}
          {#if overlayNodeLayout[link.node] && overlayNodeLayout[link.peer]}
            <line
              x1={overlayNodeLayout[link.node].x}
              y1={overlayNodeLayout[link.node].y}
              x2={overlayNodeLayout[link.peer].x}
              y2={overlayNodeLayout[link.peer].y}
              class={linkStatusClass(link.status)}
            />
          {/if}
        {/each}

        {#each overlayNodeIds as nodeId}
          {#if overlayNodeLayout[nodeId]}
            <circle class="overlay-node" cx={overlayNodeLayout[nodeId].x} cy={overlayNodeLayout[nodeId].y} r="14" />
            <text class="overlay-label" x={overlayNodeLayout[nodeId].x} y={overlayNodeLayout[nodeId].y + 4}>
              {nodeId}
            </text>
          {/if}
        {/each}
      </svg>

      <div class="table-wrap compact">
        <table>
          <thead>
            <tr>
              <th>Link</th>
              <th>Status</th>
              <th>Seen</th>
            </tr>
          </thead>
          <tbody>
            {#if overlayRows.length === 0}
              <tr><td colspan="3" class="empty">No overlay events yet</td></tr>
            {:else}
              {#each overlayRows as link}
                <tr>
                  <td>{link.node} ↔ {link.peer}</td>
                  <td><span class={linkStatusClass(link.status)}>{link.status}</span></td>
                  <td>{formatMs(link.lastSeenMs)}</td>
                </tr>
              {/each}
            {/if}
          </tbody>
        </table>
      </div>
    </article>

    <article class="panel">
      <h2>Babel Routes</h2>
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Node</th>
              <th>Prefix</th>
              <th>Via</th>
              <th>Interface</th>
              <th>Metric</th>
            </tr>
          </thead>
          <tbody>
            {#if routeRows.length === 0}
              <tr><td colspan="5" class="empty">No Babel route snapshots yet</td></tr>
            {:else}
              {#each routeRows as route}
                <tr>
                  <td>{route.node}</td>
                  <td><code>{route.prefix}</code></td>
                  <td><code>{route.via}</code></td>
                  <td>{route.interface}</td>
                  <td>{route.metric}</td>
                </tr>
              {/each}
            {/if}
          </tbody>
        </table>
      </div>
    </article>

    <article class="panel">
      <h2>Babel Neighbors</h2>
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Node</th>
              <th>Neighbor</th>
              <th>Interface</th>
              <th>Rx/Tx Cost</th>
              <th>Reach</th>
            </tr>
          </thead>
          <tbody>
            {#if neighborRows.length === 0}
              <tr><td colspan="5" class="empty">No Babel neighbor snapshots yet</td></tr>
            {:else}
              {#each neighborRows as neighbor}
                <tr>
                  <td>{neighbor.node}</td>
                  <td><code>{neighbor.address}</code></td>
                  <td>{neighbor.interface}</td>
                  <td>{neighbor.rxCost}/{neighbor.txCost}</td>
                  <td>{neighbor.reach}</td>
                </tr>
              {/each}
            {/if}
          </tbody>
        </table>
      </div>
    </article>

    <article class="panel">
      <h2>Startup Metrics</h2>
      <div class="table-wrap compact">
        <table>
          <thead>
            <tr>
              <th>Node</th>
              <th>Metric</th>
              <th>Value</th>
            </tr>
          </thead>
          <tbody>
            {#if startupRows.length === 0}
              <tr><td colspan="3" class="empty">No derived startup metrics yet</td></tr>
            {:else}
              {#each startupRows as metric}
                <tr>
                  <td>{metric.node}</td>
                  <td>{metric.metric}</td>
                  <td>{formatMs(metric.valueMs)}</td>
                </tr>
              {/each}
            {/if}
          </tbody>
        </table>
      </div>
    </article>

    <article class="panel">
      <h2>Assertion Timeline</h2>
      <div class="assertions">
        {#if currentView.assertions.length === 0}
          <p class="empty">No assertion results yet</p>
        {:else}
          {#each currentView.assertions as assertion}
            <div class="assertion {assertion.passed ? 'pass' : 'fail'}">
              <strong>{assertion.condition}</strong>
              <span>{assertion.passed ? 'PASS' : 'FAIL'}</span>
              <small>at {assertion.atSecs ?? '-'}s · seen {formatMs(assertion.tsMs)}</small>
            </div>
          {/each}
        {/if}
      </div>
    </article>
  </section>
</main>

<style>
  :global(body) {
    margin: 0;
    font-family: 'IBM Plex Sans', 'Segoe UI', sans-serif;
    background:
      radial-gradient(140% 110% at 0% 0%, #12333d 0%, rgba(18, 51, 61, 0.2) 58%, transparent 75%),
      radial-gradient(120% 150% at 100% 0%, #1c2f5f 0%, rgba(28, 47, 95, 0.3) 52%, transparent 80%),
      #08131b;
    color: #e6f0f4;
  }

  .shell {
    max-width: 1400px;
    margin: 0 auto;
    padding: 1.25rem;
    display: grid;
    gap: 1rem;
  }

  .panel {
    background: linear-gradient(160deg, rgba(20, 38, 48, 0.94), rgba(10, 23, 31, 0.9));
    border: 1px solid rgba(116, 167, 184, 0.24);
    border-radius: 16px;
    box-shadow: inset 0 1px 0 rgba(196, 224, 232, 0.08), 0 22px 40px rgba(2, 9, 14, 0.35);
  }

  .hero {
    padding: 1.2rem;
    display: grid;
    gap: 1rem;
  }

  .hero-top {
    display: flex;
    justify-content: space-between;
    gap: 1rem;
    align-items: flex-start;
  }

  h1 {
    margin: 0;
    font-size: clamp(1.4rem, 2.6vw, 2rem);
    letter-spacing: 0.02em;
  }

  h2 {
    margin: 0 0 0.8rem;
    font-size: 1rem;
    letter-spacing: 0.04em;
    text-transform: uppercase;
    color: #8fbbc8;
  }

  p {
    margin: 0.35rem 0 0;
    color: #b5d0d8;
  }

  .status-pill {
    display: grid;
    gap: 0.15rem;
    text-align: right;
    border-radius: 999px;
    padding: 0.55rem 0.9rem;
    border: 1px solid rgba(122, 176, 192, 0.35);
    background: rgba(22, 56, 68, 0.7);
    min-width: 180px;
  }

  .status-pill span {
    font-family: 'IBM Plex Mono', monospace;
    font-size: 0.82rem;
    letter-spacing: 0.08em;
  }

  .status-pill small {
    color: #9fc0ca;
    font-size: 0.72rem;
  }

  .status-connected,
  .status-replay,
  .status-demo {
    border-color: rgba(74, 197, 151, 0.7);
    background: rgba(17, 74, 59, 0.54);
  }

  .status-error {
    border-color: rgba(247, 116, 91, 0.8);
    background: rgba(113, 34, 29, 0.54);
  }

  .status-loading,
  .status-connecting {
    border-color: rgba(237, 177, 89, 0.8);
    background: rgba(94, 67, 24, 0.5);
  }

  .controls {
    display: grid;
    grid-template-columns: repeat(3, minmax(220px, 1fr));
    gap: 0.8rem;
  }

  label {
    display: grid;
    gap: 0.35rem;
  }

  label span {
    font-size: 0.78rem;
    color: #9dbbc5;
    letter-spacing: 0.05em;
    text-transform: uppercase;
  }

  input {
    font: inherit;
    background: rgba(12, 29, 39, 0.92);
    color: #def1f8;
    border: 1px solid rgba(119, 162, 177, 0.4);
    border-radius: 10px;
    padding: 0.55rem 0.65rem;
    transition: border-color 120ms ease;
  }

  input:focus {
    outline: none;
    border-color: rgba(81, 204, 201, 0.9);
  }

  .actions {
    display: flex;
    flex-wrap: wrap;
    gap: 0.55rem;
  }

  button {
    font: inherit;
    border-radius: 10px;
    border: 1px solid rgba(126, 168, 183, 0.5);
    color: #d5ebf1;
    background: rgba(15, 37, 48, 0.9);
    padding: 0.52rem 0.85rem;
    cursor: pointer;
    transition: transform 120ms ease, background 120ms ease;
  }

  button:hover {
    transform: translateY(-1px);
  }

  button.primary {
    background: linear-gradient(135deg, #2f90a8, #2b6d98);
    border-color: rgba(102, 196, 220, 0.9);
    color: #f5fcff;
  }

  button.ghost {
    background: rgba(16, 39, 50, 0.65);
  }

  .timeline {
    display: grid;
    gap: 0.5rem;
    padding: 0.7rem 0.8rem;
    border-radius: 12px;
    background: rgba(6, 18, 26, 0.55);
    border: 1px solid rgba(93, 130, 144, 0.35);
  }

  .timeline > div:first-child {
    display: flex;
    justify-content: space-between;
    gap: 1rem;
    align-items: baseline;
  }

  .timeline-controls {
    display: flex;
    align-items: center;
    gap: 0.5rem;
  }

  .timeline-controls button {
    padding: 0.35rem 0.65rem;
    font-size: 0.84rem;
  }

  .timeline-controls button.active {
    background: rgba(34, 89, 102, 0.92);
    border-color: rgba(106, 198, 214, 0.92);
  }

  .timeline-controls input[type='range'] {
    flex: 1;
    min-width: 160px;
  }

  code {
    font-family: 'IBM Plex Mono', monospace;
    font-size: 0.78rem;
    color: #8dd2de;
  }

  .hint {
    color: #93b7c1;
    font-size: 0.82rem;
  }

  .error {
    margin: 0;
    color: #ffb3a8;
  }

  .summary-grid {
    display: grid;
    grid-template-columns: repeat(4, minmax(140px, 1fr));
    gap: 0.85rem;
  }

  .metric {
    padding: 0.8rem 1rem;
    display: grid;
    gap: 0.35rem;
  }

  .metric strong {
    font-family: 'IBM Plex Mono', monospace;
    font-size: 1.55rem;
    color: #ddf7fb;
  }

  .metric small {
    color: #98bac5;
  }

  .grid {
    display: grid;
    grid-template-columns: repeat(2, minmax(280px, 1fr));
    gap: 0.9rem;
  }

  .grid > .panel {
    padding: 0.9rem;
  }

  .map-panel svg,
  .panel svg {
    width: 100%;
    border-radius: 12px;
  }

  .map-bg {
    fill: rgba(9, 24, 32, 0.85);
    stroke: rgba(82, 126, 142, 0.35);
  }

  .graph-bg {
    fill: rgba(9, 23, 31, 0.8);
    stroke: rgba(89, 126, 140, 0.35);
  }

  .trail {
    fill: none;
    stroke: rgba(118, 192, 207, 0.6);
    stroke-width: 2;
  }

  .dot {
    fill: #ffcf6e;
    stroke: rgba(15, 27, 35, 0.8);
    stroke-width: 1.4;
  }

  .label,
  .overlay-label {
    font-size: 11px;
    fill: #d8eef5;
    font-family: 'IBM Plex Mono', monospace;
  }

  .overlay-node {
    fill: #24556a;
    stroke: #7ed2e2;
    stroke-width: 1.2;
  }

  line.status-good {
    stroke: rgba(99, 219, 167, 0.9);
    stroke-width: 2.2;
  }

  line.status-neutral {
    stroke: rgba(239, 193, 106, 0.86);
    stroke-width: 2;
  }

  line.status-bad {
    stroke: rgba(245, 114, 98, 0.9);
    stroke-width: 2;
    stroke-dasharray: 6 4;
  }

  .table-wrap {
    overflow: auto;
    max-height: 320px;
    border: 1px solid rgba(97, 135, 149, 0.33);
    border-radius: 10px;
    background: rgba(7, 19, 25, 0.6);
  }

  .table-wrap.compact {
    margin-top: 0.7rem;
    max-height: 240px;
  }

  table {
    width: 100%;
    border-collapse: collapse;
    font-size: 0.86rem;
  }

  thead {
    position: sticky;
    top: 0;
    z-index: 1;
    background: rgba(14, 31, 40, 0.95);
  }

  th,
  td {
    padding: 0.5rem 0.56rem;
    text-align: left;
    border-bottom: 1px solid rgba(80, 111, 123, 0.25);
    vertical-align: top;
  }

  .empty {
    text-align: center;
    color: #89aab5;
    padding: 0.95rem;
  }

  .status-good,
  .status-neutral,
  .status-bad {
    display: inline-block;
    border-radius: 999px;
    padding: 0.14rem 0.5rem;
    font-size: 0.76rem;
    letter-spacing: 0.04em;
    text-transform: uppercase;
  }

  .status-good {
    background: rgba(73, 175, 136, 0.24);
    color: #9ef2c8;
  }

  .status-neutral {
    background: rgba(225, 170, 92, 0.2);
    color: #f6d08c;
  }

  .status-bad {
    background: rgba(219, 97, 81, 0.25);
    color: #ffb4aa;
  }

  .assertions {
    display: grid;
    gap: 0.5rem;
  }

  .assertion {
    border: 1px solid rgba(112, 147, 159, 0.32);
    border-radius: 10px;
    padding: 0.5rem 0.65rem;
    display: grid;
    grid-template-columns: 1fr auto;
    gap: 0.15rem 0.8rem;
    background: rgba(10, 25, 34, 0.65);
  }

  .assertion.pass {
    border-color: rgba(90, 184, 146, 0.52);
  }

  .assertion.fail {
    border-color: rgba(211, 103, 90, 0.56);
  }

  .assertion small {
    grid-column: 1 / -1;
    color: #93b7c2;
  }

  @media (max-width: 980px) {
    .controls {
      grid-template-columns: 1fr;
    }

    .summary-grid {
      grid-template-columns: repeat(2, minmax(140px, 1fr));
    }

    .grid {
      grid-template-columns: 1fr;
    }

    .hero-top {
      flex-direction: column;
    }

    .status-pill {
      min-width: unset;
      width: 100%;
      text-align: left;
    }

    .timeline > div:first-child {
      flex-direction: column;
      align-items: flex-start;
    }
  }

  @media (max-width: 580px) {
    .shell {
      padding: 0.8rem;
    }

    .summary-grid {
      grid-template-columns: 1fr;
    }
  }
</style>
