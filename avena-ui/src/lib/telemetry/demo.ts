import type { TelemetryEnvelope } from './types';

export function buildDemoReplay(runId: string): TelemetryEnvelope[] {
  const base: TelemetryEnvelope[] = [];

  base.push(
    envelope(runId, 0, 'testbed', `avena.v1.${runId}.scenario`, {
      name: 'demo-ns3',
      duration_secs: 45,
      backend: 'ns3',
      nodes: [
        { id: 'nodeA', radio_profile: 'default_wifi', radios: ['wifi0'] },
        { id: 'nodeB', radio_profile: 'default_wifi', radios: ['wifi0'] },
        { id: 'nodeC', radio_profile: 'default_wifi', radios: ['wifi0'] }
      ],
      links: [
        { id: 'ab-wifi', endpoints: ['nodeA:wifi0', 'nodeB:wifi0'], medium: 'wifi' },
        { id: 'bc-wifi', endpoints: ['nodeB:wifi0', 'nodeC:wifi0'], medium: 'wifi' }
      ],
      bridges: []
    })
  );

  for (let i = 1; i <= 20; i += 1) {
    base.push(
      envelope(runId, i * 1000, 'ns3', `avena.v1.${runId}.ns3.realtime`, {
        type: 'realtime',
        sim_ms: i * 1000,
        wall_ms: i * 1000 + (i % 3) * 8,
        lag_ms: (i % 3) * 8
      })
    );

    base.push(
      envelope(runId, i * 1000, 'ns3', `avena.v1.${runId}.ns3.mobility`, {
        type: 'mobility',
        node: 'nodeA',
        x_m: i * 2,
        y_m: 5 + i * 0.5,
        z_m: 0
      },
      { node: 'nodeA' })
    );

    base.push(
      envelope(runId, i * 1000, 'ns3', `avena.v1.${runId}.ns3.mobility`, {
        type: 'mobility',
        node: 'nodeB',
        x_m: 30,
        y_m: i,
        z_m: 0
      },
      { node: 'nodeB' })
    );

    base.push(
      envelope(runId, i * 1000, 'ns3', `avena.v1.${runId}.ns3.mobility`, {
        type: 'mobility',
        node: 'nodeC',
        x_m: 60 - i * 1.5,
        y_m: 20 - i * 0.4,
        z_m: 0
      },
      { node: 'nodeC' })
    );
  }

  base.push(
    envelope(runId, 1500, 'ns3', `avena.v1.${runId}.ns3.l2`, {
      type: 'l2',
      event: 'l2_ready',
      node: 'nodeA',
      radio: 'wifi0',
      network: 'ab-wifi',
      band: '5ghz',
      channel: 36
    },
    { node: 'nodeA', radio: 'wifi0' })
  );

  base.push(
    envelope(runId, 1600, 'ns3', `avena.v1.${runId}.ns3.l2`, {
      type: 'l2',
      event: 'l2_ready',
      node: 'nodeB',
      radio: 'wifi0',
      network: 'ab-wifi',
      band: '5ghz',
      channel: 36
    },
    { node: 'nodeB', radio: 'wifi0' })
  );

  base.push(
    envelope(runId, 1700, 'ns3', `avena.v1.${runId}.ns3.l2`, {
      type: 'l2',
      event: 'l2_ready',
      node: 'nodeC',
      radio: 'wifi0',
      network: 'bc-wifi',
      band: '5ghz',
      channel: 36
    },
    { node: 'nodeC', radio: 'wifi0' })
  );

  base.push(
    envelope(runId, 2400, 'avenad', `avena.v1.${runId}.node.nodeA.overlay.peer_discovered`, {
      peer_id: 'nodeB'
    },
    { node: 'nodeA', peer: 'nodeB' })
  );
  base.push(
    envelope(runId, 2700, 'avenad', `avena.v1.${runId}.node.nodeA.overlay.peer_connected`, {
      peer_id: 'nodeB'
    },
    { node: 'nodeA', peer: 'nodeB' })
  );

  base.push(
    envelope(runId, 3100, 'avenad', `avena.v1.${runId}.node.nodeB.overlay.peer_discovered`, {
      peer_id: 'nodeC'
    },
    { node: 'nodeB', peer: 'nodeC' })
  );
  base.push(
    envelope(runId, 3600, 'avenad', `avena.v1.${runId}.node.nodeB.overlay.peer_connected`, {
      peer_id: 'nodeC'
    },
    { node: 'nodeB', peer: 'nodeC' })
  );

  base.push(
    envelope(runId, 4200, 'testbed', `avena.v1.${runId}.metrics.startup`, {
      node: 'nodeA',
      metric: 'l2_ready_to_peer_connected_ms',
      value_ms: 1200,
      observed_ms: 2700
    },
    { node: 'nodeA' })
  );

  base.push(
    envelope(runId, 5100, 'testbed', `avena.v1.${runId}.metrics.startup`, {
      node: 'nodeB',
      metric: 'l2_ready_to_peer_connected_ms',
      value_ms: 2000,
      observed_ms: 3600
    },
    { node: 'nodeB' })
  );

  base.push(
    envelope(runId, 6000, 'avenad', `avena.v1.${runId}.node.nodeB.routing.babel.routes`, {
      routes: [
        {
          id: 'r1',
          prefix: 'fd00::/64',
          installed: true,
          metric: 96,
          via: 'fe80::1',
          interface: 'av-nodeA'
        },
        {
          id: 'r2',
          prefix: 'fd01::/64',
          installed: true,
          metric: 128,
          via: 'fe80::2',
          interface: 'av-nodeC'
        }
      ]
    },
    { node: 'nodeB' })
  );

  base.push(
    envelope(runId, 6200, 'avenad', `avena.v1.${runId}.node.nodeB.routing.babel.neighbors`, {
      neighbours: [
        {
          id: 'n1',
          address: 'fe80::1',
          interface: 'av-nodeA',
          rxcost: 96,
          txcost: 96,
          reach: 'ffff'
        },
        {
          id: 'n2',
          address: 'fe80::2',
          interface: 'av-nodeC',
          rxcost: 128,
          txcost: 128,
          reach: 'ff0f'
        }
      ]
    },
    { node: 'nodeB' })
  );

  base.push(
    envelope(runId, 10000, 'testbed', `avena.v1.${runId}.testbed.assertion_result`, {
      condition: 'NodesConnected',
      at_secs: 10,
      passed: true
    })
  );
  base.push(
    envelope(runId, 15000, 'testbed', `avena.v1.${runId}.testbed.assertion_result`, {
      condition: 'Ping',
      at_secs: 15,
      passed: true
    })
  );

  return base.sort((a, b) => a.ts_ms - b.ts_ms);
}

function envelope(
  runId: string,
  tsMs: number,
  source: string,
  subject: string,
  data: Record<string, unknown>,
  identity: {
    node?: string;
    radio?: string;
    peer?: string;
  } = {}
): TelemetryEnvelope {
  return {
    v: 1,
    subject,
    ts_ms: tsMs,
    run_id: runId,
    source,
    node: identity.node,
    radio: identity.radio,
    peer: identity.peer,
    data
  };
}
