import { StringCodec, connect, type NatsConnection, type Subscription } from 'nats.ws';
import type { TelemetryEnvelope } from './types';

export interface TelemetryConnectionOptions {
  serverUrl: string;
  runId: string;
  onEnvelope: (envelope: TelemetryEnvelope) => void;
  onError?: (error: Error) => void;
}

export interface ReplayOptions {
  maxMessages?: number;
  streamName?: string;
}

export interface TelemetryConnection {
  close: () => Promise<void>;
  loadReplay: (options?: ReplayOptions) => Promise<TelemetryEnvelope[]>;
  streamName: string;
}

const DEFAULT_REPLAY_MAX_MESSAGES = 5000;

export async function connectTelemetry(options: TelemetryConnectionOptions): Promise<TelemetryConnection> {
  const nc = await connect({ servers: options.serverUrl });
  const subject = telemetryRunSubjectPattern(options.runId);
  const sub = nc.subscribe(subject);
  const codec = StringCodec();
  const streamName = jetstreamStreamName(options.runId);

  const pump = consumeLiveSubscription(sub, codec, options.onEnvelope, options.onError);

  return {
    streamName,
    close: async () => {
      sub.unsubscribe();
      await pump;
      await nc.drain();
    },
    loadReplay: async (replayOptions?: ReplayOptions) =>
      loadReplayFromJetStream(nc, options.runId, {
        maxMessages: replayOptions?.maxMessages,
        streamName: replayOptions?.streamName
      })
  };
}

export async function loadReplayFromJetStream(
  nc: NatsConnection,
  runId: string,
  options?: ReplayOptions
): Promise<TelemetryEnvelope[]> {
  const jsm = await nc.jetstreamManager();
  const streamName = options?.streamName?.trim() || jetstreamStreamName(runId);
  const maxMessages = Math.max(1, options?.maxMessages ?? DEFAULT_REPLAY_MAX_MESSAGES);

  const stream = await jsm.streams.get(streamName);
  const info = await stream.info();
  const firstSeq = info.state.first_seq;
  const lastSeq = info.state.last_seq;

  if (lastSeq < firstSeq) {
    return [];
  }

  const startSeq = Math.max(firstSeq, lastSeq - maxMessages + 1);
  const envelopes: TelemetryEnvelope[] = [];

  for (let seq = startSeq; seq <= lastSeq; seq += 1) {
    try {
      const stored = await stream.getMessage({ seq });
      const parsed = parseEnvelope(stored.string());
      if (parsed && parsed.run_id === runId) {
        envelopes.push(parsed);
      }
    } catch {
      continue;
    }
  }

  return envelopes.sort((a, b) => a.ts_ms - b.ts_ms);
}

function consumeLiveSubscription(
  sub: Subscription,
  codec: ReturnType<typeof StringCodec>,
  onEnvelope: (envelope: TelemetryEnvelope) => void,
  onError?: (error: Error) => void
): Promise<void> {
  return (async () => {
    for await (const message of sub) {
      try {
        const payload = codec.decode(message.data);
        const envelope = parseEnvelope(payload);
        if (envelope) {
          onEnvelope(envelope);
        }
      } catch (error) {
        if (onError) {
          onError(error instanceof Error ? error : new Error('Failed to parse telemetry envelope'));
        }
      }
    }
  })();
}

function parseEnvelope(payload: string): TelemetryEnvelope | null {
  const parsed = JSON.parse(payload);
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    return null;
  }

  const obj = parsed as Record<string, unknown>;
  if (typeof obj.subject !== 'string') {
    return null;
  }
  if (typeof obj.run_id !== 'string') {
    return null;
  }
  if (typeof obj.ts_ms !== 'number') {
    return null;
  }
  if (!obj.data || typeof obj.data !== 'object' || Array.isArray(obj.data)) {
    return null;
  }

  return {
    v: typeof obj.v === 'number' ? obj.v : 1,
    subject: obj.subject,
    ts_ms: obj.ts_ms,
    run_id: obj.run_id,
    source: typeof obj.source === 'string' ? obj.source : 'unknown',
    node: typeof obj.node === 'string' ? obj.node : undefined,
    radio: typeof obj.radio === 'string' ? obj.radio : undefined,
    peer: typeof obj.peer === 'string' ? obj.peer : undefined,
    data: obj.data as Record<string, unknown>
  };
}

function telemetryRunSubjectPattern(runId: string): string {
  return `avena.v1.${runId}.>`;
}

export function jetstreamStreamName(runId: string): string {
  let token = runId
    .split('')
    .map((ch) => (/^[a-zA-Z0-9_-]$/.test(ch) ? ch.toUpperCase() : '_'))
    .join('');

  while (token.includes('__')) {
    token = token.replaceAll('__', '_');
  }

  token = token.replace(/^_+|_+$/g, '');
  if (!token) {
    token = 'RUN';
  }

  let stream = `AVENA_${token}`;
  if (stream.length > 128) {
    stream = stream.slice(0, 128);
  }
  return stream;
}
