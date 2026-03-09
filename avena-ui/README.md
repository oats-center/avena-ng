# Avena UI v0

SvelteKit dashboard for ns-3 + overlay telemetry.

The UI subscribes to `avena.v1.<run_id>.>` over NATS WebSocket and renders:

- node motion with trails
- radio underlay state
- overlay peer graph
- Babel route and neighbor snapshots
- assertion timeline
- startup metric events

It also supports local replay scrubbing from cached events and can request JetStream replay for a run.

## Run locally

```sh
npm install
npm run dev -- --open
```

Default live connection target in the UI is `ws://127.0.0.1:9222`.

## Build

```sh
npm run build
npm run preview
```

## NATS / JetStream notes

- The UI expects a WebSocket-enabled NATS listener.
- Run IDs come from `avena-testbed` telemetry envelopes (`run_id`).
- If stream name is left blank, the UI derives `AVENA_<RUN_ID_TOKEN>` using the same normalization as testbed.
