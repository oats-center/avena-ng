# Container Assets

This directory contains the container image definition and example quadlet files for running `avena-overlay` as a reusable network sidecar.

## Files

- `Containerfile` builds the `avena-overlay` image with a multistage Rust build.
- `quadlet/avena-overlay.container` runs the overlay sidecar and publishes the overlay ports.
- `quadlet/avena-nats.container.example` shows how to run `nats-server` in the overlay container's network namespace.

## Build

From the repository root:

```bash
podman build -t localhost/avena-overlay:latest -f avena-overlay/container/Containerfile .
```

## Quadlet install

Copy the desired files from `quadlet/` into your quadlet directory, for example:

- rootful: `/etc/containers/systemd/`
- rootless: `~/.config/containers/systemd/`

Then reload systemd and start the generated service:

```bash
systemctl daemon-reload
systemctl start avena-overlay.service
```

If you also run a sibling service like NATS, give that container `Network=avena-overlay.container` so it joins the overlay container's network namespace.

## Published ports

- `51820/udp` for WireGuard data
- `51821/tcp` for handshake control

Sibling containers decide their own published host ports, for example `4222/tcp` for NATS.
