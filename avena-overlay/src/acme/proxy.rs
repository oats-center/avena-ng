use crate::{AcmeConfig, DeviceId};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::net::UdpSocket;
use tokio::sync::{Mutex, mpsc, oneshot};
use tracing::{debug, warn};

use super::frame::{ControlEnvelope, DiscoveryPayload, Frame, FrameKind};
use super::process::AcmeProcessController;
use super::AcmeError;

#[derive(Debug)]
pub struct IncomingControlRequest {
    pub source: DeviceId,
    pub request_id: u64,
    pub payload: Vec<u8>,
}

#[derive(Debug)]
pub struct AcmeRuntime {
    inner: Arc<AcmeRuntimeInner>,
}

#[derive(Debug)]
struct AcmeRuntimeInner {
    local_device_id: DeviceId,
    config: AcmeConfig,
    wg_proxy: Arc<UdpSocket>,
    rx_socket: Arc<UdpSocket>,
    tx_socket: Arc<UdpSocket>,
    peer_ports: Mutex<HashMap<DeviceId, u16>>,
    listen_ports: Mutex<HashMap<u16, DeviceId>>,
    pending: Mutex<HashMap<(DeviceId, u64), oneshot::Sender<Vec<u8>>>>,
    next_request_id: AtomicU64,
    processes: Mutex<Option<AcmeProcessController>>,
}

impl Clone for AcmeRuntime {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl AcmeRuntime {
    pub async fn start(
        config: AcmeConfig,
        local_device_id: DeviceId,
    ) -> Result<
        (
            Self,
            mpsc::Receiver<IncomingControlRequest>,
            mpsc::Receiver<DiscoveryPayload>,
        ),
        AcmeError,
    > {
        let wg_proxy = Arc::new(UdpSocket::bind(config.wg_proxy_endpoint()).await?);
        let rx_socket = Arc::new(UdpSocket::bind(config.rx_endpoint()).await?);
        let tx_socket = Arc::new(UdpSocket::bind((config.proxy_ip, 0)).await?);
        let processes = AcmeProcessController::start(&config).await?;

        let inner = Arc::new(AcmeRuntimeInner {
            local_device_id,
            config,
            wg_proxy: Arc::clone(&wg_proxy),
            rx_socket: Arc::clone(&rx_socket),
            tx_socket,
            peer_ports: Mutex::new(HashMap::new()),
            listen_ports: Mutex::new(HashMap::new()),
            pending: Mutex::new(HashMap::new()),
            next_request_id: AtomicU64::new(1),
            processes: Mutex::new(Some(processes)),
        });

        let (control_tx, control_rx) = mpsc::channel(64);
        let (discovery_tx, discovery_rx) = mpsc::channel(64);

        tokio::spawn(run_wg_loop(Arc::clone(&inner)));
        tokio::spawn(run_rx_loop(inner.clone(), control_tx, discovery_tx));

        Ok((Self { inner }, control_rx, discovery_rx))
    }

    pub fn shared_proxy_endpoint(&self) -> std::net::SocketAddr {
        self.inner.config.wg_proxy_endpoint()
    }

    pub fn underlay_id(&self) -> &str {
        &self.inner.config.name
    }

    pub async fn register_peer_tunnel(&self, peer_id: DeviceId, listen_port: u16) {
        self.inner.peer_ports.lock().await.insert(peer_id, listen_port);
        self.inner.listen_ports.lock().await.insert(listen_port, peer_id);
    }

    pub async fn unregister_peer_tunnel(&self, peer_id: &DeviceId, listen_port: u16) {
        self.inner.peer_ports.lock().await.remove(peer_id);
        self.inner.listen_ports.lock().await.remove(&listen_port);
    }

    pub async fn announce_discovery(&self, payload: &DiscoveryPayload) -> Result<(), AcmeError> {
        let bytes = serde_json::to_vec(payload)?;
        let frame = Frame {
            kind: FrameKind::Discovery,
            source: self.inner.local_device_id,
            destination: None,
            payload: bytes,
        };
        self.send_frame(frame).await
    }

    pub async fn request_control(
        &self,
        peer_id: DeviceId,
        payload: &[u8],
    ) -> Result<Vec<u8>, AcmeError> {
        let request_id = self.inner.next_request_id.fetch_add(1, Ordering::Relaxed);
        let envelope = ControlEnvelope::new(request_id, false, payload);
        let bytes = serde_json::to_vec(&envelope)?;
        let frame = Frame {
            kind: FrameKind::Control,
            source: self.inner.local_device_id,
            destination: Some(peer_id),
            payload: bytes,
        };

        let (tx, rx) = oneshot::channel();
        self.inner.pending.lock().await.insert((peer_id, request_id), tx);
        self.send_frame(frame).await?;

        let timeout = std::time::Duration::from_millis(self.inner.config.control_timeout_ms);
        match tokio::time::timeout(timeout, rx).await {
            Ok(Ok(payload)) => Ok(payload),
            Ok(Err(_)) => Err(AcmeError::ControlClosed),
            Err(_) => {
                self.inner.pending.lock().await.remove(&(peer_id, request_id));
                Err(AcmeError::ControlTimeout {
                    peer_id,
                    request_id,
                })
            }
        }
    }

    pub async fn send_control_response(
        &self,
        peer_id: DeviceId,
        request_id: u64,
        payload: &[u8],
    ) -> Result<(), AcmeError> {
        let envelope = ControlEnvelope::new(request_id, true, payload);
        let bytes = serde_json::to_vec(&envelope)?;
        let frame = Frame {
            kind: FrameKind::Control,
            source: self.inner.local_device_id,
            destination: Some(peer_id),
            payload: bytes,
        };
        self.send_frame(frame).await
    }

    pub async fn shutdown(&self) {
        if let Some(mut processes) = self.inner.processes.lock().await.take() {
            processes.stop().await;
        }
    }

    async fn send_frame(&self, frame: Frame) -> Result<(), AcmeError> {
        let encoded = frame.encode();
        self.inner
            .tx_socket
            .send_to(&encoded, self.inner.config.tx_endpoint())
            .await?;
        Ok(())
    }
}

async fn run_wg_loop(inner: Arc<AcmeRuntimeInner>) {
    let mut buffer = vec![0u8; 64 * 1024];
    loop {
        let Ok((len, source_addr)) = inner.wg_proxy.recv_from(&mut buffer).await else {
            break;
        };
        let listen_port = source_addr.port();
        let Some(peer_id) = inner.listen_ports.lock().await.get(&listen_port).copied() else {
            debug!(listen_port, "dropping ACME proxy packet from unknown local tunnel");
            continue;
        };

        let frame = Frame {
            kind: FrameKind::WgData,
            source: inner.local_device_id,
            destination: Some(peer_id),
            payload: buffer[..len].to_vec(),
        };

        if let Err(err) = inner
            .tx_socket
            .send_to(&frame.encode(), inner.config.tx_endpoint())
            .await
        {
            warn!(peer = %peer_id, "failed to forward WireGuard packet over ACME: {}", err);
        }
    }
}

async fn run_rx_loop(
    inner: Arc<AcmeRuntimeInner>,
    control_tx: mpsc::Sender<IncomingControlRequest>,
    discovery_tx: mpsc::Sender<DiscoveryPayload>,
) {
    let mut buffer = vec![0u8; 64 * 1024];
    loop {
        let Ok((len, _source_addr)) = inner.rx_socket.recv_from(&mut buffer).await else {
            break;
        };

        let frame = match Frame::decode(&buffer[..len]) {
            Ok(frame) => frame,
            Err(err) => {
                debug!("dropping malformed ACME frame: {}", err);
                continue;
            }
        };

        if frame.source == inner.local_device_id {
            continue;
        }
        if let Some(destination) = frame.destination {
            if destination != inner.local_device_id {
                continue;
            }
        }

        match frame.kind {
            FrameKind::WgData => {
                let Some(port) = inner.peer_ports.lock().await.get(&frame.source).copied() else {
                    debug!(peer = %frame.source, "dropping ACME frame for unknown peer tunnel");
                    continue;
                };
                if let Err(err) = inner
                    .wg_proxy
                    .send_to(&frame.payload, std::net::SocketAddr::from((inner.config.proxy_ip, port)))
                    .await
                {
                    warn!(peer = %frame.source, port, "failed to inject ACME packet into WireGuard: {}", err);
                }
            }
            FrameKind::Discovery => match serde_json::from_slice::<DiscoveryPayload>(&frame.payload) {
                Ok(payload) => {
                    let _ = discovery_tx.send(payload).await;
                }
                Err(err) => {
                    debug!(peer = %frame.source, "failed to parse ACME discovery payload: {}", err);
                }
            },
            FrameKind::Control => match serde_json::from_slice::<ControlEnvelope>(&frame.payload) {
                Ok(envelope) => match envelope.payload() {
                    Ok(payload) => {
                        if envelope.is_response {
                            if let Some(waiter) = inner
                                .pending
                                .lock()
                                .await
                                .remove(&(frame.source, envelope.request_id))
                            {
                                let _ = waiter.send(payload);
                            }
                        } else if control_tx
                            .send(IncomingControlRequest {
                                source: frame.source,
                                request_id: envelope.request_id,
                                payload,
                            })
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                    Err(err) => {
                        debug!(peer = %frame.source, "failed to decode ACME control payload: {}", err);
                    }
                },
                Err(err) => {
                    debug!(peer = %frame.source, "failed to parse ACME control payload: {}", err);
                }
            },
        }
    }
}
