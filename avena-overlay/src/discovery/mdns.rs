//! mDNS-based peer discovery for local networks.
//!
//! Advertises a device's WireGuard endpoint and capabilities, and listens for
//! peers broadcasting the same service type.

use crate::DeviceId;
use mdns_sd::{ServiceDaemon, ServiceEvent, ServiceInfo};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::sync::mpsc;
use tracing::{debug, warn};

use super::{Capability, DiscoveredPeer, DiscoveryError, DiscoverySource, LocalAnnouncement};

const SERVICE_TYPE: &str = "_avena._udp.local.";
const TXT_AVENA_ID: &str = "avena-id";
const TXT_WG_ENDPOINT: &str = "wg-endpoint";
const TXT_CAPABILITIES: &str = "cap";

#[expect(
    missing_debug_implementations,
    reason = "ServiceDaemon does not implement Debug"
)]
pub struct MdnsDiscovery {
    daemon: ServiceDaemon,
    shutdown: AtomicBool,
}

impl MdnsDiscovery {
    pub fn new(interfaces: &[String]) -> Result<Self, DiscoveryError> {
        let daemon = ServiceDaemon::new().map_err(|e| DiscoveryError::Mdns(e.to_string()))?;

        for if_name in interfaces {
            daemon.enable_interface(if_name).map_err(|e| {
                DiscoveryError::Mdns(format!("failed to bind to interface {}: {}", if_name, e))
            })?;
            debug!(interface = if_name, "mDNS bound to interface");
        }

        if interfaces.is_empty() {
            debug!("mDNS using system default interfaces");
        }

        Ok(Self {
            daemon,
            shutdown: AtomicBool::new(false),
        })
    }

    pub async fn advertise(&self, announcement: &LocalAnnouncement) -> Result<(), DiscoveryError> {
        let base_name = announcement.device_id.to_base32();
        let instance_name = match announcement.interface_suffix {
            Some(suffix) => format!("{}-{}", base_name, suffix),
            None => base_name.clone(),
        };
        let hostname = format!("{}.local.", instance_name);

        let mut properties = vec![
            (TXT_AVENA_ID.to_string(), announcement.device_id.to_base32()),
            (
                TXT_WG_ENDPOINT.to_string(),
                announcement.wg_endpoint.to_string(),
            ),
        ];

        if !announcement.capabilities.is_empty() {
            let caps: Vec<&str> = announcement
                .capabilities
                .iter()
                .map(Capability::as_str)
                .collect();
            properties.push((TXT_CAPABILITIES.to_string(), caps.join(",")));
        }

        let ip = announcement.wg_endpoint.ip();

        let service_info = ServiceInfo::new(
            SERVICE_TYPE,
            &instance_name,
            &hostname,
            ip,
            announcement.wg_endpoint.port(),
            properties.as_slice(),
        )
        .map_err(|e| DiscoveryError::Mdns(e.to_string()))?;

        self.daemon
            .register(service_info)
            .map_err(|e| DiscoveryError::Mdns(e.to_string()))?;

        debug!(
            device_id = %announcement.device_id,
            endpoint = %announcement.wg_endpoint,
            instance_name = %instance_name,
            "mDNS service registered"
        );

        Ok(())
    }

    pub fn browse(&self) -> Result<mpsc::Receiver<DiscoveredPeer>, DiscoveryError> {
        let receiver = self
            .daemon
            .browse(SERVICE_TYPE)
            .map_err(|e| DiscoveryError::Mdns(e.to_string()))?;

        let (tx, rx) = mpsc::channel(64);

        std::thread::spawn(move || {
            Self::browse_loop(receiver, tx);
        });

        Ok(rx)
    }

    fn browse_loop(receiver: mdns_sd::Receiver<ServiceEvent>, tx: mpsc::Sender<DiscoveredPeer>) {
        while let Ok(event) = receiver.recv() {
            match event {
                ServiceEvent::ServiceResolved(info) => {
                    if let Some(peer) = Self::parse_service_info(&info) {
                        if tx.blocking_send(peer).is_err() {
                            break;
                        }
                    }
                }
                ServiceEvent::ServiceRemoved(_, _) => {}
                _ => {}
            }
        }
    }

    fn parse_service_info(info: &ServiceInfo) -> Option<DiscoveredPeer> {
        let properties = info.get_properties();

        let device_id_str = properties.get(TXT_AVENA_ID)?;
        let device_id = DeviceId::from_base32(device_id_str.val_str()).ok()?;

        let endpoint = if let Some(wg_endpoint) = properties.get(TXT_WG_ENDPOINT) {
            wg_endpoint.val_str().parse::<SocketAddr>().ok()?
        } else {
            let addrs = info.get_addresses();
            let ip = addrs.iter().next()?;
            SocketAddr::new((*ip).into(), info.get_port())
        };

        let capabilities = properties
            .get(TXT_CAPABILITIES)
            .map(|prop| {
                prop.val_str()
                    .split(',')
                    .filter_map(Capability::from_str)
                    .collect()
            })
            .unwrap_or_default();

        debug!(
            device_id = %device_id,
            endpoint = %endpoint,
            "discovered peer via mDNS"
        );

        Some(DiscoveredPeer::new(
            device_id,
            endpoint,
            capabilities,
            DiscoverySource::Mdns,
        ))
    }

    pub fn stop_browse(&self) {
        if let Err(e) = self.daemon.stop_browse(SERVICE_TYPE) {
            warn!("failed to stop mDNS browse: {}", e);
        }
    }

    pub fn shutdown(&self) {
        if self.shutdown.swap(true, Ordering::SeqCst) {
            return;
        }
        self.stop_browse();
        // mdns_sd shutdown is synchronous; ignore errors on teardown.
        let _ = self.daemon.shutdown();
    }

    pub fn unregister(&self, device_id: &DeviceId) -> Result<(), DiscoveryError> {
        let instance_name = device_id.to_base32();
        let full_name = format!("{}.{}", instance_name, SERVICE_TYPE);

        self.daemon
            .unregister(&full_name)
            .map_err(|e| DiscoveryError::Mdns(e.to_string()))?;

        Ok(())
    }
}

impl Drop for MdnsDiscovery {
    fn drop(&mut self) {
        // Prefer an explicit call to `shutdown()` while the runtime is still up,
        // but keep Drop as a best-effort fallback.
        self.shutdown();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn service_type_format() {
        assert_eq!(SERVICE_TYPE, "_avena._udp.local.");
    }

    #[test]
    fn capability_serialization_for_txt() {
        let caps: Vec<&str> = vec![Capability::Relay, Capability::Gateway]
            .iter()
            .map(Capability::as_str)
            .collect();
        let txt = caps.join(",");
        assert_eq!(txt, "relay,gateway");
    }

    #[test]
    fn capability_parsing_from_txt() {
        let txt = "relay,gateway,workload-spawn";
        let caps: HashSet<Capability> = txt.split(',').filter_map(Capability::from_str).collect();

        assert_eq!(caps.len(), 3);
        assert!(caps.contains(&Capability::Relay));
        assert!(caps.contains(&Capability::Gateway));
        assert!(caps.contains(&Capability::WorkloadSpawn));
    }
}
