//! Daemon-facing types such as runtime configuration and peer state.

mod config;
mod peer_state;

pub use config::{
    AvenadConfig, ConfigError, DiscoveryConfig, RoutingConfig, TelemetryConfig, TunnelMode,
};
pub use peer_state::PeerState;
