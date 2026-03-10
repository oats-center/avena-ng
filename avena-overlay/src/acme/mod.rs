mod frame;
mod process;
mod proxy;

pub use frame::{ControlEnvelope, DiscoveryPayload, Frame, FrameError, FrameKind};
pub use proxy::{AcmeRuntime, IncomingControlRequest};

use crate::DeviceId;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AcmeError {
    #[error("acme configuration error: {0}")]
    Config(String),
    #[error("acme io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("acme json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("acme frame error: {0}")]
    Frame(#[from] FrameError),
    #[error("acme helper process error: {0}")]
    Process(String),
    #[error("acme control channel closed")]
    ControlClosed,
    #[error("acme control timeout waiting for peer {peer_id} request {request_id}")]
    ControlTimeout { peer_id: DeviceId, request_id: u64 },
}
