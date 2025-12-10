//! Shared error types returned by WireGuard backends.

use std::io;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum WgError {
    #[error("interface creation failed: {0}")]
    InterfaceCreation(String),

    #[error("interface not found: {0}")]
    InterfaceNotFound(String),

    #[error("peer not found")]
    PeerNotFound,

    #[error("invalid key: {0}")]
    InvalidKey(String),

    #[error("UAPI protocol error: {0}")]
    UapiError(String),

    #[error("socket error: {0}")]
    SocketError(String),

    #[error("netlink error: {0}")]
    NetlinkError(String),

    #[error("permission denied: {0}")]
    PermissionDenied(String),

    #[error("io error: {0}")]
    Io(#[from] io::Error),

    #[error("process spawn error: {0}")]
    ProcessError(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_display() {
        let err = WgError::InterfaceCreation("test".into());
        assert!(err.to_string().contains("test"));

        let err = WgError::PeerNotFound;
        assert!(err.to_string().contains("not found"));

        let err = WgError::PermissionDenied("CAP_NET_ADMIN required".into());
        assert!(err.to_string().contains("CAP_NET_ADMIN"));

        let err = WgError::InvalidKey("bad hex".into());
        assert!(err.to_string().contains("bad hex"));
    }

    #[test]
    fn io_error_conversion() {
        let io_err = io::Error::new(io::ErrorKind::NotFound, "file not found");
        let wg_err: WgError = io_err.into();
        assert!(matches!(wg_err, WgError::Io(_)));
    }
}
