//! Error types for the routing module.

use std::io;
use std::path::PathBuf;

#[derive(Debug)]
pub struct RoutingError {
    kind: RoutingErrorKind,
}

#[derive(Debug)]
enum RoutingErrorKind {
    Io(io::Error),
    SpawnFailed { binary: PathBuf, source: io::Error },
    SocketConnect { path: PathBuf, source: io::Error },
    ProtocolError(String),
    NotRunning,
    AlreadyRunning,
}

impl RoutingError {
    pub fn spawn_failed(binary: PathBuf, source: io::Error) -> Self {
        Self {
            kind: RoutingErrorKind::SpawnFailed { binary, source },
        }
    }

    pub fn socket_connect(path: PathBuf, source: io::Error) -> Self {
        Self {
            kind: RoutingErrorKind::SocketConnect { path, source },
        }
    }

    pub fn protocol_error(msg: impl Into<String>) -> Self {
        Self {
            kind: RoutingErrorKind::ProtocolError(msg.into()),
        }
    }

    pub fn not_running() -> Self {
        Self {
            kind: RoutingErrorKind::NotRunning,
        }
    }

    pub fn already_running() -> Self {
        Self {
            kind: RoutingErrorKind::AlreadyRunning,
        }
    }

    pub fn is_io(&self) -> bool {
        matches!(self.kind, RoutingErrorKind::Io(_))
    }

    pub fn is_not_running(&self) -> bool {
        matches!(self.kind, RoutingErrorKind::NotRunning)
    }

    pub fn is_already_running(&self) -> bool {
        matches!(self.kind, RoutingErrorKind::AlreadyRunning)
    }
}

impl std::fmt::Display for RoutingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.kind {
            RoutingErrorKind::Io(e) => write!(f, "routing I/O error: {e}"),
            RoutingErrorKind::SpawnFailed { binary, source } => {
                write!(f, "failed to spawn {}: {source}", binary.display())
            }
            RoutingErrorKind::SocketConnect { path, source } => {
                write!(f, "failed to connect to {}: {source}", path.display())
            }
            RoutingErrorKind::ProtocolError(msg) => write!(f, "babeld protocol error: {msg}"),
            RoutingErrorKind::NotRunning => write!(f, "babeld is not running"),
            RoutingErrorKind::AlreadyRunning => write!(f, "babeld is already running"),
        }
    }
}

impl std::error::Error for RoutingError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match &self.kind {
            RoutingErrorKind::Io(e) => Some(e),
            RoutingErrorKind::SpawnFailed { source, .. } => Some(source),
            RoutingErrorKind::SocketConnect { source, .. } => Some(source),
            RoutingErrorKind::ProtocolError(_)
            | RoutingErrorKind::NotRunning
            | RoutingErrorKind::AlreadyRunning => None,
        }
    }
}

impl From<io::Error> for RoutingError {
    fn from(e: io::Error) -> Self {
        Self {
            kind: RoutingErrorKind::Io(e),
        }
    }
}
