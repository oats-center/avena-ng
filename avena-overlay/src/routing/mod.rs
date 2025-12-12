//! Routing protocol integration for multi-hop mesh networking.
//!
//! This module provides an abstraction for dynamic routing via babeld,
//! the reference Babel (RFC 8966) implementation.

pub mod babeld;
pub mod error;

pub use babeld::{BabeldConfig, BabeldController};
pub use error::RoutingError;
