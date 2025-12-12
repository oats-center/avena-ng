//! Babeld (RFC 8966) controller for dynamic mesh routing.
//!
//! This module spawns and controls babeld as a subprocess, communicating
//! via its Unix socket protocol to manage routing.

use std::net::Ipv6Addr;
use std::path::PathBuf;
use std::time::Duration;

use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::UnixStream;
use tokio::process::{Child, Command};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use super::error::RoutingError;

/// Configuration for the babeld subprocess.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BabeldConfig {
    /// Path to the control socket.
    #[serde(default = "default_socket_path")]
    pub socket_path: PathBuf,

    /// Path to the babeld binary.
    #[serde(default = "default_binary_path")]
    pub binary_path: PathBuf,

    /// Hello interval in milliseconds.
    #[serde(default = "default_hello_interval")]
    pub hello_interval: u16,

    /// Update interval in milliseconds.
    #[serde(default = "default_update_interval")]
    pub update_interval: u16,
}

fn default_socket_path() -> PathBuf {
    PathBuf::from("/run/avena/babel.sock")
}

fn default_binary_path() -> PathBuf {
    PathBuf::from("/usr/sbin/babeld")
}

const fn default_hello_interval() -> u16 {
    4000
}

const fn default_update_interval() -> u16 {
    16000
}

impl Default for BabeldConfig {
    fn default() -> Self {
        Self {
            socket_path: default_socket_path(),
            binary_path: default_binary_path(),
            hello_interval: default_hello_interval(),
            update_interval: default_update_interval(),
        }
    }
}

/// Parsed babeld interface info.
#[derive(Clone, Debug)]
pub struct BabelInterface {
    pub name: String,
    pub up: bool,
    pub ipv6: Option<Ipv6Addr>,
}

/// Parsed babeld neighbour info.
#[derive(Clone, Debug)]
pub struct BabelNeighbour {
    pub id: String,
    pub address: Ipv6Addr,
    pub interface: String,
    pub rxcost: u16,
    pub txcost: u16,
    pub reach: u16,
}

/// Parsed babeld route info.
#[derive(Clone, Debug)]
pub struct BabelRoute {
    pub id: String,
    pub prefix: IpNet,
    pub installed: bool,
    pub metric: u16,
    pub via: Ipv6Addr,
    pub interface: String,
}

/// Parsed babeld xroute (local export) info.
#[derive(Clone, Debug)]
pub struct BabelXroute {
    pub prefix: IpNet,
    pub metric: u16,
}

/// Full dump of babeld state.
#[derive(Clone, Debug, Default)]
pub struct BabelDump {
    pub interfaces: Vec<BabelInterface>,
    pub neighbours: Vec<BabelNeighbour>,
    pub routes: Vec<BabelRoute>,
    pub xroutes: Vec<BabelXroute>,
}

/// Events from babeld monitor stream.
#[derive(Clone, Debug)]
pub enum BabelEvent {
    RouteAdded(BabelRoute),
    RouteChanged(BabelRoute),
    RouteRemoved { id: String, prefix: IpNet },
    NeighbourAdded(BabelNeighbour),
    NeighbourChanged(BabelNeighbour),
    NeighbourRemoved { id: String },
    InterfaceUp { name: String },
    InterfaceDown { name: String },
}

/// Controller for the babeld subprocess.
pub struct BabeldController {
    config: BabeldConfig,
    process: Option<Child>,
    reader: Option<BufReader<OwnedReadHalf>>,
    writer: Option<OwnedWriteHalf>,
}

impl std::fmt::Debug for BabeldController {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BabeldController")
            .field("config", &self.config)
            .field("process", &self.process)
            .field("connected", &self.reader.is_some())
            .finish()
    }
}

impl BabeldController {
    pub fn new(config: BabeldConfig) -> Self {
        Self {
            config,
            process: None,
            reader: None,
            writer: None,
        }
    }

    /// Start babeld with the given interfaces.
    pub async fn start(&mut self, interfaces: &[&str]) -> Result<(), RoutingError> {
        if self.process.is_some() {
            return Err(RoutingError::already_running());
        }

        // Ensure socket directory exists
        if let Some(parent) = self.config.socket_path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }

        // Remove stale socket if present
        let _ = tokio::fs::remove_file(&self.config.socket_path).await;

        let mut cmd = Command::new(&self.config.binary_path);
        // -G: read-write control socket
        // -d 1: debug level (log route changes)
        // -h: hello interval for wireless interfaces (ms -> s conversion)
        // -H: hello interval for wired interfaces (ms -> s conversion)
        let hello_secs = (self.config.hello_interval / 1000).max(1);

        cmd.arg("-G")
            .arg(&self.config.socket_path)
            .arg("-d")
            .arg("1")
            .arg("-h")
            .arg(hello_secs.to_string())
            .arg("-H")
            .arg(hello_secs.to_string());

        for iface in interfaces {
            cmd.arg(*iface);
        }

        info!(
            binary = %self.config.binary_path.display(),
            socket = %self.config.socket_path.display(),
            ?interfaces,
            "starting babeld"
        );

        let child = cmd.spawn().map_err(|e| {
            RoutingError::spawn_failed(self.config.binary_path.clone(), e)
        })?;

        self.process = Some(child);

        // Wait for socket to appear
        self.wait_for_socket().await?;

        // Connect to control socket
        self.connect().await?;

        Ok(())
    }

    async fn wait_for_socket(&self) -> Result<(), RoutingError> {
        let max_attempts = 50;
        let delay = Duration::from_millis(100);

        for _ in 0..max_attempts {
            if self.config.socket_path.exists() {
                return Ok(());
            }
            tokio::time::sleep(delay).await;
        }

        Err(RoutingError::protocol_error(format!(
            "socket {} did not appear within {}ms",
            self.config.socket_path.display(),
            max_attempts * 100
        )))
    }

    async fn connect(&mut self) -> Result<(), RoutingError> {
        let stream = UnixStream::connect(&self.config.socket_path)
            .await
            .map_err(|e| RoutingError::socket_connect(self.config.socket_path.clone(), e))?;

        let (read_half, write_half) = stream.into_split();
        let mut reader = BufReader::new(read_half);
        let mut line = String::new();

        // Expect "BABEL 1.0" banner
        reader.read_line(&mut line).await?;
        if !line.starts_with("BABEL") {
            return Err(RoutingError::protocol_error(format!(
                "unexpected banner: {line}"
            )));
        }

        // Read until "ok"
        loop {
            line.clear();
            reader.read_line(&mut line).await?;
            let trimmed = line.trim();
            debug!(line = trimmed, "babeld banner");
            if trimmed == "ok" {
                break;
            }
        }

        self.reader = Some(reader);
        self.writer = Some(write_half);
        info!("connected to babeld control socket");
        Ok(())
    }

    /// Stop the babeld process.
    pub async fn stop(&mut self) -> Result<(), RoutingError> {
        // Send quit command if connected
        if let Some(ref mut writer) = self.writer {
            let _ = writer.write_all(b"quit\n").await;
        }
        self.reader = None;
        self.writer = None;

        if let Some(ref mut child) = self.process {
            // Give it a moment to exit gracefully
            tokio::time::sleep(Duration::from_millis(100)).await;

            // Then kill if still running
            let _ = child.kill().await;
            let _ = child.wait().await;
            info!("babeld stopped");
        }

        self.process = None;

        // Clean up socket
        let _ = tokio::fs::remove_file(&self.config.socket_path).await;

        Ok(())
    }

    /// Add an interface to the babel routing domain.
    pub async fn add_interface(&mut self, name: &str) -> Result<(), RoutingError> {
        self.send_command(&format!("interface {name}\n")).await?;
        self.read_until_ok().await
    }

    /// Remove an interface from the babel routing domain.
    pub async fn flush_interface(&mut self, name: &str) -> Result<(), RoutingError> {
        self.send_command(&format!("flush interface {name}\n")).await?;
        self.read_until_ok().await
    }

    /// Dump current babel state.
    pub async fn dump(&mut self) -> Result<BabelDump, RoutingError> {
        self.send_command("dump\n").await?;

        let reader = self.reader.as_mut().ok_or_else(RoutingError::not_running)?;
        let mut dump = BabelDump::default();
        let mut line = String::new();

        loop {
            line.clear();
            reader.read_line(&mut line).await?;
            let trimmed = line.trim();

            if trimmed == "ok" {
                break;
            }

            if let Some(parsed) = parse_babel_line(trimmed) {
                match parsed {
                    ParsedLine::Interface(iface) => dump.interfaces.push(iface),
                    ParsedLine::Neighbour(neigh) => dump.neighbours.push(neigh),
                    ParsedLine::Route(route) => dump.routes.push(route),
                    ParsedLine::Xroute(xroute) => dump.xroutes.push(xroute),
                }
            }
        }

        Ok(dump)
    }

    /// Subscribe to route/neighbour changes. Returns a receiver for events.
    pub async fn monitor(&mut self) -> Result<mpsc::Receiver<BabelEvent>, RoutingError> {
        self.send_command("monitor\n").await?;

        let reader = self
            .reader
            .take()
            .ok_or_else(RoutingError::not_running)?;

        self.writer = None; // Close writer too since monitor takes over

        let (tx, rx) = mpsc::channel(64);

        tokio::spawn(async move {
            let mut reader = reader;
            let mut line = String::new();

            loop {
                line.clear();
                match reader.read_line(&mut line).await {
                    Ok(0) => break, // EOF
                    Ok(_) => {
                        if let Some(event) = parse_event_line(line.trim()) {
                            if tx.send(event).await.is_err() {
                                break;
                            }
                        }
                    }
                    Err(e) => {
                        warn!(error = %e, "babeld monitor read error");
                        break;
                    }
                }
            }
        });

        Ok(rx)
    }

    async fn send_command(&mut self, cmd: &str) -> Result<(), RoutingError> {
        let writer = self.writer.as_mut().ok_or_else(RoutingError::not_running)?;
        writer.write_all(cmd.as_bytes()).await?;
        Ok(())
    }

    async fn read_until_ok(&mut self) -> Result<(), RoutingError> {
        let reader = self.reader.as_mut().ok_or_else(RoutingError::not_running)?;
        let mut line = String::new();

        loop {
            line.clear();
            reader.read_line(&mut line).await?;
            let trimmed = line.trim();
            if trimmed == "ok" {
                return Ok(());
            }
            if trimmed.starts_with("bad") || trimmed.starts_with("no") {
                return Err(RoutingError::protocol_error(trimmed.to_string()));
            }
        }
    }

    /// Check if babeld is running.
    pub fn is_running(&self) -> bool {
        self.process.is_some()
    }
}

impl Drop for BabeldController {
    fn drop(&mut self) {
        if let Some(ref mut child) = self.process {
            // Best-effort kill on drop
            let _ = child.start_kill();
        }
    }
}

enum ParsedLine {
    Interface(BabelInterface),
    Neighbour(BabelNeighbour),
    Route(BabelRoute),
    Xroute(BabelXroute),
}

fn parse_babel_line(line: &str) -> Option<ParsedLine> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 3 {
        return None;
    }

    let action = parts[0];
    let kind = parts[1];

    if action != "add" && action != "change" {
        return None;
    }

    match kind {
        "interface" => parse_interface(&parts[2..]).map(ParsedLine::Interface),
        "neighbour" => parse_neighbour(&parts[2..]).map(ParsedLine::Neighbour),
        "route" => parse_route(&parts[2..]).map(ParsedLine::Route),
        "xroute" => parse_xroute(&parts[2..]).map(ParsedLine::Xroute),
        _ => None,
    }
}

fn parse_event_line(line: &str) -> Option<BabelEvent> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 3 {
        return None;
    }

    let action = parts[0];
    let kind = parts[1];

    match (action, kind) {
        ("add", "route") => parse_route(&parts[2..]).map(BabelEvent::RouteAdded),
        ("change", "route") => parse_route(&parts[2..]).map(BabelEvent::RouteChanged),
        ("flush", "route") => parse_flush_route(&parts[2..]),
        ("add", "neighbour") => parse_neighbour(&parts[2..]).map(BabelEvent::NeighbourAdded),
        ("change", "neighbour") => parse_neighbour(&parts[2..]).map(BabelEvent::NeighbourChanged),
        ("flush", "neighbour") => parse_flush_neighbour(&parts[2..]),
        ("add", "interface") => {
            let iface = parse_interface(&parts[2..])?;
            if iface.up {
                Some(BabelEvent::InterfaceUp { name: iface.name })
            } else {
                Some(BabelEvent::InterfaceDown { name: iface.name })
            }
        }
        ("change", "interface") => {
            let iface = parse_interface(&parts[2..])?;
            if iface.up {
                Some(BabelEvent::InterfaceUp { name: iface.name })
            } else {
                Some(BabelEvent::InterfaceDown { name: iface.name })
            }
        }
        _ => None,
    }
}

fn parse_interface(parts: &[&str]) -> Option<BabelInterface> {
    if parts.is_empty() {
        return None;
    }

    let name = parts[0].to_string();
    let mut up = false;
    let mut ipv6 = None;

    let mut i = 1;
    while i < parts.len() {
        match parts[i] {
            "up" if i + 1 < parts.len() => {
                up = parts[i + 1] == "true";
                i += 2;
            }
            "ipv6" if i + 1 < parts.len() => {
                // May contain %interface suffix, strip it
                let addr_str = parts[i + 1].split('%').next()?;
                ipv6 = addr_str.parse().ok();
                i += 2;
            }
            _ => i += 1,
        }
    }

    Some(BabelInterface { name, up, ipv6 })
}

fn parse_neighbour(parts: &[&str]) -> Option<BabelNeighbour> {
    if parts.is_empty() {
        return None;
    }

    let id = parts[0].to_string();
    let mut address = None;
    let mut interface = String::new();
    let mut rxcost = 0u16;
    let mut txcost = 0u16;
    let mut reach = 0u16;

    let mut i = 1;
    while i < parts.len() {
        match parts[i] {
            "address" if i + 1 < parts.len() => {
                let addr_str = parts[i + 1].split('%').next()?;
                address = addr_str.parse().ok();
                i += 2;
            }
            "if" if i + 1 < parts.len() => {
                interface = parts[i + 1].to_string();
                i += 2;
            }
            "rxcost" if i + 1 < parts.len() => {
                rxcost = parts[i + 1].parse().unwrap_or(0);
                i += 2;
            }
            "txcost" if i + 1 < parts.len() => {
                txcost = parts[i + 1].parse().unwrap_or(0);
                i += 2;
            }
            "reach" if i + 1 < parts.len() => {
                reach = u16::from_str_radix(parts[i + 1], 16).unwrap_or(0);
                i += 2;
            }
            _ => i += 1,
        }
    }

    Some(BabelNeighbour {
        id,
        address: address?,
        interface,
        rxcost,
        txcost,
        reach,
    })
}

fn parse_route(parts: &[&str]) -> Option<BabelRoute> {
    if parts.is_empty() {
        return None;
    }

    let id = parts[0].to_string();
    let mut prefix = None;
    let mut installed = false;
    let mut metric = 0u16;
    let mut via = None;
    let mut interface = String::new();

    let mut i = 1;
    while i < parts.len() {
        match parts[i] {
            "prefix" if i + 1 < parts.len() => {
                prefix = parts[i + 1].parse().ok();
                i += 2;
            }
            "installed" if i + 1 < parts.len() => {
                installed = parts[i + 1] == "yes";
                i += 2;
            }
            "metric" if i + 1 < parts.len() => {
                metric = parts[i + 1].parse().unwrap_or(0);
                i += 2;
            }
            "via" if i + 1 < parts.len() => {
                let addr_str = parts[i + 1].split('%').next()?;
                via = addr_str.parse().ok();
                i += 2;
            }
            "if" if i + 1 < parts.len() => {
                interface = parts[i + 1].to_string();
                i += 2;
            }
            _ => i += 1,
        }
    }

    Some(BabelRoute {
        id,
        prefix: prefix?,
        installed,
        metric,
        via: via?,
        interface,
    })
}

fn parse_xroute(parts: &[&str]) -> Option<BabelXroute> {
    let mut prefix = None;
    let mut metric = 0u16;

    let mut i = 0;
    while i < parts.len() {
        match parts[i] {
            "prefix" if i + 1 < parts.len() => {
                prefix = parts[i + 1].parse().ok();
                i += 2;
            }
            "metric" if i + 1 < parts.len() => {
                metric = parts[i + 1].parse().unwrap_or(0);
                i += 2;
            }
            _ => i += 1,
        }
    }

    Some(BabelXroute {
        prefix: prefix?,
        metric,
    })
}

fn parse_flush_route(parts: &[&str]) -> Option<BabelEvent> {
    if parts.is_empty() {
        return None;
    }

    let id = parts[0].to_string();
    let mut prefix = None;

    let mut i = 1;
    while i < parts.len() {
        if parts[i] == "prefix" && i + 1 < parts.len() {
            prefix = parts[i + 1].parse().ok();
            break;
        }
        i += 1;
    }

    Some(BabelEvent::RouteRemoved { id, prefix: prefix? })
}

fn parse_flush_neighbour(parts: &[&str]) -> Option<BabelEvent> {
    if parts.is_empty() {
        return None;
    }

    Some(BabelEvent::NeighbourRemoved {
        id: parts[0].to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_interface_line() {
        let line = "add interface avena0 up true ipv6 fe80::1%avena0";
        let parsed = parse_babel_line(line);
        assert!(matches!(parsed, Some(ParsedLine::Interface(_))));

        if let Some(ParsedLine::Interface(iface)) = parsed {
            assert_eq!(iface.name, "avena0");
            assert!(iface.up);
            assert_eq!(iface.ipv6, Some("fe80::1".parse().unwrap()));
        }
    }

    #[test]
    fn parse_neighbour_line() {
        let line = "add neighbour 12ab34cd address fe80::2 if avena0 reach ffff rxcost 256 txcost 256";
        let parsed = parse_babel_line(line);
        assert!(matches!(parsed, Some(ParsedLine::Neighbour(_))));

        if let Some(ParsedLine::Neighbour(neigh)) = parsed {
            assert_eq!(neigh.id, "12ab34cd");
            assert_eq!(neigh.address, "fe80::2".parse::<Ipv6Addr>().unwrap());
            assert_eq!(neigh.interface, "avena0");
            assert_eq!(neigh.rxcost, 256);
            assert_eq!(neigh.txcost, 256);
            assert_eq!(neigh.reach, 0xffff);
        }
    }

    #[test]
    fn parse_route_line() {
        let line = "add route 12ab34cd prefix fd00:a0e0:a000::1/128 installed yes metric 256 via fe80::2 if avena0";
        let parsed = parse_babel_line(line);
        assert!(matches!(parsed, Some(ParsedLine::Route(_))));

        if let Some(ParsedLine::Route(route)) = parsed {
            assert_eq!(route.id, "12ab34cd");
            assert_eq!(route.prefix, "fd00:a0e0:a000::1/128".parse::<IpNet>().unwrap());
            assert!(route.installed);
            assert_eq!(route.metric, 256);
            assert_eq!(route.via, "fe80::2".parse::<Ipv6Addr>().unwrap());
            assert_eq!(route.interface, "avena0");
        }
    }

    #[test]
    fn parse_xroute_line() {
        let line = "add xroute prefix fd00:a0e0:a000::/48 metric 0";
        let parsed = parse_babel_line(line);
        assert!(matches!(parsed, Some(ParsedLine::Xroute(_))));

        if let Some(ParsedLine::Xroute(xroute)) = parsed {
            assert_eq!(xroute.prefix, "fd00:a0e0:a000::/48".parse::<IpNet>().unwrap());
            assert_eq!(xroute.metric, 0);
        }
    }
}
