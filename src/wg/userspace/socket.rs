use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

const SOCKET_DIR: &str = "/var/run/wireguard";
const SOCKET_TIMEOUT_SECS: u64 = 3;

pub fn socket_path(ifname: &str) -> PathBuf {
    PathBuf::from(SOCKET_DIR).join(format!("{}.sock", ifname))
}

pub struct WgSocket {
    stream: UnixStream,
}

impl WgSocket {
    pub fn connect(ifname: &str) -> io::Result<Self> {
        Self::connect_path(&socket_path(ifname))
    }

    pub fn connect_path(path: &Path) -> io::Result<Self> {
        let stream = UnixStream::connect(path)?;
        stream.set_read_timeout(Some(Duration::from_secs(SOCKET_TIMEOUT_SECS)))?;
        Ok(Self { stream })
    }

    pub fn send(&mut self, data: &[u8]) -> io::Result<()> {
        self.stream.write_all(data)
    }

    pub fn into_reader(self) -> impl Read {
        self.stream
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn socket_path_format() {
        let path = socket_path("wg0");
        assert_eq!(path, PathBuf::from("/var/run/wireguard/wg0.sock"));
    }
}
