use crate::{Capability, DeviceId};
use base64::Engine;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use thiserror::Error;

const FRAME_MAGIC: &[u8; 4] = b"A2WG";
const FRAME_VERSION: u8 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameKind {
    WgData = 1,
    Discovery = 2,
    Control = 3,
}

impl FrameKind {
    fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::WgData),
            2 => Some(Self::Discovery),
            3 => Some(Self::Control),
            _ => None,
        }
    }
}

#[derive(Clone, Debug)]
pub struct Frame {
    pub kind: FrameKind,
    pub source: DeviceId,
    pub destination: Option<DeviceId>,
    pub payload: Vec<u8>,
}

impl Frame {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + 1 + 1 + 16 + 16 + 4 + self.payload.len());
        out.extend_from_slice(FRAME_MAGIC);
        out.push(FRAME_VERSION);
        out.push(self.kind as u8);
        out.extend_from_slice(self.source.as_bytes());
        match self.destination {
            Some(device_id) => out.extend_from_slice(device_id.as_bytes()),
            None => out.extend_from_slice(&[0u8; 16]),
        }
        out.extend_from_slice(&(self.payload.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.payload);
        out
    }

    pub fn decode(data: &[u8]) -> Result<Self, FrameError> {
        const HEADER_LEN: usize = 4 + 1 + 1 + 16 + 16 + 4;
        if data.len() < HEADER_LEN {
            return Err(FrameError::TooShort);
        }
        if &data[..4] != FRAME_MAGIC {
            return Err(FrameError::InvalidMagic);
        }
        if data[4] != FRAME_VERSION {
            return Err(FrameError::Version(data[4]));
        }
        let kind = FrameKind::from_u8(data[5]).ok_or(FrameError::Kind(data[5]))?;
        let source = DeviceId::from_bytes(data[6..22].try_into().expect("fixed width slice"));
        let raw_destination = &data[22..38];
        let destination = if raw_destination.iter().all(|byte| *byte == 0) {
            None
        } else {
            Some(DeviceId::from_bytes(
                raw_destination.try_into().expect("fixed width slice"),
            ))
        };
        let payload_len =
            u32::from_be_bytes(data[38..42].try_into().expect("fixed width slice")) as usize;
        if data.len() != HEADER_LEN + payload_len {
            return Err(FrameError::Length {
                expected: HEADER_LEN + payload_len,
                actual: data.len(),
            });
        }
        Ok(Self {
            kind,
            source,
            destination,
            payload: data[HEADER_LEN..].to_vec(),
        })
    }
}

#[derive(Debug, Error)]
pub enum FrameError {
    #[error("frame too short")]
    TooShort,
    #[error("invalid magic")]
    InvalidMagic,
    #[error("unsupported frame version: {0}")]
    Version(u8),
    #[error("unsupported frame kind: {0}")]
    Kind(u8),
    #[error("invalid frame length: expected {expected}, got {actual}")]
    Length { expected: usize, actual: usize },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DiscoveryPayload {
    pub device_id: DeviceId,
    pub node_name: Option<String>,
    pub capabilities: Vec<String>,
    pub underlay_id: String,
}

impl DiscoveryPayload {
    pub fn new(
        device_id: DeviceId,
        node_name: Option<String>,
        capabilities: &HashSet<Capability>,
        underlay_id: String,
    ) -> Self {
        let mut capability_list = capabilities
            .iter()
            .map(Capability::as_str)
            .map(str::to_string)
            .collect::<Vec<_>>();
        capability_list.sort();
        Self {
            device_id,
            node_name,
            capabilities: capability_list,
            underlay_id,
        }
    }

    pub fn capabilities(&self) -> HashSet<Capability> {
        self.capabilities
            .iter()
            .filter_map(|capability| Capability::from_str(capability))
            .collect()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ControlEnvelope {
    pub request_id: u64,
    pub is_response: bool,
    pub payload_b64: String,
}

impl ControlEnvelope {
    pub fn new(request_id: u64, is_response: bool, payload: &[u8]) -> Self {
        Self {
            request_id,
            is_response,
            payload_b64: base64::engine::general_purpose::STANDARD.encode(payload),
        }
    }

    pub fn payload(&self) -> Result<Vec<u8>, base64::DecodeError> {
        base64::engine::general_purpose::STANDARD.decode(&self.payload_b64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_roundtrip() {
        let frame = Frame {
            kind: FrameKind::WgData,
            source: DeviceId::from_bytes([1u8; 16]),
            destination: Some(DeviceId::from_bytes([2u8; 16])),
            payload: vec![1, 2, 3, 4],
        };
        let encoded = frame.encode();
        let decoded = Frame::decode(&encoded).expect("frame should decode");
        assert_eq!(decoded.kind, FrameKind::WgData);
        assert_eq!(decoded.source, frame.source);
        assert_eq!(decoded.destination, frame.destination);
        assert_eq!(decoded.payload, frame.payload);
    }
}
