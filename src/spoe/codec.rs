//! The SPOP wire format (HAProxy `doc/SPOE.txt`, protocol 2.0, the version HAProxy 3.1's rewritten
//! SPOE speaks).
//!
//! A frame on the wire is `[length:u32 BE][type:u8][flags:u32 BE][stream-id:varint]
//! [frame-id:varint][payload]`, the length counting everything after itself. Payloads are made of
//! typed data, key/value lists, messages (in NOTIFY) and actions (in ACK). Fragmentation is gone
//! in 2.0, so every frame carries FIN.

use std::net::{Ipv4Addr, Ipv6Addr};

use thiserror::Error;

pub const SPOP_VERSION: &str = "2.0";

pub const FRAME_HAPROXY_HELLO: u8 = 1;
pub const FRAME_HAPROXY_DISCONNECT: u8 = 2;
pub const FRAME_NOTIFY: u8 = 3;
pub const FRAME_AGENT_HELLO: u8 = 101;
pub const FRAME_AGENT_DISCONNECT: u8 = 102;
pub const FRAME_ACK: u8 = 103;

pub const FLAG_FIN: u32 = 0x0000_0001;
pub const FLAG_ABORT: u32 = 0x0000_0002;

const ACTION_SET_VAR: u8 = 1;

/// Status codes of a DISCONNECT frame, from `doc/SPOE.txt`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum DisconnectStatus {
    Normal = 0,
    Io = 1,
    Timeout = 2,
    FrameTooBig = 3,
    Invalid = 4,
    NoVersion = 5,
    NoFrameSize = 6,
    NoCapability = 7,
    BadVersion = 8,
    BadFrameSize = 9,
    Unknown = 99,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CodecError {
    #[error("frame ends early")]
    Truncated,
    #[error("varint is longer than ten bytes")]
    VarintOverflow,
    #[error("unknown data type {0}")]
    UnknownType(u8),
    #[error("string is not UTF-8")]
    NotUtf8,
    #[error("frame is shorter than its header")]
    ShortFrame,
}

/// HAProxy's varint: one byte below 240; above, the low four bits ride in the first byte (flagged
/// 0xF0) and seven bits per continuation byte follow, high bit set on all but the last.
pub fn encode_varint(out: &mut Vec<u8>, mut value: u64) {
    if value < 240 {
        out.push(value as u8);
        return;
    }
    out.push((value as u8) | 240);
    value = (value - 240) >> 4;
    while value >= 128 {
        out.push((value as u8) | 128);
        value = (value - 128) >> 7;
    }
    out.push(value as u8);
}

/// Typed data as SPOP carries it. Only what the agent reads and writes; IP addresses decode so an
/// argument such as `src` is not refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TypedData {
    Null,
    Bool(bool),
    Int32(i32),
    Uint32(u32),
    Int64(i64),
    Uint64(u64),
    Ipv4(Ipv4Addr),
    Ipv6(Ipv6Addr),
    String(String),
    Binary(Vec<u8>),
}

impl TypedData {
    pub fn as_str(&self) -> Option<&str> {
        match self {
            TypedData::String(text) => Some(text),
            TypedData::Binary(bytes) => std::str::from_utf8(bytes).ok(),
            _ => None,
        }
    }

    /// Any non-negative integer, whatever its declared width.
    pub fn as_u64(&self) -> Option<u64> {
        match *self {
            TypedData::Int32(value) => u64::try_from(value).ok(),
            TypedData::Uint32(value) => Some(u64::from(value)),
            TypedData::Int64(value) => u64::try_from(value).ok(),
            TypedData::Uint64(value) => Some(value),
            TypedData::String(ref text) => text.trim().parse().ok(),
            _ => None,
        }
    }

    pub fn encode(&self, out: &mut Vec<u8>) {
        match self {
            TypedData::Null => out.push(0),
            TypedData::Bool(value) => out.push(1 | if *value { 0x10 } else { 0 }),
            TypedData::Int32(value) => {
                out.push(2);
                encode_varint(out, *value as i64 as u64);
            }
            TypedData::Uint32(value) => {
                out.push(3);
                encode_varint(out, u64::from(*value));
            }
            TypedData::Int64(value) => {
                out.push(4);
                encode_varint(out, *value as u64);
            }
            TypedData::Uint64(value) => {
                out.push(5);
                encode_varint(out, *value);
            }
            TypedData::Ipv4(address) => {
                out.push(6);
                out.extend_from_slice(&address.octets());
            }
            TypedData::Ipv6(address) => {
                out.push(7);
                out.extend_from_slice(&address.octets());
            }
            TypedData::String(text) => {
                out.push(8);
                encode_bytes(out, text.as_bytes());
            }
            TypedData::Binary(bytes) => {
                out.push(9);
                encode_bytes(out, bytes);
            }
        }
    }
}

fn encode_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    encode_varint(out, bytes.len() as u64);
    out.extend_from_slice(bytes);
}

/// A read cursor over one frame.
pub struct Reader<'frame> {
    bytes: &'frame [u8],
}

impl<'frame> Reader<'frame> {
    pub fn new(bytes: &'frame [u8]) -> Self {
        Self { bytes }
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    fn take(&mut self, count: usize) -> Result<&'frame [u8], CodecError> {
        if self.bytes.len() < count {
            return Err(CodecError::Truncated);
        }
        let (head, rest) = self.bytes.split_at(count);
        self.bytes = rest;
        Ok(head)
    }

    pub fn byte(&mut self) -> Result<u8, CodecError> {
        Ok(self.take(1)?[0])
    }

    pub fn u32_be(&mut self) -> Result<u32, CodecError> {
        let bytes = self.take(4)?;
        Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    pub fn varint(&mut self) -> Result<u64, CodecError> {
        let mut value = u64::from(self.byte()?);
        if value < 240 {
            return Ok(value);
        }
        let mut shift = 4_u32;
        loop {
            if shift > 63 {
                return Err(CodecError::VarintOverflow);
            }
            let byte = u64::from(self.byte()?);
            value = value.wrapping_add(byte << shift);
            shift += 7;
            if byte < 128 {
                return Ok(value);
            }
        }
    }

    pub fn bytes(&mut self) -> Result<&'frame [u8], CodecError> {
        let length = usize::try_from(self.varint()?).map_err(|_| CodecError::Truncated)?;
        self.take(length)
    }

    pub fn string(&mut self) -> Result<&'frame str, CodecError> {
        std::str::from_utf8(self.bytes()?).map_err(|_| CodecError::NotUtf8)
    }

    pub fn typed(&mut self) -> Result<TypedData, CodecError> {
        let tag = self.byte()?;
        Ok(match tag & 0x0F {
            0 => TypedData::Null,
            1 => TypedData::Bool(tag & 0x10 != 0),
            2 => TypedData::Int32(self.varint()? as i32),
            3 => TypedData::Uint32(self.varint()? as u32),
            4 => TypedData::Int64(self.varint()? as i64),
            5 => TypedData::Uint64(self.varint()?),
            6 => {
                let octets = self.take(4)?;
                TypedData::Ipv4(Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3]))
            }
            7 => {
                let octets: [u8; 16] = self.take(16)?.try_into().expect("sixteen bytes");
                TypedData::Ipv6(Ipv6Addr::from(octets))
            }
            8 => TypedData::String(self.string()?.to_owned()),
            9 => TypedData::Binary(self.bytes()?.to_vec()),
            other => return Err(CodecError::UnknownType(other)),
        })
    }

    /// A KV-LIST to the end of the frame.
    pub fn kv_list(&mut self) -> Result<Vec<(String, TypedData)>, CodecError> {
        let mut entries = Vec::new();
        while !self.is_empty() {
            let key = self.string()?.to_owned();
            entries.push((key, self.typed()?));
        }
        Ok(entries)
    }
}

/// One frame, without its length prefix.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Frame<'frame> {
    pub frame_type: u8,
    pub flags: u32,
    pub stream_id: u64,
    pub frame_id: u64,
    pub payload: &'frame [u8],
}

impl<'frame> Frame<'frame> {
    pub fn parse(body: &'frame [u8]) -> Result<Self, CodecError> {
        let mut reader = Reader::new(body);
        let frame_type = reader.byte().map_err(|_| CodecError::ShortFrame)?;
        let flags = reader.u32_be().map_err(|_| CodecError::ShortFrame)?;
        let stream_id = reader.varint()?;
        let frame_id = reader.varint()?;
        Ok(Self {
            frame_type,
            flags,
            stream_id,
            frame_id,
            payload: reader.bytes,
        })
    }
}

/// Starts a frame: the length is patched in by `finish_frame`.
fn start_frame(frame_type: u8, stream_id: u64, frame_id: u64) -> Vec<u8> {
    let mut out = vec![0, 0, 0, 0, frame_type];
    out.extend_from_slice(&FLAG_FIN.to_be_bytes());
    encode_varint(&mut out, stream_id);
    encode_varint(&mut out, frame_id);
    out
}

fn finish_frame(mut out: Vec<u8>) -> Vec<u8> {
    let length = (out.len() - 4) as u32;
    out[..4].copy_from_slice(&length.to_be_bytes());
    out
}

fn put_kv(out: &mut Vec<u8>, key: &str, value: &TypedData) {
    encode_bytes(out, key.as_bytes());
    value.encode(out);
}

/// AGENT-HELLO. `capabilities` is what both sides support; pipelining is the only one left in 2.0.
pub fn agent_hello(max_frame_size: u32, pipelining: bool) -> Vec<u8> {
    let mut out = start_frame(FRAME_AGENT_HELLO, 0, 0);
    put_kv(&mut out, "version", &TypedData::String(SPOP_VERSION.into()));
    put_kv(
        &mut out,
        "max-frame-size",
        &TypedData::Uint32(max_frame_size),
    );
    let capabilities = if pipelining { "pipelining" } else { "" };
    put_kv(
        &mut out,
        "capabilities",
        &TypedData::String(capabilities.into()),
    );
    finish_frame(out)
}

pub fn agent_disconnect(status: DisconnectStatus, message: &str) -> Vec<u8> {
    let mut out = start_frame(FRAME_AGENT_DISCONNECT, 0, 0);
    put_kv(&mut out, "status-code", &TypedData::Uint32(status as u32));
    put_kv(&mut out, "message", &TypedData::String(message.into()));
    finish_frame(out)
}

/// The scope of a variable an ACK sets. HAProxy names it `<scope>.<engine-id>.<name>`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum VarScope {
    Process = 0,
    Session = 1,
    Transaction = 2,
    Request = 3,
    Response = 4,
}

/// ACK with one SET-VAR action per variable.
pub fn ack(stream_id: u64, frame_id: u64, vars: &[(VarScope, &str, TypedData)]) -> Vec<u8> {
    let mut out = start_frame(FRAME_ACK, stream_id, frame_id);
    for (scope, name, value) in vars {
        out.push(ACTION_SET_VAR);
        out.push(3);
        out.push(*scope as u8);
        encode_bytes(&mut out, name.as_bytes());
        value.encode(&mut out);
    }
    finish_frame(out)
}

/// One message of a NOTIFY frame.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Message {
    pub name: String,
    pub args: Vec<(String, TypedData)>,
}

impl Message {
    pub fn arg(&self, name: &str) -> Option<&TypedData> {
        self.args
            .iter()
            .find(|(arg_name, _)| arg_name == name)
            .map(|(_, value)| value)
    }
}

/// The messages of a NOTIFY payload.
pub fn parse_messages(payload: &[u8]) -> Result<Vec<Message>, CodecError> {
    let mut reader = Reader::new(payload);
    let mut messages = Vec::new();
    while !reader.is_empty() {
        let name = reader.string()?.to_owned();
        let arg_count = reader.byte()?;
        let mut args = Vec::with_capacity(usize::from(arg_count));
        for _ in 0..arg_count {
            let key = reader.string()?.to_owned();
            args.push((key, reader.typed()?));
        }
        messages.push(Message { name, args });
    }
    Ok(messages)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The boundaries HAProxy's own table gives: one byte below 240, two up to 2287, three up to
    /// 264431.
    #[test]
    fn varints_round_trip_at_every_width_boundary() {
        for (value, width) in [
            (0_u64, 1),
            (239, 1),
            (240, 2),
            (2_287, 2),
            (2_288, 3),
            (264_431, 3),
            (264_432, 4),
            (u64::from(u32::MAX), 5),
            (u64::MAX, 10),
        ] {
            let mut out = Vec::new();
            encode_varint(&mut out, value);
            assert_eq!(out.len(), width, "{value}");
            let mut reader = Reader::new(&out);
            assert_eq!(reader.varint().unwrap(), value);
            assert!(reader.is_empty());
        }
    }

    /// Pinned bytes, worked from the algorithm in `doc/SPOE.txt`: 240 is `F0 00`, 1000 is
    /// `F8 2F` (1000 & 0xF | 0xF0, then (1000 - 240) >> 4 = 47).
    #[test]
    fn varint_bytes_match_the_specification() {
        let mut out = Vec::new();
        encode_varint(&mut out, 240);
        encode_varint(&mut out, 1_000);
        assert_eq!(out, [0xF0, 0x00, 0xF8, 0x2F]);
    }

    #[test]
    fn typed_data_round_trips() {
        let values = [
            TypedData::Null,
            TypedData::Bool(true),
            TypedData::Bool(false),
            TypedData::Int32(-5),
            TypedData::Uint32(70_000),
            TypedData::Int64(-1),
            TypedData::Uint64(u64::MAX),
            TypedData::Ipv4(Ipv4Addr::new(10, 0, 0, 1)),
            TypedData::Ipv6(Ipv6Addr::LOCALHOST),
            TypedData::String("GET".into()),
            TypedData::Binary(vec![0, 255]),
        ];
        let mut out = Vec::new();
        for value in &values {
            value.encode(&mut out);
        }
        let mut reader = Reader::new(&out);
        for value in &values {
            assert_eq!(&reader.typed().unwrap(), value);
        }
        assert!(reader.is_empty());
    }

    /// A HAPROXY-HELLO as HAProxy sends it, built by hand, parses into its frame and its list.
    #[test]
    fn a_hello_frame_parses() {
        let mut body = vec![FRAME_HAPROXY_HELLO];
        body.extend_from_slice(&FLAG_FIN.to_be_bytes());
        body.extend_from_slice(&[0, 0]);
        put_kv(
            &mut body,
            "supported-versions",
            &TypedData::String("2.0".into()),
        );
        put_kv(&mut body, "max-frame-size", &TypedData::Uint32(16_380));
        put_kv(
            &mut body,
            "capabilities",
            &TypedData::String("pipelining".into()),
        );

        let frame = Frame::parse(&body).unwrap();
        assert_eq!(frame.frame_type, FRAME_HAPROXY_HELLO);
        assert_eq!(frame.flags, FLAG_FIN);
        let list = Reader::new(frame.payload).kv_list().unwrap();
        assert_eq!(
            list[1],
            ("max-frame-size".into(), TypedData::Uint32(16_380))
        );
    }

    #[test]
    fn a_notify_payload_yields_its_messages() {
        let mut payload = Vec::new();
        encode_bytes(&mut payload, b"fareward-check");
        payload.push(2);
        put_kv(&mut payload, "method", &TypedData::String("POST".into()));
        put_kv(&mut payload, "length", &TypedData::Int64(9_000));
        let messages = parse_messages(&payload).unwrap();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].name, "fareward-check");
        assert_eq!(
            messages[0].arg("length").and_then(TypedData::as_u64),
            Some(9_000)
        );
        assert_eq!(
            messages[0].arg("method").and_then(TypedData::as_str),
            Some("POST")
        );
    }

    #[test]
    fn an_ack_carries_its_ids_and_set_var_actions() {
        let frame = ack(
            7,
            300,
            &[(VarScope::Transaction, "status", TypedData::Int32(429))],
        );
        let length = u32::from_be_bytes(frame[..4].try_into().unwrap()) as usize;
        assert_eq!(length, frame.len() - 4);
        let parsed = Frame::parse(&frame[4..]).unwrap();
        assert_eq!(
            (parsed.frame_type, parsed.stream_id, parsed.frame_id),
            (FRAME_ACK, 7, 300)
        );
        let mut reader = Reader::new(parsed.payload);
        assert_eq!(reader.byte().unwrap(), ACTION_SET_VAR);
        assert_eq!(reader.byte().unwrap(), 3);
        assert_eq!(reader.byte().unwrap(), VarScope::Transaction as u8);
        assert_eq!(reader.string().unwrap(), "status");
        assert_eq!(reader.typed().unwrap(), TypedData::Int32(429));
        assert!(reader.is_empty());
    }

    #[test]
    fn a_truncated_frame_is_an_error_not_a_panic() {
        assert_eq!(Frame::parse(&[1, 0]), Err(CodecError::ShortFrame));
        let mut reader = Reader::new(&[0xF0]);
        assert_eq!(reader.varint(), Err(CodecError::Truncated));
        let mut reader = Reader::new(&[8, 5, b'a']);
        assert_eq!(reader.typed(), Err(CodecError::Truncated));
    }
}
