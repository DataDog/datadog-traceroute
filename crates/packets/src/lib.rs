//! Packet IO abstractions and filter definitions.

mod frame_parser;

pub use frame_parser::{
    FrameParser, IPPair, IcmpInfo, IcmpPacket, LayerType, TcpInfo, UdpInfo, parse_tcp_first_bytes,
    parse_udp_first_bytes, serialize_tcp_first_bytes, write_udp_first_bytes,
};

use datadog_traceroute_common::{BadPacketError, ReceiveProbeNoPktError};
use std::io;
use std::net::SocketAddr;
use std::time::Instant;

#[cfg(windows)]
pub mod windows;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PacketFilterType {
    None = 0,
    Icmp = 1,
    Udp = 2,
    Tcp = 3,
    SynAck = 4,
}

#[derive(Debug, Clone, Copy)]
pub struct FilterConfig {
    pub src: SocketAddr,
    pub dst: SocketAddr,
}

#[derive(Debug, Clone, Copy)]
pub struct PacketFilterSpec {
    pub filter_type: PacketFilterType,
    pub filter_config: FilterConfig,
}

pub trait PacketSource {
    fn set_read_deadline(&mut self, deadline: Instant) -> io::Result<()>;
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize>;
    fn close(&mut self) -> io::Result<()>;
    fn set_packet_filter(&mut self, spec: PacketFilterSpec) -> io::Result<()>;
}

pub trait PacketSink {
    fn write_to(&mut self, buf: &[u8], addr: SocketAddr) -> io::Result<()>;
    fn close(&mut self) -> io::Result<()>;
}

pub struct SourceSinkHandle {
    pub source: Box<dyn PacketSource + Send>,
    pub sink: Box<dyn PacketSink + Send>,
    pub must_close_port: bool,
}

pub fn read_and_parse(
    source: &mut dyn PacketSource,
    buffer: &mut [u8],
    parser: &mut FrameParser,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let n = match source.read(buffer) {
        Ok(n) => n,
        Err(err) => {
            if matches!(
                err.kind(),
                io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
            ) {
                return Err(Box::new(ReceiveProbeNoPktError::new(err.to_string())));
            }
            return Err(Box::new(io::Error::new(
                err.kind(),
                format!("packet source read failed: {}", err),
            )));
        }
    };
    if n == 0 {
        return Err(Box::new(BadPacketError::new(
            "packet source read returned 0 bytes",
        )));
    }
    parser.parse(&buffer[..n])
}
