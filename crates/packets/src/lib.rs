//! Packet IO abstractions and filter definitions.

mod frame_parser;

pub use frame_parser::{
    FrameParser, IPPair, IcmpInfo, IcmpPacket, LayerType, TcpInfo, UdpInfo, parse_tcp_first_bytes,
    parse_udp_first_bytes, serialize_tcp_first_bytes, write_udp_first_bytes,
};

use datadog_traceroute_common::{BadPacketError, ReceiveProbeNoPktError};
use std::io;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::time::Instant;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
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

#[cfg(windows)]
pub fn start_driver() -> io::Result<()> {
    windows::start_driver()
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub fn start_driver() -> io::Result<()> {
    Ok(())
}

#[cfg(windows)]
pub fn new_source_sink(_addr: IpAddr, use_driver: bool) -> io::Result<SourceSinkHandle> {
    if use_driver {
        windows::new_source_sink_driver()
    } else {
        Err(io::Error::new(
            io::ErrorKind::Other,
            "raw socket source/sink not implemented on Windows without driver",
        ))
    }
}

#[cfg(target_os = "linux")]
pub fn new_source_sink(addr: IpAddr, _use_driver: bool) -> io::Result<SourceSinkHandle> {
    linux::new_source_sink(addr)
}

#[cfg(target_os = "macos")]
pub fn new_source_sink(addr: IpAddr, _use_driver: bool) -> io::Result<SourceSinkHandle> {
    macos::new_source_sink(addr)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn strip_ethernet_header(buf: &[u8]) -> io::Result<Option<&[u8]>> {
    const ETH_HEADER_LEN: usize = 14;
    const ETH_TYPE_IPV4: u16 = 0x0800;
    const ETH_TYPE_IPV6: u16 = 0x86dd;

    if buf.len() < ETH_HEADER_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "ethernet frame too short",
        ));
    }
    let eth_type = u16::from_be_bytes([buf[12], buf[13]]);
    if eth_type != ETH_TYPE_IPV4 && eth_type != ETH_TYPE_IPV6 {
        return Ok(None);
    }
    Ok(Some(&buf[ETH_HEADER_LEN..]))
}

#[cfg(target_os = "macos")]
fn strip_ipv6_header(buf: &[u8]) -> io::Result<(&[u8], u8)> {
    const IPV6_HEADER_LEN: usize = 40;
    if buf.len() < IPV6_HEADER_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "ipv6 packet too short",
        ));
    }
    let hop_limit = buf[7];
    Ok((&buf[IPV6_HEADER_LEN..], hop_limit))
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn get_read_timeout(deadline: Option<Instant>) -> std::time::Duration {
    const DEFAULT_TIMEOUT_MS: u64 = 1000;
    const MIN_TIMEOUT_MS: u64 = 100;
    let Some(deadline) = deadline else {
        return std::time::Duration::from_millis(DEFAULT_TIMEOUT_MS);
    };
    let now = Instant::now();
    if deadline <= now {
        return std::time::Duration::from_millis(MIN_TIMEOUT_MS);
    }
    let timeout = deadline.saturating_duration_since(now);
    if timeout < std::time::Duration::from_millis(MIN_TIMEOUT_MS) {
        return std::time::Duration::from_millis(MIN_TIMEOUT_MS);
    }
    timeout
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
