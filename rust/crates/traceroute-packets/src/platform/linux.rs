//! Linux-specific packet I/O using AF_PACKET.

use crate::{PacketFilterSpec, Sink, Source, SourceSinkHandle};
use async_trait::async_trait;
use std::io::Read;
use std::net::{IpAddr, SocketAddr};
use std::os::fd::{FromRawFd, RawFd};
use std::time::Instant;
use traceroute_core::TracerouteError;

// Constants from linux headers
const AF_PACKET: i32 = 17;
const SOCK_RAW: i32 = 3;
const ETH_P_ALL: u16 = 0x0003;
const SOL_SOCKET: i32 = 1;

const AF_INET: i32 = 2;
const AF_INET6: i32 = 10;
const IPPROTO_RAW: i32 = 255;
const IP_HDRINCL: i32 = 3;
const IPV6_HDRINCL: i32 = 36;

// Ethernet header size
const ETH_HLEN: usize = 14;

/// Convert host to network byte order (big-endian)
fn htons(val: u16) -> u16 {
    val.to_be()
}

/// AF_PACKET-based packet source for Linux.
pub struct AfPacketSource {
    fd: RawFd,
    file: std::fs::File,
    read_deadline: Option<Instant>,
}

impl AfPacketSource {
    /// Creates a new AF_PACKET source.
    pub fn new() -> Result<Self, TracerouteError> {
        let fd = unsafe {
            libc::socket(
                AF_PACKET,
                SOCK_RAW | libc::SOCK_NONBLOCK,
                htons(ETH_P_ALL) as i32,
            )
        };

        if fd < 0 {
            return Err(TracerouteError::SocketCreation(
                std::io::Error::last_os_error(),
            ));
        }

        let file = unsafe { std::fs::File::from_raw_fd(fd) };

        Ok(Self {
            fd,
            file,
            read_deadline: None,
        })
    }

    /// Strips the Ethernet header from a packet, returning the IP payload.
    fn strip_ethernet_header(buf: &[u8]) -> Result<&[u8], TracerouteError> {
        if buf.len() < ETH_HLEN {
            return Err(TracerouteError::PacketTooShort {
                expected: ETH_HLEN,
                actual: buf.len(),
            });
        }

        // Check EtherType (bytes 12-13)
        let ethertype = u16::from_be_bytes([buf[12], buf[13]]);

        // 0x0800 = IPv4, 0x86DD = IPv6
        if ethertype != 0x0800 && ethertype != 0x86DD {
            return Err(TracerouteError::PacketMismatch);
        }

        Ok(&buf[ETH_HLEN..])
    }
}

#[async_trait]
impl Source for AfPacketSource {
    fn set_read_deadline(&mut self, deadline: Instant) -> Result<(), TracerouteError> {
        self.read_deadline = Some(deadline);

        // Set socket timeout
        let duration = deadline.saturating_duration_since(Instant::now());
        let tv = libc::timeval {
            tv_sec: duration.as_secs() as libc::time_t,
            tv_usec: duration.subsec_micros() as libc::suseconds_t,
        };

        let result = unsafe {
            libc::setsockopt(
                self.fd,
                SOL_SOCKET,
                libc::SO_RCVTIMEO,
                &tv as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::timeval>() as libc::socklen_t,
            )
        };

        if result < 0 {
            return Err(TracerouteError::Internal(format!(
                "Failed to set socket timeout: {}",
                std::io::Error::last_os_error()
            )));
        }

        Ok(())
    }

    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, TracerouteError> {
        // Read raw packet including ethernet header
        let mut raw_buf = vec![0u8; buf.len() + ETH_HLEN];

        loop {
            let n = match (&self.file).read(&mut raw_buf) {
                Ok(n) => n,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    // Check deadline
                    if let Some(deadline) = self.read_deadline {
                        if Instant::now() >= deadline {
                            return Err(TracerouteError::ReadTimeout);
                        }
                    }
                    // Yield and retry
                    tokio::task::yield_now().await;
                    continue;
                }
                Err(e) => return Err(TracerouteError::from(e)),
            };

            // Strip ethernet header
            match Self::strip_ethernet_header(&raw_buf[..n]) {
                Ok(payload) => {
                    let len = payload.len().min(buf.len());
                    buf[..len].copy_from_slice(&payload[..len]);
                    return Ok(len);
                }
                Err(TracerouteError::PacketMismatch) => {
                    // Not an IP packet, continue reading
                    continue;
                }
                Err(e) => return Err(e),
            }
        }
    }

    async fn close(&mut self) -> Result<(), TracerouteError> {
        // File will be closed when dropped
        Ok(())
    }

    fn set_packet_filter(&mut self, _spec: PacketFilterSpec) -> Result<(), TracerouteError> {
        // TODO: Implement BPF filter
        // For now, we'll filter in userspace
        Ok(())
    }
}

/// Raw socket-based packet sink for Linux.
pub struct RawSink {
    fd: RawFd,
    #[allow(dead_code)]
    is_ipv6: bool,
}

impl RawSink {
    /// Creates a new raw socket sink.
    pub fn new(addr: IpAddr) -> Result<Self, TracerouteError> {
        let (domain, protocol, hdrincl) = match addr {
            IpAddr::V4(_) => (AF_INET, libc::IPPROTO_IP, IP_HDRINCL),
            IpAddr::V6(_) => (AF_INET6, libc::IPPROTO_IPV6, IPV6_HDRINCL),
        };

        let fd = unsafe { libc::socket(domain, SOCK_RAW | libc::SOCK_NONBLOCK, IPPROTO_RAW) };

        if fd < 0 {
            return Err(TracerouteError::SocketCreation(
                std::io::Error::last_os_error(),
            ));
        }

        // Set IP_HDRINCL to include IP header in packets
        let one: i32 = 1;
        let result = unsafe {
            libc::setsockopt(
                fd,
                protocol,
                hdrincl,
                &one as *const _ as *const libc::c_void,
                std::mem::size_of::<i32>() as libc::socklen_t,
            )
        };

        if result < 0 {
            unsafe { libc::close(fd) };
            return Err(TracerouteError::Internal(format!(
                "Failed to set IP_HDRINCL: {}",
                std::io::Error::last_os_error()
            )));
        }

        Ok(Self {
            fd,
            is_ipv6: addr.is_ipv6(),
        })
    }
}

#[async_trait]
impl Sink for RawSink {
    async fn write_to(&mut self, buf: &[u8], addr: SocketAddr) -> Result<(), TracerouteError> {
        let (sockaddr, sockaddr_len): (libc::sockaddr_storage, libc::socklen_t) = match addr {
            SocketAddr::V4(v4) => {
                let mut sa: libc::sockaddr_in = unsafe { std::mem::zeroed() };
                sa.sin_family = AF_INET as libc::sa_family_t;
                sa.sin_port = v4.port().to_be();
                sa.sin_addr.s_addr = u32::from_ne_bytes(v4.ip().octets());

                let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
                unsafe {
                    std::ptr::copy_nonoverlapping(
                        &sa as *const _ as *const u8,
                        &mut storage as *mut _ as *mut u8,
                        std::mem::size_of::<libc::sockaddr_in>(),
                    );
                }
                (
                    storage,
                    std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
                )
            }
            SocketAddr::V6(v6) => {
                let mut sa: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
                sa.sin6_family = AF_INET6 as libc::sa_family_t;
                sa.sin6_port = v6.port().to_be();
                sa.sin6_addr.s6_addr = v6.ip().octets();

                let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
                unsafe {
                    std::ptr::copy_nonoverlapping(
                        &sa as *const _ as *const u8,
                        &mut storage as *mut _ as *mut u8,
                        std::mem::size_of::<libc::sockaddr_in6>(),
                    );
                }
                (
                    storage,
                    std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
                )
            }
        };

        let result = unsafe {
            libc::sendto(
                self.fd,
                buf.as_ptr() as *const libc::c_void,
                buf.len(),
                0,
                &sockaddr as *const _ as *const libc::sockaddr,
                sockaddr_len,
            )
        };

        if result < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::WouldBlock {
                // Retry with async
                tokio::task::yield_now().await;
                return self.write_to(buf, addr).await;
            }
            return Err(TracerouteError::WriteFailed(err));
        }

        Ok(())
    }

    async fn close(&mut self) -> Result<(), TracerouteError> {
        unsafe { libc::close(self.fd) };
        Ok(())
    }
}

impl Drop for RawSink {
    fn drop(&mut self) {
        unsafe { libc::close(self.fd) };
    }
}

/// Creates a new source and sink for Linux.
pub async fn new_source_sink(target_addr: IpAddr) -> Result<SourceSinkHandle, TracerouteError> {
    let source = AfPacketSource::new()?;
    let sink = RawSink::new(target_addr)?;

    Ok(SourceSinkHandle {
        source: Box::new(source),
        sink: Box::new(sink),
        must_close_port: false,
    })
}
