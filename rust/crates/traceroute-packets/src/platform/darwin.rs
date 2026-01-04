//! macOS-specific packet I/O using BPF devices.

use crate::{PacketFilterSpec, Sink, Source, SourceSinkHandle};
use async_trait::async_trait;
use std::fs::File;
use std::io::{Read as IoRead, Write as IoWrite};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::time::{Duration, Instant};
use traceroute_core::TracerouteError;
use tracing::{debug, trace};

/// Maximum number of BPF devices on macOS.
const MAX_BPF_DEVICES: usize = 256;

/// BPF header alignment (4 bytes on macOS, even on 64-bit systems).
const BPF_ALIGNMENT: usize = 4;

/// Size of the BPF header structure.
const BPF_HEADER_SIZE: usize = 18; // sizeof(struct bpf_hdr) on macOS

/// Ethernet header size.
const ETHERNET_HEADER_SIZE: usize = 14;

/// DLT_NULL header size (loopback).
const DLT_NULL_HEADER_SIZE: usize = 4;

fn bpf_align(x: usize) -> usize {
    (x + BPF_ALIGNMENT - 1) & !(BPF_ALIGNMENT - 1)
}

/// Finds and opens an available BPF device.
fn pick_bpf_device() -> Result<RawFd, TracerouteError> {
    for i in 0..MAX_BPF_DEVICES {
        let path = format!("/dev/bpf{}", i);
        match std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
        {
            Ok(file) => {
                let fd = file.as_raw_fd();
                // Prevent the file from being closed when `file` is dropped
                std::mem::forget(file);
                return Ok(fd);
            }
            Err(e) if e.raw_os_error() == Some(libc::EBUSY) => continue,
            Err(e) => {
                return Err(TracerouteError::Internal(format!(
                    "Failed to open {}: {}",
                    path, e
                )));
            }
        }
    }

    Err(TracerouteError::Internal(format!(
        "All {} BPF devices are busy",
        MAX_BPF_DEVICES
    )))
}

/// Finds the network interface for the given target IP.
fn device_for_target(target_ip: IpAddr) -> Result<(String, bool), TracerouteError> {
    // Check if target is loopback
    let is_loopback = match target_ip {
        IpAddr::V4(ip) => ip.is_loopback(),
        IpAddr::V6(ip) => ip.is_loopback(),
    };

    if is_loopback {
        // Return loopback interface
        return Ok(("lo0".to_string(), true));
    }

    // Use a UDP socket to determine the outgoing interface
    let socket = UdpSocket::bind("0.0.0.0:0")
        .map_err(|e| TracerouteError::Internal(format!("Failed to bind UDP socket: {}", e)))?;

    let target_addr = match target_ip {
        IpAddr::V4(ip) => SocketAddr::new(IpAddr::V4(ip), 53),
        IpAddr::V6(ip) => SocketAddr::new(IpAddr::V6(ip), 53),
    };

    socket
        .connect(target_addr)
        .map_err(|e| TracerouteError::Internal(format!("Failed to connect UDP socket: {}", e)))?;

    let local_addr = socket
        .local_addr()
        .map_err(|e| TracerouteError::Internal(format!("Failed to get local address: {}", e)))?;

    // Find interface with matching IP
    // For simplicity, we'll use "en0" as the default interface on macOS
    // A full implementation would enumerate interfaces and find the matching one

    trace!(local_addr = %local_addr, "Determined local address for target");

    // Default to en0 for non-loopback
    Ok(("en0".to_string(), false))
}

/// Strips the Ethernet header and returns the IP payload.
fn strip_ethernet_header(frame: &[u8]) -> Result<&[u8], TracerouteError> {
    if frame.len() < ETHERNET_HEADER_SIZE {
        return Err(TracerouteError::MalformedPacket(format!(
            "Frame too short for Ethernet header: {} bytes",
            frame.len()
        )));
    }

    // Check EtherType (bytes 12-13)
    let ethertype = u16::from_be_bytes([frame[12], frame[13]]);

    match ethertype {
        0x0800 => Ok(&frame[ETHERNET_HEADER_SIZE..]), // IPv4
        0x86DD => Ok(&frame[ETHERNET_HEADER_SIZE..]), // IPv6
        _ => Err(TracerouteError::MalformedPacket(format!(
            "Unsupported EtherType: 0x{:04x}",
            ethertype
        ))),
    }
}

/// BPF device-based packet source for macOS.
pub struct BpfDevice {
    fd: RawFd,
    deadline: Option<Instant>,
    read_buf: Vec<u8>,
    pkt_buf: Vec<u8>,
    pkt_offset: usize,
    is_loopback: bool,
}

impl BpfDevice {
    /// Creates a new BPF device source.
    pub fn new(target_ip: IpAddr) -> Result<Self, TracerouteError> {
        let (iface_name, is_loopback) = device_for_target(target_ip)?;

        let fd = pick_bpf_device()?;

        // Set BIOCIMMEDIATE for immediate delivery
        let immediate: libc::c_int = 1;
        let result =
            unsafe { libc::ioctl(fd, libc::BIOCIMMEDIATE, &immediate as *const libc::c_int) };
        if result < 0 {
            unsafe { libc::close(fd) };
            return Err(TracerouteError::Internal(format!(
                "Failed to set BIOCIMMEDIATE: {}",
                std::io::Error::last_os_error()
            )));
        }

        // Bind to the interface
        let mut ifreq: libc::ifreq = unsafe { std::mem::zeroed() };
        let name_bytes = iface_name.as_bytes();
        let copy_len = std::cmp::min(name_bytes.len(), ifreq.ifr_name.len() - 1);
        for (i, &b) in name_bytes[..copy_len].iter().enumerate() {
            ifreq.ifr_name[i] = b as i8;
        }

        let result = unsafe { libc::ioctl(fd, libc::BIOCSETIF, &ifreq as *const libc::ifreq) };
        if result < 0 {
            unsafe { libc::close(fd) };
            return Err(TracerouteError::Internal(format!(
                "Failed to bind BPF to interface {}: {}",
                iface_name,
                std::io::Error::last_os_error()
            )));
        }

        debug!(interface = %iface_name, is_loopback = is_loopback, "Opened BPF device");

        Ok(Self {
            fd,
            deadline: None,
            read_buf: vec![0u8; 4096],
            pkt_buf: Vec::new(),
            pkt_offset: 0,
            is_loopback,
        })
    }

    fn has_next_packet(&self) -> bool {
        self.pkt_offset < self.pkt_buf.len()
    }

    fn read_packets(&mut self) -> Result<(), TracerouteError> {
        // Set timeout based on deadline
        let timeout = if let Some(deadline) = self.deadline {
            let now = Instant::now();
            if now >= deadline {
                return Err(TracerouteError::ReadTimeout);
            }
            deadline.duration_since(now)
        } else {
            Duration::from_secs(1)
        };

        // Set BPF timeout
        let tv = libc::timeval {
            tv_sec: timeout.as_secs() as libc::time_t,
            tv_usec: timeout.subsec_micros() as libc::suseconds_t,
        };
        let result =
            unsafe { libc::ioctl(self.fd, libc::BIOCSRTIMEOUT, &tv as *const libc::timeval) };
        if result < 0 {
            return Err(TracerouteError::Internal(format!(
                "Failed to set BPF timeout: {}",
                std::io::Error::last_os_error()
            )));
        }

        // Read from BPF device
        let n = unsafe {
            libc::read(
                self.fd,
                self.read_buf.as_mut_ptr() as *mut libc::c_void,
                self.read_buf.len(),
            )
        };

        if n < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                return Err(TracerouteError::ReadTimeout);
            }
            return Err(TracerouteError::from(err));
        }

        if n == 0 {
            return Err(TracerouteError::ReadTimeout);
        }

        self.pkt_buf = self.read_buf[..n as usize].to_vec();
        self.pkt_offset = 0;

        Ok(())
    }

    fn next_packet(&mut self) -> Result<&[u8], TracerouteError> {
        if self.pkt_offset + BPF_HEADER_SIZE > self.pkt_buf.len() {
            return Err(TracerouteError::MalformedPacket(
                "Buffer too small for BPF header".to_string(),
            ));
        }

        // Parse BPF header
        // struct bpf_hdr {
        //     struct timeval bh_tstamp;   // 16 bytes on 64-bit macOS
        //     uint32_t bh_caplen;
        //     uint32_t bh_datalen;
        //     uint16_t bh_hdrlen;
        // }
        // Actually on macOS: timestamp(8) + caplen(4) + datalen(4) + hdrlen(2) = 18 bytes

        let hdr_start = self.pkt_offset;

        // Read hdrlen (at offset 16, 2 bytes)
        let hdrlen =
            u16::from_ne_bytes([self.pkt_buf[hdr_start + 16], self.pkt_buf[hdr_start + 17]])
                as usize;

        // Read caplen (at offset 8, 4 bytes)
        let caplen = u32::from_ne_bytes([
            self.pkt_buf[hdr_start + 8],
            self.pkt_buf[hdr_start + 9],
            self.pkt_buf[hdr_start + 10],
            self.pkt_buf[hdr_start + 11],
        ]) as usize;

        let pkt_start = hdr_start + hdrlen;
        let pkt_end = pkt_start + caplen;
        let next_offset = bpf_align(pkt_end);

        if pkt_end > self.pkt_buf.len() {
            return Err(TracerouteError::MalformedPacket(format!(
                "Packet extends beyond buffer: {} > {}",
                pkt_end,
                self.pkt_buf.len()
            )));
        }

        self.pkt_offset = next_offset;

        Ok(&self.pkt_buf[pkt_start..pkt_end])
    }
}

#[async_trait]
impl Source for BpfDevice {
    fn set_read_deadline(&mut self, deadline: Instant) -> Result<(), TracerouteError> {
        self.deadline = Some(deadline);
        Ok(())
    }

    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, TracerouteError> {
        let is_loopback = self.is_loopback;
        loop {
            if !self.has_next_packet() {
                self.read_packets()?;
            }

            let link_frame = self.next_packet()?;

            // Strip link-layer header to get IP payload
            let payload = if is_loopback {
                // DLT_NULL: 4-byte address family header
                if link_frame.len() < DLT_NULL_HEADER_SIZE {
                    return Err(TracerouteError::MalformedPacket(format!(
                        "Loopback packet too short: {} bytes",
                        link_frame.len()
                    )));
                }
                &link_frame[DLT_NULL_HEADER_SIZE..]
            } else {
                // DLT_EN10MB: Ethernet header
                strip_ethernet_header(link_frame)?
            };

            let copy_len = std::cmp::min(payload.len(), buf.len());
            buf[..copy_len].copy_from_slice(&payload[..copy_len]);
            return Ok(copy_len);
        }
    }

    async fn close(&mut self) -> Result<(), TracerouteError> {
        if self.fd > 0 {
            unsafe { libc::close(self.fd) };
            self.fd = -1;
        }
        Ok(())
    }

    fn set_packet_filter(&mut self, _spec: PacketFilterSpec) -> Result<(), TracerouteError> {
        // BPF filter not implemented for macOS - no-op
        Ok(())
    }
}

/// Raw socket-based packet sink for macOS.
pub struct RawSink {
    fd: RawFd,
    is_ipv6: bool,
    write_buf: Vec<u8>,
}

impl RawSink {
    /// Creates a new raw socket sink.
    pub fn new(target_addr: IpAddr) -> Result<Self, TracerouteError> {
        let is_ipv6 = target_addr.is_ipv6();

        let (domain, protocol) = if is_ipv6 {
            (libc::AF_INET6, libc::IPPROTO_RAW)
        } else {
            (libc::AF_INET, libc::IPPROTO_RAW)
        };

        let fd = unsafe { libc::socket(domain, libc::SOCK_RAW, protocol) };
        if fd < 0 {
            return Err(TracerouteError::SocketCreation(
                std::io::Error::last_os_error(),
            ));
        }

        // Set IP_HDRINCL for IPv4 (macOS only supports this for IPv4)
        if !is_ipv6 {
            let hdrincl: libc::c_int = 1;
            let result = unsafe {
                libc::setsockopt(
                    fd,
                    libc::IPPROTO_IP,
                    libc::IP_HDRINCL,
                    &hdrincl as *const libc::c_int as *const libc::c_void,
                    std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                )
            };
            if result < 0 {
                unsafe { libc::close(fd) };
                return Err(TracerouteError::Internal(format!(
                    "Failed to set IP_HDRINCL: {}",
                    std::io::Error::last_os_error()
                )));
            }
        }

        Ok(Self {
            fd,
            is_ipv6,
            write_buf: vec![0u8; 4096],
        })
    }
}

#[async_trait]
impl Sink for RawSink {
    async fn write_to(&mut self, buf: &[u8], addr: SocketAddr) -> Result<(), TracerouteError> {
        if buf.len() > self.write_buf.len() {
            return Err(TracerouteError::Internal(format!(
                "Packet too large: {} bytes",
                buf.len()
            )));
        }

        let (send_buf, sa_len, sa_ptr) = if self.is_ipv6 {
            // IPv6: macOS has no IPV6_HDRINCL, so strip IPv6 header and set hop limit via socket option
            if buf.len() < 40 {
                return Err(TracerouteError::MalformedPacket(
                    "Packet too short for IPv6 header".to_string(),
                ));
            }

            // Extract TTL (hop limit) from IPv6 header (byte 7)
            let ttl = buf[7] as libc::c_int;

            // Set hop limit via IPV6_UNICAST_HOPS
            let result = unsafe {
                libc::setsockopt(
                    self.fd,
                    libc::IPPROTO_IPV6,
                    libc::IPV6_UNICAST_HOPS,
                    &ttl as *const libc::c_int as *const libc::c_void,
                    std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                )
            };
            if result < 0 {
                return Err(TracerouteError::Internal(format!(
                    "Failed to set IPV6_UNICAST_HOPS: {}",
                    std::io::Error::last_os_error()
                )));
            }

            // Use payload without IPv6 header
            let payload = &buf[40..];

            let sa6 = libc::sockaddr_in6 {
                sin6_len: std::mem::size_of::<libc::sockaddr_in6>() as u8,
                sin6_family: libc::AF_INET6 as u8,
                sin6_port: 0,
                sin6_flowinfo: 0,
                sin6_addr: match addr.ip() {
                    IpAddr::V6(ip) => libc::in6_addr {
                        s6_addr: ip.octets(),
                    },
                    _ => unreachable!(),
                },
                sin6_scope_id: 0,
            };

            (
                payload,
                std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
                &sa6 as *const _ as *const libc::sockaddr,
            )
        } else {
            // IPv4: Use IP_HDRINCL, but need to convert ip_len and ip_off to host byte order
            self.write_buf[..buf.len()].copy_from_slice(buf);

            if buf.len() >= 20 {
                // Convert ip_len (bytes 2-3) from network to host byte order
                let ip_len = u16::from_be_bytes([self.write_buf[2], self.write_buf[3]]);
                self.write_buf[2..4].copy_from_slice(&ip_len.to_ne_bytes());

                // Convert ip_off (bytes 6-7) from network to host byte order
                let ip_off = u16::from_be_bytes([self.write_buf[6], self.write_buf[7]]);
                self.write_buf[6..8].copy_from_slice(&ip_off.to_ne_bytes());
            }

            let sa4 = libc::sockaddr_in {
                sin_len: std::mem::size_of::<libc::sockaddr_in>() as u8,
                sin_family: libc::AF_INET as u8,
                sin_port: 0,
                sin_addr: libc::in_addr {
                    s_addr: match addr.ip() {
                        IpAddr::V4(ip) => u32::from_ne_bytes(ip.octets()),
                        _ => unreachable!(),
                    },
                },
                sin_zero: [0; 8],
            };

            (
                &self.write_buf[..buf.len()] as &[u8],
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
                &sa4 as *const _ as *const libc::sockaddr,
            )
        };

        let result = unsafe {
            libc::sendto(
                self.fd,
                send_buf.as_ptr() as *const libc::c_void,
                send_buf.len(),
                0,
                sa_ptr,
                sa_len,
            )
        };

        if result < 0 {
            return Err(TracerouteError::from(std::io::Error::last_os_error()));
        }

        Ok(())
    }

    async fn close(&mut self) -> Result<(), TracerouteError> {
        if self.fd > 0 {
            unsafe { libc::close(self.fd) };
            self.fd = -1;
        }
        Ok(())
    }
}

/// Creates a new source and sink for macOS.
pub async fn new_source_sink(target_addr: IpAddr) -> Result<SourceSinkHandle, TracerouteError> {
    let sink = RawSink::new(target_addr)?;
    let source = BpfDevice::new(target_addr)?;

    Ok(SourceSinkHandle {
        source: Box::new(source),
        sink: Box::new(sink),
        must_close_port: false,
    })
}
