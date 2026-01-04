use crate::{
    PacketFilterSpec, PacketSink, PacketSource, SourceSinkHandle, get_read_timeout,
    strip_ethernet_header, strip_ipv6_header,
};
use if_addrs::get_if_addrs;
use libc::{AF_INET, AF_INET6, IP_HDRINCL, IPPROTO_IPV6, IPPROTO_RAW};
use std::ffi::CString;
use std::io;
use std::mem;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::os::unix::io::RawFd;
use std::time::Instant;

const MAX_BPF_DEVICES: usize = 256;

pub fn new_source_sink(addr: IpAddr) -> io::Result<SourceSinkHandle> {
    let sink = Box::new(SinkMacos::new(addr)?);
    let source = Box::new(BpfDevice::new(addr)?);
    Ok(SourceSinkHandle {
        source,
        sink,
        must_close_port: false,
    })
}

struct SinkMacos {
    fd: RawFd,
    write_buf: Vec<u8>,
}

impl SinkMacos {
    fn new(addr: IpAddr) -> io::Result<Self> {
        let (domain, protocol) = match addr {
            IpAddr::V4(_) => (AF_INET, libc::IPPROTO_IP),
            IpAddr::V6(_) => (AF_INET6, IPPROTO_IPV6),
        };
        let fd = unsafe { libc::socket(domain, libc::SOCK_RAW, IPPROTO_RAW) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        if addr.is_ipv4() {
            let opt: libc::c_int = 1;
            let rc = unsafe {
                libc::setsockopt(
                    fd,
                    protocol,
                    IP_HDRINCL,
                    &opt as *const _ as *const libc::c_void,
                    mem::size_of_val(&opt) as libc::socklen_t,
                )
            };
            if rc < 0 {
                let err = io::Error::last_os_error();
                unsafe {
                    libc::close(fd);
                }
                return Err(err);
            }
        }
        Ok(Self {
            fd,
            write_buf: vec![0u8; 4096],
        })
    }
}

impl PacketSink for SinkMacos {
    fn write_to(&mut self, buf: &[u8], addr: SocketAddr) -> io::Result<()> {
        let (sockaddr, socklen) = socket_addr_to_sockaddr(addr)?;
        let mut owned = Vec::new();

        if addr.ip().is_ipv4() {
            if buf.len() > self.write_buf.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "packet too large for write buffer",
                ));
            }
            self.write_buf[..buf.len()].copy_from_slice(buf);
            let send = &mut self.write_buf[..buf.len()];
            update_ntohs16(&mut send[2..4]);
            update_ntohs16(&mut send[6..8]);
        } else {
            let (payload, hop_limit) = strip_ipv6_header(buf)?;
            owned.extend_from_slice(payload);
            let hop: libc::c_int = hop_limit as libc::c_int;
            let rc = unsafe {
                libc::setsockopt(
                    self.fd,
                    IPPROTO_IPV6,
                    libc::IPV6_HOPLIMIT,
                    &hop as *const _ as *const libc::c_void,
                    mem::size_of_val(&hop) as libc::socklen_t,
                )
            };
            if rc < 0 {
                return Err(io::Error::last_os_error());
            }
        }

        let send_buf = if addr.ip().is_ipv4() {
            &self.write_buf[..buf.len()]
        } else {
            &owned
        };
        let rc = unsafe {
            libc::sendto(
                self.fd,
                send_buf.as_ptr() as *const libc::c_void,
                send_buf.len(),
                0,
                &sockaddr as *const _ as *const libc::sockaddr,
                socklen,
            )
        };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn close(&mut self) -> io::Result<()> {
        if self.fd >= 0 {
            let rc = unsafe { libc::close(self.fd) };
            self.fd = -1;
            if rc < 0 {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(())
    }
}

struct BpfDevice {
    fd: RawFd,
    deadline: Option<Instant>,
    read_buf: Vec<u8>,
    pkt_buf: Vec<u8>,
    is_loopback: bool,
}

impl BpfDevice {
    fn new(target: IpAddr) -> io::Result<Self> {
        let (iface, is_loopback) = interface_for_target(target)?;
        let fd = pick_bpf_device()?;
        set_bpf_immediate(fd)?;
        set_bpf_interface(fd, &iface)?;
        let is_loopback = is_loopback || is_loopback_dlt(fd)?;
        Ok(Self {
            fd,
            deadline: None,
            read_buf: vec![0u8; 4096],
            pkt_buf: Vec::new(),
            is_loopback,
        })
    }

    fn has_next_packet(&self) -> bool {
        !self.pkt_buf.is_empty()
    }

    fn read_packets(&mut self) -> io::Result<()> {
        let timeout = get_read_timeout(self.deadline);
        let tv = libc::timeval {
            tv_sec: timeout.as_secs() as libc::time_t,
            tv_usec: timeout.subsec_micros() as libc::suseconds_t,
        };
        let rc = unsafe { libc::ioctl(self.fd, libc::BIOCSRTIMEOUT, &tv) };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        let n = unsafe {
            libc::read(
                self.fd,
                self.read_buf.as_mut_ptr() as *mut libc::c_void,
                self.read_buf.len(),
            )
        };
        if n < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                return Err(io::Error::new(io::ErrorKind::TimedOut, "no packets"));
            }
            return Err(err);
        }
        if n == 0 {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "no packets"));
        }
        self.pkt_buf = self.read_buf[..n as usize].to_vec();
        Ok(())
    }

    fn next_packet(&mut self) -> io::Result<Vec<u8>> {
        if self.pkt_buf.len() < mem::size_of::<libc::bpf_hdr>() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "bpf buffer too small",
            ));
        }
        let header = unsafe { &*(self.pkt_buf.as_ptr() as *const libc::bpf_hdr) };
        let start = header.bh_hdrlen as usize;
        let pkt_finish = start + header.bh_caplen as usize;
        let aligned = bpf_align(pkt_finish);
        if self.pkt_buf.len() < pkt_finish {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "bpf packet length exceeds buffer",
            ));
        }
        let packet = self.pkt_buf[start..pkt_finish].to_vec();
        if self.pkt_buf.len() > aligned {
            self.pkt_buf = self.pkt_buf[aligned..].to_vec();
        } else {
            self.pkt_buf.clear();
        }
        Ok(packet)
    }
}

impl PacketSource for BpfDevice {
    fn set_read_deadline(&mut self, deadline: Instant) -> io::Result<()> {
        self.deadline = Some(deadline);
        Ok(())
    }

    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            if !self.has_next_packet() {
                self.read_packets()?;
            }
            let packet = self.next_packet()?;
            let payload = if self.is_loopback {
                if packet.len() < 4 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "loopback packet too short",
                    ));
                }
                &packet[4..]
            } else {
                match strip_ethernet_header(&packet)? {
                    Some(payload) => payload,
                    None => continue,
                }
            };
            let n = payload.len().min(buf.len());
            buf[..n].copy_from_slice(&payload[..n]);
            return Ok(n);
        }
    }

    fn close(&mut self) -> io::Result<()> {
        if self.fd >= 0 {
            let rc = unsafe { libc::close(self.fd) };
            self.fd = -1;
            if rc < 0 {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(())
    }

    fn set_packet_filter(&mut self, _spec: PacketFilterSpec) -> io::Result<()> {
        Ok(())
    }
}

fn interface_for_target(target: IpAddr) -> io::Result<(String, bool)> {
    if target.is_loopback() {
        let ifaces = get_if_addrs().map_err(|err| io::Error::new(io::ErrorKind::Other, err))?;
        for iface in ifaces {
            if iface.ip().is_loopback() {
                return Ok((iface.name, true));
            }
        }
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "loopback interface not found",
        ));
    }

    let socket = match target {
        IpAddr::V4(_) => UdpSocket::bind("0.0.0.0:0"),
        IpAddr::V6(_) => UdpSocket::bind("[::]:0"),
    }?;
    socket.connect(SocketAddr::new(target, 53))?;
    let local_ip = socket.local_addr()?.ip();

    let ifaces = get_if_addrs().map_err(|err| io::Error::new(io::ErrorKind::Other, err))?;
    for iface in ifaces {
        if iface.ip() == local_ip {
            let is_loopback = iface.ip().is_loopback();
            return Ok((iface.name, is_loopback));
        }
    }

    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "could not find matching interface",
    ))
}

fn pick_bpf_device() -> io::Result<RawFd> {
    for idx in 0..MAX_BPF_DEVICES {
        let path = format!("/dev/bpf{}", idx);
        let c_path = CString::new(path)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid bpf path"))?;
        let fd = unsafe { libc::open(c_path.as_ptr(), libc::O_RDWR) };
        if fd >= 0 {
            return Ok(fd);
        }
        let err = io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::EBUSY) {
            continue;
        }
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "no available bpf devices",
    ))
}

fn set_bpf_immediate(fd: RawFd) -> io::Result<()> {
    let one: libc::c_uint = 1;
    let rc = unsafe { libc::ioctl(fd, libc::BIOCIMMEDIATE, &one) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn set_bpf_interface(fd: RawFd, name: &str) -> io::Result<()> {
    let mut ifr: libc::ifreq = unsafe { mem::zeroed() };
    for (idx, byte) in name.bytes().enumerate() {
        if idx >= ifr.ifr_name.len() {
            break;
        }
        ifr.ifr_name[idx] = byte as libc::c_char;
    }
    let rc = unsafe { libc::ioctl(fd, libc::BIOCSETIF, &ifr) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn is_loopback_dlt(fd: RawFd) -> io::Result<bool> {
    let mut dlt: libc::c_uint = 0;
    let rc = unsafe { libc::ioctl(fd, libc::BIOCGDLT, &mut dlt) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(dlt == libc::DLT_NULL as libc::c_uint)
}

fn bpf_align(value: usize) -> usize {
    let align = mem::align_of::<libc::bpf_hdr>();
    (value + align - 1) & !(align - 1)
}

fn socket_addr_to_sockaddr(
    addr: SocketAddr,
) -> io::Result<(libc::sockaddr_storage, libc::socklen_t)> {
    match addr {
        SocketAddr::V4(v4) => {
            let mut sockaddr: libc::sockaddr_in = unsafe { mem::zeroed() };
            sockaddr.sin_family = AF_INET as libc::sa_family_t;
            sockaddr.sin_port = v4.port().to_be();
            sockaddr.sin_addr = libc::in_addr {
                s_addr: u32::from_be_bytes(v4.ip().octets()).to_be(),
            };
            let mut storage: libc::sockaddr_storage = unsafe { mem::zeroed() };
            unsafe {
                std::ptr::copy_nonoverlapping(
                    &sockaddr as *const _ as *const u8,
                    &mut storage as *mut _ as *mut u8,
                    mem::size_of::<libc::sockaddr_in>(),
                );
            }
            Ok((
                storage,
                mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            ))
        }
        SocketAddr::V6(v6) => {
            let mut sockaddr: libc::sockaddr_in6 = unsafe { mem::zeroed() };
            sockaddr.sin6_family = AF_INET6 as libc::sa_family_t;
            sockaddr.sin6_port = v6.port().to_be();
            sockaddr.sin6_addr = libc::in6_addr {
                s6_addr: v6.ip().octets(),
            };
            sockaddr.sin6_scope_id = v6.scope_id();
            let mut storage: libc::sockaddr_storage = unsafe { mem::zeroed() };
            unsafe {
                std::ptr::copy_nonoverlapping(
                    &sockaddr as *const _ as *const u8,
                    &mut storage as *mut _ as *mut u8,
                    mem::size_of::<libc::sockaddr_in6>(),
                );
            }
            Ok((
                storage,
                mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
            ))
        }
    }
}

fn update_ntohs16(bytes: &mut [u8]) {
    if bytes.len() < 2 {
        return;
    }
    let value = u16::from_be_bytes([bytes[0], bytes[1]]);
    bytes[..2].copy_from_slice(&value.to_ne_bytes());
}
