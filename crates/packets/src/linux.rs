use crate::{
    FilterConfig, PacketFilterSpec, PacketFilterType, PacketSink, PacketSource, SourceSinkHandle,
    get_read_timeout, strip_ethernet_header,
};
use libc::{
    AF_INET, AF_INET6, ETH_P_ALL, IP_HDRINCL, IPPROTO_IPV6, IPPROTO_RAW, IPV6_HDRINCL,
    SO_ATTACH_FILTER, SO_DETACH_FILTER, SOCK_NONBLOCK, SOCK_RAW, SOL_SOCKET,
};
use std::io;
use std::mem;
use std::net::{IpAddr, SocketAddr};
use std::os::unix::io::RawFd;
use std::time::Instant;

const ETH_P_ALL_NETWORK: i32 = (ETH_P_ALL as u16).to_be() as i32;

pub fn new_source_sink(addr: IpAddr) -> io::Result<SourceSinkHandle> {
    let sink = Box::new(SinkLinux::new(addr)?);
    let source = Box::new(AfPacketSource::new()?);
    Ok(SourceSinkHandle {
        source,
        sink,
        must_close_port: false,
    })
}

struct SinkLinux {
    fd: RawFd,
}

impl SinkLinux {
    fn new(addr: IpAddr) -> io::Result<Self> {
        let (domain, hdrincl_level, hdrincl_opt) = match addr {
            IpAddr::V4(_) => (AF_INET, libc::IPPROTO_IP, IP_HDRINCL),
            IpAddr::V6(_) => (AF_INET6, IPPROTO_IPV6, IPV6_HDRINCL),
        };
        let fd = unsafe { libc::socket(domain, SOCK_RAW | SOCK_NONBLOCK, IPPROTO_RAW) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let opt: libc::c_int = 1;
        let rc = unsafe {
            libc::setsockopt(
                fd,
                hdrincl_level,
                hdrincl_opt,
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
        Ok(Self { fd })
    }
}

impl PacketSink for SinkLinux {
    fn write_to(&mut self, buf: &[u8], addr: SocketAddr) -> io::Result<()> {
        let (sockaddr, socklen) = socket_addr_to_sockaddr(addr)?;
        loop {
            let rc = unsafe {
                libc::sendto(
                    self.fd,
                    buf.as_ptr() as *const libc::c_void,
                    buf.len(),
                    0,
                    &sockaddr as *const _ as *const libc::sockaddr,
                    socklen,
                )
            };
            if rc >= 0 {
                return Ok(());
            }
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::WouldBlock {
                continue;
            }
            return Err(err);
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
}

struct AfPacketSource {
    fd: RawFd,
    deadline: Option<Instant>,
}

impl AfPacketSource {
    fn new() -> io::Result<Self> {
        let fd =
            unsafe { libc::socket(libc::AF_PACKET, SOCK_RAW | SOCK_NONBLOCK, ETH_P_ALL_NETWORK) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { fd, deadline: None })
    }
}

impl PacketSource for AfPacketSource {
    fn set_read_deadline(&mut self, deadline: Instant) -> io::Result<()> {
        self.deadline = Some(deadline);
        Ok(())
    }

    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            let timeout = get_read_timeout(self.deadline);
            let mut fds = libc::pollfd {
                fd: self.fd,
                events: libc::POLLIN,
                revents: 0,
            };
            let rc = unsafe { libc::poll(&mut fds as *mut _, 1, timeout.as_millis() as i32) };
            if rc == 0 {
                return Err(io::Error::new(io::ErrorKind::TimedOut, "read timeout"));
            }
            if rc < 0 {
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(err);
            }
            let rc =
                unsafe { libc::recv(self.fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
            if rc < 0 {
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::WouldBlock {
                    continue;
                }
                return Err(err);
            }
            if rc == 0 {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "read 0 bytes"));
            }
            let frame_len = rc as usize;
            if frame_len < 14 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "ethernet frame too short",
                ));
            }
            let eth_type = u16::from_be_bytes([buf[12], buf[13]]);
            if eth_type != 0x0800 && eth_type != 0x86dd {
                continue;
            }
            let payload_len = frame_len - 14;
            buf.copy_within(14..frame_len, 0);
            return Ok(payload_len);
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

    fn set_packet_filter(&mut self, spec: PacketFilterSpec) -> io::Result<()> {
        match spec.filter_type {
            PacketFilterType::None => remove_bpf(self.fd),
            PacketFilterType::Icmp => set_bpf_and_drain(self.fd, &icmp_filter()),
            PacketFilterType::Udp => set_bpf_and_drain(self.fd, &udp_filter()),
            PacketFilterType::Tcp => {
                let filter = tcp_filter(spec.filter_config)?;
                set_bpf_and_drain(self.fd, &filter)
            }
            PacketFilterType::SynAck => set_bpf_and_drain(self.fd, &tcp_synack_filter()),
        }
    }
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

fn remove_bpf(fd: RawFd) -> io::Result<()> {
    let rc = unsafe { libc::setsockopt(fd, SOL_SOCKET, SO_DETACH_FILTER, std::ptr::null(), 0) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn set_bpf(fd: RawFd, filter: &[libc::sock_filter]) -> io::Result<()> {
    let prog = libc::sock_fprog {
        len: filter.len() as u16,
        filter: filter.as_ptr() as *mut libc::sock_filter,
    };
    let rc = unsafe {
        libc::setsockopt(
            fd,
            SOL_SOCKET,
            SO_ATTACH_FILTER,
            &prog as *const _ as *const libc::c_void,
            mem::size_of_val(&prog) as libc::socklen_t,
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn set_bpf_and_drain(fd: RawFd, filter: &[libc::sock_filter]) -> io::Result<()> {
    set_bpf(fd, &drop_all_filter())?;
    let mut buf = [0u8; 1];
    loop {
        let rc = unsafe {
            libc::recv(
                fd,
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
                libc::MSG_DONTWAIT,
            )
        };
        if rc >= 0 {
            continue;
        }
        let err = io::Error::last_os_error();
        if err.kind() == io::ErrorKind::WouldBlock {
            break;
        }
        return Err(err);
    }
    set_bpf(fd, filter)
}

fn drop_all_filter() -> [libc::sock_filter; 1] {
    [libc::sock_filter {
        code: 0x6,
        jt: 0,
        jf: 0,
        k: 0,
    }]
}

fn icmp_filter() -> [libc::sock_filter; 12] {
    [
        sock_filter(0x28, 0, 0, 0x0000000c),
        sock_filter(0x15, 0, 2, 0x00000800),
        sock_filter(0x30, 0, 0, 0x00000017),
        sock_filter(0x15, 6, 7, 0x00000001),
        sock_filter(0x15, 0, 6, 0x000086dd),
        sock_filter(0x30, 0, 0, 0x00000014),
        sock_filter(0x15, 3, 0, 0x0000003a),
        sock_filter(0x15, 0, 3, 0x0000002c),
        sock_filter(0x30, 0, 0, 0x00000036),
        sock_filter(0x15, 0, 1, 0x0000003a),
        sock_filter(0x6, 0, 0, 0x00040000),
        sock_filter(0x6, 0, 0, 0x00000000),
    ]
}

fn udp_filter() -> [libc::sock_filter; 13] {
    [
        sock_filter(0x28, 0, 0, 0x0000000c),
        sock_filter(0x15, 0, 2, 0x00000800),
        sock_filter(0x30, 0, 0, 0x00000017),
        sock_filter(0x15, 7, 6, 0x00000001),
        sock_filter(0x15, 0, 7, 0x000086dd),
        sock_filter(0x30, 0, 0, 0x00000014),
        sock_filter(0x15, 4, 0, 0x0000003a),
        sock_filter(0x15, 0, 2, 0x0000002c),
        sock_filter(0x30, 0, 0, 0x00000036),
        sock_filter(0x15, 1, 0, 0x0000003a),
        sock_filter(0x15, 0, 1, 0x00000011),
        sock_filter(0x6, 0, 0, 0x00040000),
        sock_filter(0x6, 0, 0, 0x00000000),
    ]
}

fn tcp_synack_filter() -> [libc::sock_filter; 12] {
    [
        sock_filter(0x28, 0, 0, 0x0000000c),
        sock_filter(0x15, 0, 9, 0x00000800),
        sock_filter(0x30, 0, 0, 0x00000017),
        sock_filter(0x15, 0, 7, 0x00000006),
        sock_filter(0x28, 0, 0, 0x00000014),
        sock_filter(0x45, 5, 0, 0x00001fff),
        sock_filter(0xb1, 0, 0, 0x0000000e),
        sock_filter(0x50, 0, 0, 0x0000001b),
        sock_filter(0x45, 0, 2, 0x00000002),
        sock_filter(0x45, 0, 1, 0x00000010),
        sock_filter(0x6, 0, 0, 0x00040000),
        sock_filter(0x6, 0, 0, 0x00000000),
    ]
}

fn tcp_filter(config: FilterConfig) -> io::Result<Vec<libc::sock_filter>> {
    let (src, dst) = (config.src, config.dst);
    let (src_ip, dst_ip) = match (src.ip(), dst.ip()) {
        (IpAddr::V4(src_ip), IpAddr::V4(dst_ip)) => (src_ip, dst_ip),
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "tcp filter only supports IPv4 addresses",
            ));
        }
    };
    let src_addr = u32::from_be_bytes(src_ip.octets());
    let dst_addr = u32::from_be_bytes(dst_ip.octets());
    let src_port = src.port() as u32;
    let dst_port = dst.port() as u32;

    Ok(vec![
        sock_filter(0x28, 0, 0, 0x0000000c),
        sock_filter(0x15, 0, 15, 0x00000800),
        sock_filter(0x30, 0, 0, 0x00000017),
        sock_filter(0x15, 12, 0, 0x00000001),
        sock_filter(0x15, 0, 12, 0x00000006),
        sock_filter(0x20, 0, 0, 0x0000001a),
        sock_filter(0x15, 0, 10, src_addr),
        sock_filter(0x20, 0, 0, 0x0000001e),
        sock_filter(0x15, 0, 8, dst_addr),
        sock_filter(0x28, 0, 0, 0x00000014),
        sock_filter(0x45, 6, 0, 0x00001fff),
        sock_filter(0xb1, 0, 0, 0x0000000e),
        sock_filter(0x48, 0, 0, 0x0000000e),
        sock_filter(0x15, 0, 3, src_port),
        sock_filter(0x48, 0, 0, 0x00000010),
        sock_filter(0x15, 0, 1, dst_port),
        sock_filter(0x6, 0, 0, 0x00040000),
        sock_filter(0x6, 0, 0, 0x00000000),
    ])
}

const fn sock_filter(code: u16, jt: u8, jf: u8, k: u32) -> libc::sock_filter {
    libc::sock_filter { code, jt, jf, k }
}
