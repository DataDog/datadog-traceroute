//! Windows-specific packet I/O using raw sockets.

use crate::{PacketFilterSpec, Sink, Source, SourceSinkHandle};
use async_trait::async_trait;
use std::net::{IpAddr, SocketAddr};
use std::sync::Once;
use std::time::{Duration, Instant};
use traceroute_core::TracerouteError;
use tracing::{debug, trace};

#[cfg(target_os = "windows")]
use std::os::windows::io::{AsRawSocket, RawSocket};

/// IPPROTO_IP constant for Windows.
const IPPROTO_IP: i32 = 0;

/// IP_HDRINCL constant for Windows.
const IP_HDRINCL: i32 = 2;

/// SO_RCVTIMEO constant for Windows.
const SO_RCVTIMEO: i32 = 0x1006;

/// WSAETIMEDOUT error code.
const WSAETIMEDOUT: i32 = 10060;

/// WSAEMSGSIZE error code.
const WSAEMSGSIZE: i32 = 10040;

/// Raw connection-based packet source and sink for Windows.
///
/// This combines both Source and Sink functionality in a single struct,
/// as Windows raw sockets support both reading and writing.
pub struct RawConn {
    #[cfg(target_os = "windows")]
    socket: RawSocket,
    #[cfg(not(target_os = "windows"))]
    socket: i64,
    deadline: Option<Instant>,
    closed: bool,
}

impl RawConn {
    /// Creates a new raw connection.
    pub fn new(addr: IpAddr) -> Result<Self, TracerouteError> {
        // Windows only supports IPv4 raw sockets with IP_HDRINCL
        match addr {
            IpAddr::V4(_) => {}
            IpAddr::V6(_) => {
                return Err(TracerouteError::Internal(
                    "IPv6 raw sockets not supported on Windows".to_string(),
                ));
            }
        }

        #[cfg(target_os = "windows")]
        {
            use windows_sys::Win32::Networking::WinSock::{
                socket, setsockopt, AF_INET, IPPROTO_IP as WS_IPPROTO_IP, IP_HDRINCL as WS_IP_HDRINCL,
                SOCK_RAW, INVALID_SOCKET, SOCKET_ERROR,
            };

            let s = unsafe { socket(AF_INET as i32, SOCK_RAW as i32, WS_IPPROTO_IP as i32) };
            if s == INVALID_SOCKET {
                return Err(TracerouteError::SocketCreation(std::io::Error::last_os_error()));
            }

            // Set IP_HDRINCL to include IP header in packets
            let hdrincl: i32 = 1;
            let result = unsafe {
                setsockopt(
                    s,
                    WS_IPPROTO_IP as i32,
                    WS_IP_HDRINCL as i32,
                    &hdrincl as *const i32 as *const u8,
                    std::mem::size_of::<i32>() as i32,
                )
            };
            if result == SOCKET_ERROR {
                unsafe { windows_sys::Win32::Networking::WinSock::closesocket(s) };
                return Err(TracerouteError::Internal(format!(
                    "Failed to set IP_HDRINCL: {}",
                    std::io::Error::last_os_error()
                )));
            }

            debug!("Created Windows raw socket");

            Ok(Self {
                socket: s as RawSocket,
                deadline: None,
                closed: false,
            })
        }

        #[cfg(not(target_os = "windows"))]
        {
            // Stub for non-Windows platforms (won't be used)
            Err(TracerouteError::Internal(
                "Windows raw sockets only available on Windows".to_string(),
            ))
        }
    }

    fn get_timeout(&self) -> Duration {
        if let Some(deadline) = self.deadline {
            let now = Instant::now();
            if now >= deadline {
                Duration::from_millis(1) // Minimum timeout
            } else {
                deadline.duration_since(now)
            }
        } else {
            Duration::from_secs(1)
        }
    }
}

#[async_trait]
impl Source for RawConn {
    fn set_read_deadline(&mut self, deadline: Instant) -> Result<(), TracerouteError> {
        self.deadline = Some(deadline);
        Ok(())
    }

    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, TracerouteError> {
        if self.closed {
            return Err(TracerouteError::Internal("Socket closed".to_string()));
        }

        #[cfg(target_os = "windows")]
        {
            use windows_sys::Win32::Networking::WinSock::{
                recvfrom, setsockopt, SOL_SOCKET, SO_RCVTIMEO as WS_SO_RCVTIMEO,
                SOCKET_ERROR, WSAETIMEDOUT as WS_WSAETIMEDOUT, WSAEMSGSIZE as WS_WSAEMSGSIZE,
                WSAGetLastError,
            };

            let timeout = self.get_timeout();
            let timeout_ms = timeout.as_millis() as i32;

            // Set receive timeout
            let result = unsafe {
                setsockopt(
                    self.socket as usize,
                    SOL_SOCKET as i32,
                    WS_SO_RCVTIMEO as i32,
                    &timeout_ms as *const i32 as *const u8,
                    std::mem::size_of::<i32>() as i32,
                )
            };
            if result == SOCKET_ERROR {
                return Err(TracerouteError::Internal(format!(
                    "Failed to set SO_RCVTIMEO: {}",
                    std::io::Error::last_os_error()
                )));
            }

            let mut from_addr: windows_sys::Win32::Networking::WinSock::SOCKADDR_IN =
                unsafe { std::mem::zeroed() };
            let mut from_len =
                std::mem::size_of::<windows_sys::Win32::Networking::WinSock::SOCKADDR_IN>() as i32;

            let n = unsafe {
                recvfrom(
                    self.socket as usize,
                    buf.as_mut_ptr(),
                    buf.len() as i32,
                    0,
                    &mut from_addr as *mut _ as *mut _,
                    &mut from_len,
                )
            };

            if n == SOCKET_ERROR {
                let err = unsafe { WSAGetLastError() };
                if err == WS_WSAETIMEDOUT || err == WS_WSAEMSGSIZE {
                    return Err(TracerouteError::ReadTimeout);
                }
                return Err(TracerouteError::from(std::io::Error::from_raw_os_error(err)));
            }

            // Windows returns -1 on errors, unlike Unix
            if n < 0 {
                return Ok(0);
            }

            Ok(n as usize)
        }

        #[cfg(not(target_os = "windows"))]
        {
            Err(TracerouteError::Internal("Not on Windows".to_string()))
        }
    }

    async fn close(&mut self) -> Result<(), TracerouteError> {
        if !self.closed {
            #[cfg(target_os = "windows")]
            {
                use windows_sys::Win32::Networking::WinSock::closesocket;
                unsafe { closesocket(self.socket as usize) };
            }
            self.closed = true;
        }
        Ok(())
    }

    fn set_packet_filter(&mut self, _spec: PacketFilterSpec) -> Result<(), TracerouteError> {
        // Packet filtering not supported on Windows raw sockets - no-op
        Ok(())
    }
}

#[async_trait]
impl Sink for RawConn {
    async fn write_to(&mut self, buf: &[u8], addr: SocketAddr) -> Result<(), TracerouteError> {
        if self.closed {
            return Err(TracerouteError::Internal("Socket closed".to_string()));
        }

        #[cfg(target_os = "windows")]
        {
            use windows_sys::Win32::Networking::WinSock::{
                sendto, AF_INET, SOCKADDR_IN, SOCKET_ERROR,
            };

            let ip = match addr.ip() {
                IpAddr::V4(ip) => ip,
                IpAddr::V6(_) => {
                    return Err(TracerouteError::Internal(
                        "IPv6 not supported on Windows".to_string(),
                    ));
                }
            };

            let sa = SOCKADDR_IN {
                sin_family: AF_INET,
                sin_port: addr.port().to_be(),
                sin_addr: windows_sys::Win32::Networking::WinSock::IN_ADDR {
                    S_un: windows_sys::Win32::Networking::WinSock::IN_ADDR_0 {
                        S_addr: u32::from_ne_bytes(ip.octets()),
                    },
                },
                sin_zero: [0; 8],
            };

            let result = unsafe {
                sendto(
                    self.socket as usize,
                    buf.as_ptr(),
                    buf.len() as i32,
                    0,
                    &sa as *const _ as *const _,
                    std::mem::size_of::<SOCKADDR_IN>() as i32,
                )
            };

            if result == SOCKET_ERROR {
                return Err(TracerouteError::from(std::io::Error::last_os_error()));
            }

            Ok(())
        }

        #[cfg(not(target_os = "windows"))]
        {
            Err(TracerouteError::Internal("Not on Windows".to_string()))
        }
    }

    async fn close(&mut self) -> Result<(), TracerouteError> {
        <Self as Source>::close(self).await
    }
}

/// Placeholder for driver-based packet source (uses Datadog agent driver).
#[cfg(feature = "driver")]
pub struct SourceDriver {
    read_deadline: Option<Instant>,
    // Driver handle would go here
}

#[cfg(feature = "driver")]
impl SourceDriver {
    /// Creates a new driver-based source.
    pub fn new(_addr: IpAddr) -> Result<Self, TracerouteError> {
        // TODO: Implement driver FFI
        Err(TracerouteError::DriverNotAvailable)
    }
}

#[cfg(feature = "driver")]
#[async_trait]
impl Source for SourceDriver {
    fn set_read_deadline(&mut self, deadline: Instant) -> Result<(), TracerouteError> {
        self.read_deadline = Some(deadline);
        Ok(())
    }

    async fn read(&mut self, _buf: &mut [u8]) -> Result<usize, TracerouteError> {
        Err(TracerouteError::DriverNotAvailable)
    }

    async fn close(&mut self) -> Result<(), TracerouteError> {
        Ok(())
    }

    fn set_packet_filter(&mut self, _spec: PacketFilterSpec) -> Result<(), TracerouteError> {
        Ok(())
    }
}

/// Placeholder for driver-based packet sink (uses Datadog agent driver).
#[cfg(feature = "driver")]
pub struct SinkDriver {
    // Driver handle would go here
}

#[cfg(feature = "driver")]
impl SinkDriver {
    /// Creates a new driver-based sink.
    pub fn new(_addr: IpAddr) -> Result<Self, TracerouteError> {
        // TODO: Implement driver FFI
        Err(TracerouteError::DriverNotAvailable)
    }
}

#[cfg(feature = "driver")]
#[async_trait]
impl Sink for SinkDriver {
    async fn write_to(&mut self, _buf: &[u8], _addr: SocketAddr) -> Result<(), TracerouteError> {
        Err(TracerouteError::DriverNotAvailable)
    }

    async fn close(&mut self) -> Result<(), TracerouteError> {
        Ok(())
    }
}

/// Driver initialization once-guard.
static DRIVER_INIT: Once = Once::new();

/// Starts the Windows driver.
pub fn start_driver() -> Result<(), TracerouteError> {
    #[cfg(feature = "driver")]
    {
        let mut result = Ok(());
        DRIVER_INIT.call_once(|| {
            // TODO: Initialize driver
            // result = driver::init();
        });
        result
    }

    #[cfg(not(feature = "driver"))]
    Err(TracerouteError::DriverNotAvailable)
}

/// Creates a new source and sink for Windows.
pub async fn new_source_sink(
    target_addr: IpAddr,
    use_driver: bool,
) -> Result<SourceSinkHandle, TracerouteError> {
    if use_driver {
        #[cfg(feature = "driver")]
        {
            start_driver()?;
            let source = SourceDriver::new(target_addr)?;
            let sink = SinkDriver::new(target_addr)?;
            return Ok(SourceSinkHandle {
                source: Box::new(source),
                sink: Box::new(sink),
                must_close_port: false,
            });
        }

        #[cfg(not(feature = "driver"))]
        return Err(TracerouteError::DriverNotAvailable);
    }

    // Use raw socket mode
    let raw_conn = RawConn::new(target_addr)?;

    // For raw socket mode, we need a separate instance for reading and writing
    // or we could clone the socket handle. For now, we'll create two RawConn
    // instances (this is a simplification - in production, you'd want to share
    // the same underlying socket handle).
    let raw_conn2 = RawConn::new(target_addr)?;

    Ok(SourceSinkHandle {
        source: Box::new(raw_conn),
        sink: Box::new(raw_conn2),
        must_close_port: true, // Windows raw sockets require closing the port before receiving
    })
}
