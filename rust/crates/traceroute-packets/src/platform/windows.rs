//! Windows-specific packet I/O using raw sockets.

use crate::{PacketFilterSpec, Sink, Source, SourceSinkHandle};
use async_trait::async_trait;
use std::net::{IpAddr, SocketAddr};
use std::sync::Once;
use std::time::{Duration, Instant};
use traceroute_core::TracerouteError;
use tracing::debug;

#[cfg(target_os = "windows")]
use std::os::windows::io::RawSocket;

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
        let local_addr = match addr {
            IpAddr::V4(_) => addr,
            IpAddr::V6(_) => {
                return Err(TracerouteError::Internal(
                    "IPv6 raw sockets not supported on Windows".to_string(),
                ));
            }
        };

        #[cfg(target_os = "windows")]
        {
            use windows_sys::Win32::Networking::WinSock::{
                bind, setsockopt, socket, AF_INET, INVALID_SOCKET, IPPROTO_IP as WS_IPPROTO_IP,
                IP_HDRINCL as WS_IP_HDRINCL, SOCKADDR_IN, SOCKET_ERROR, SOCK_RAW,
            };

            let s = unsafe { socket(AF_INET as i32, SOCK_RAW, WS_IPPROTO_IP) };
            if s == INVALID_SOCKET {
                return Err(TracerouteError::SocketCreation(
                    std::io::Error::last_os_error(),
                ));
            }

            // Set IP_HDRINCL to include IP header in packets
            let hdrincl: i32 = 1;
            let result = unsafe {
                setsockopt(
                    s,
                    WS_IPPROTO_IP,
                    WS_IP_HDRINCL,
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

            // Bind to the local address - required for recvfrom to work on Windows
            let local_ip = match local_addr {
                IpAddr::V4(ip) => ip,
                _ => unreachable!(),
            };
            let sa = SOCKADDR_IN {
                sin_family: AF_INET,
                sin_port: 0,
                sin_addr: windows_sys::Win32::Networking::WinSock::IN_ADDR {
                    S_un: windows_sys::Win32::Networking::WinSock::IN_ADDR_0 {
                        S_addr: u32::from_ne_bytes(local_ip.octets()),
                    },
                },
                sin_zero: [0; 8],
            };

            let bind_result = unsafe {
                bind(
                    s,
                    &sa as *const _ as *const _,
                    std::mem::size_of::<SOCKADDR_IN>() as i32,
                )
            };
            if bind_result == SOCKET_ERROR {
                let err = std::io::Error::last_os_error();
                unsafe { windows_sys::Win32::Networking::WinSock::closesocket(s) };
                return Err(TracerouteError::Internal(format!(
                    "Failed to bind raw socket: {}",
                    err
                )));
            }

            debug!(local_addr = %local_addr, "Created and bound Windows raw socket");

            Ok(Self {
                socket: s as RawSocket,
                deadline: None,
                closed: false,
            })
        }

        #[cfg(not(target_os = "windows"))]
        {
            let _ = local_addr;
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

    /// Synchronous version of set_read_deadline for use with shared wrapper
    pub fn set_read_deadline(&mut self, deadline: Instant) -> Result<(), TracerouteError> {
        self.deadline = Some(deadline);
        Ok(())
    }

    /// Synchronous version of read for use with shared wrapper
    pub fn read_sync(&mut self, buf: &mut [u8]) -> Result<usize, TracerouteError> {
        if self.closed {
            return Err(TracerouteError::Internal("Socket closed".to_string()));
        }

        #[cfg(target_os = "windows")]
        {
            use windows_sys::Win32::Networking::WinSock::{
                recvfrom, setsockopt, WSAGetLastError, SOCKET_ERROR, SOL_SOCKET,
                SO_RCVTIMEO as WS_SO_RCVTIMEO, WSAEMSGSIZE as WS_WSAEMSGSIZE,
                WSAETIMEDOUT as WS_WSAETIMEDOUT,
            };

            let timeout = self.get_timeout();
            let timeout_ms = timeout.as_millis() as i32;

            // Set receive timeout
            let result = unsafe {
                setsockopt(
                    self.socket as usize,
                    SOL_SOCKET,
                    WS_SO_RCVTIMEO,
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
                return Err(TracerouteError::from(std::io::Error::from_raw_os_error(
                    err,
                )));
            }

            // Windows returns -1 on errors, unlike Unix
            if n < 0 {
                return Ok(0);
            }

            Ok(n as usize)
        }

        #[cfg(not(target_os = "windows"))]
        {
            let _ = buf;
            Err(TracerouteError::Internal("Not on Windows".to_string()))
        }
    }

    /// Synchronous version of close for use with shared wrapper
    pub fn close_sync(&mut self) -> Result<(), TracerouteError> {
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

    /// Synchronous version of set_packet_filter for use with shared wrapper
    pub fn set_packet_filter_sync(
        &mut self,
        _spec: PacketFilterSpec,
    ) -> Result<(), TracerouteError> {
        // Packet filtering not supported on Windows raw sockets - no-op
        Ok(())
    }

    /// Synchronous version of write_to for use with shared wrapper
    pub fn write_to_sync(&self, buf: &[u8], addr: SocketAddr) -> Result<(), TracerouteError> {
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
            let _ = (buf, addr);
            Err(TracerouteError::Internal("Not on Windows".to_string()))
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
                recvfrom, setsockopt, WSAGetLastError, SOCKET_ERROR, SOL_SOCKET,
                SO_RCVTIMEO as WS_SO_RCVTIMEO, WSAEMSGSIZE as WS_WSAEMSGSIZE,
                WSAETIMEDOUT as WS_WSAETIMEDOUT,
            };

            let timeout = self.get_timeout();
            let timeout_ms = timeout.as_millis() as i32;

            // Set receive timeout
            let result = unsafe {
                setsockopt(
                    self.socket as usize,
                    SOL_SOCKET,
                    WS_SO_RCVTIMEO,
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
                return Err(TracerouteError::from(std::io::Error::from_raw_os_error(
                    err,
                )));
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
        let result = Ok(());
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

    // Use raw socket mode with a shared socket wrapped in Arc
    // Windows raw sockets work best when the same socket is used for both
    // reading and writing, matching the Go implementation behavior
    let shared_conn = std::sync::Arc::new(std::sync::Mutex::new(RawConn::new(target_addr)?));

    Ok(SourceSinkHandle {
        source: Box::new(SharedRawConn {
            inner: shared_conn.clone(),
        }),
        sink: Box::new(SharedRawConnSink { inner: shared_conn }),
        must_close_port: true, // Windows raw sockets require closing the port before receiving
    })
}

/// Wrapper for shared RawConn as Source
pub struct SharedRawConn {
    inner: std::sync::Arc<std::sync::Mutex<RawConn>>,
}

#[async_trait]
impl Source for SharedRawConn {
    fn set_read_deadline(&mut self, deadline: Instant) -> Result<(), TracerouteError> {
        let mut conn = self.inner.lock().unwrap();
        conn.set_read_deadline(deadline)
    }

    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, TracerouteError> {
        let mut conn = self.inner.lock().unwrap();
        conn.read_sync(buf)
    }

    async fn close(&mut self) -> Result<(), TracerouteError> {
        let mut conn = self.inner.lock().unwrap();
        conn.close_sync()
    }

    fn set_packet_filter(&mut self, spec: PacketFilterSpec) -> Result<(), TracerouteError> {
        let mut conn = self.inner.lock().unwrap();
        conn.set_packet_filter_sync(spec)
    }
}

/// Wrapper for shared RawConn as Sink
pub struct SharedRawConnSink {
    inner: std::sync::Arc<std::sync::Mutex<RawConn>>,
}

#[async_trait]
impl Sink for SharedRawConnSink {
    async fn write_to(&mut self, buf: &[u8], addr: SocketAddr) -> Result<(), TracerouteError> {
        let conn = self.inner.lock().unwrap();
        conn.write_to_sync(buf, addr)
    }

    async fn close(&mut self) -> Result<(), TracerouteError> {
        // Don't close here - the source wrapper will close
        Ok(())
    }
}
