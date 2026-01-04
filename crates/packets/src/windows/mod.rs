//! Windows driver-backed packet source/sink implementation.

use crate::{PacketFilterSpec, PacketFilterType, PacketSink, PacketSource, SourceSinkHandle};
use std::io;
use std::mem::{self, MaybeUninit};
use std::net::SocketAddr;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Instant;
use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_INSUFFICIENT_BUFFER, ERROR_IO_PENDING, ERROR_SERVICE_ALREADY_RUNNING,
    GetLastError, HANDLE, INVALID_HANDLE_VALUE, WAIT_TIMEOUT,
};
use windows_sys::Win32::Networking::WinSock::{
    AF_INET, AF_INET6, IPPROTO_ICMP, IPPROTO_ICMPV6, IPPROTO_TCP,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_FLAG_OVERLAPPED, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING, ReadFile,
    WriteFile,
};
use windows_sys::Win32::System::IO::{
    CancelIoEx, CreateIoCompletionPort, DeviceIoControl, GetQueuedCompletionStatus, OVERLAPPED,
};
use windows_sys::Win32::System::Services::{
    ChangeServiceConfigW, CloseServiceHandle, ControlService, OpenSCManagerW, OpenServiceW,
    QueryServiceConfigW, QueryServiceStatusEx, SC_MANAGER_CONNECT, SC_STATUS_PROCESS_INFO,
    SERVICE_CHANGE_CONFIG, SERVICE_CONTROL_STOP, SERVICE_DEMAND_START, SERVICE_DISABLED,
    SERVICE_QUERY_CONFIG, SERVICE_QUERY_STATUS, SERVICE_RUNNING, SERVICE_START, SERVICE_STATUS,
    SERVICE_STATUS_PROCESS, SERVICE_STOP_PENDING, SERVICE_STOPPED, StartServiceW,
};
const DRIVER_SERVICE_NAME: &str = "ddnpm";
const DRIVER_DEVICE_PATH: &str = r"\\.\ddnpm\transporthandle";

const SIGNATURE: u64 = 0xddfd00000017;
const SET_DATA_FILTER_IOCTL: u32 = 0x12200c;
const FILTER_DEFINITION_SIZE: u64 = 0xa0;
const FILTER_PACKET_HEADER_SIZE: usize = 0x48;
const FILTER_LAYER_TRANSPORT: u64 = 0x1;
const DIRECTION_INBOUND: u64 = 0x0;

const READ_BUFFER_COUNT: usize = 800;
const READ_BUFFER_SIZE: usize = 150;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct FilterAddress {
    pub af: u64,
    pub v4_address: [u8; 4],
    pub v4_padding: [u8; 4],
    pub v6_address: [u8; 16],
    pub mask: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct FilterDefinition {
    pub filter_version: u64,
    pub size: u64,
    pub filter_layer: u64,
    pub af: u64,
    pub local_address: FilterAddress,
    pub remote_address: FilterAddress,
    pub local_port: u64,
    pub remote_port: u64,
    pub protocol: u64,
    pub direction: u64,
    pub interface_index: u64,
    pub discard: u64,
}

#[repr(C)]
struct ReadBuffer {
    overlapped: OVERLAPPED,
    data: [u8; READ_BUFFER_SIZE],
}

// Read buffers are owned by the driver and only touched via IOCP on one thread.
unsafe impl Send for ReadBuffer {}

struct DriverState {
    in_use: AtomicU32,
}

static DRIVER_STATE: OnceLock<DriverState> = OnceLock::new();

fn driver_state() -> &'static DriverState {
    DRIVER_STATE.get_or_init(|| DriverState {
        in_use: AtomicU32::new(0),
    })
}

pub fn start_driver() -> io::Result<()> {
    let state = driver_state();
    let refs = state.in_use.fetch_add(1, Ordering::AcqRel) + 1;
    if refs != 1 {
        return Ok(());
    }
    if let Err(err) = start_driver_service(DRIVER_SERVICE_NAME) {
        state.in_use.fetch_sub(1, Ordering::AcqRel);
        return Err(err);
    }
    Ok(())
}

pub fn stop_driver() -> io::Result<()> {
    let state = driver_state();
    let refs = state.in_use.fetch_sub(1, Ordering::AcqRel);
    if refs == 0 {
        state.in_use.store(0, Ordering::Release);
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "stop_driver called without matching start",
        ));
    }
    if refs == 1 {
        return stop_driver_service(DRIVER_SERVICE_NAME, false);
    }
    Ok(())
}

pub fn new_source_sink_driver() -> io::Result<SourceSinkHandle> {
    let source = Box::new(SourceDriver::new()?);
    let sink = Box::new(SinkDriver::new()?);
    Ok(SourceSinkHandle {
        source,
        sink,
        must_close_port: false,
    })
}

struct DriverHandle {
    handle: HANDLE,
}

impl DriverHandle {
    fn new(flags: u32) -> io::Result<Self> {
        let mut wide_path = to_wide_null(DRIVER_DEVICE_PATH);
        const GENERIC_READ: u32 = 0x8000_0000;
        const GENERIC_WRITE: u32 = 0x4000_0000;
        let handle = unsafe {
            CreateFileW(
                wide_path.as_mut_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                std::ptr::null_mut(),
                OPEN_EXISTING,
                flags,
                0,
            )
        };
        if handle == 0 || handle == INVALID_HANDLE_VALUE {
            return Err(last_os_error("CreateFileW failed"));
        }
        Ok(Self { handle })
    }

    fn device_io_control(
        &self,
        io_control: u32,
        in_buffer: *const u8,
        in_size: u32,
        out_buffer: *mut u8,
        out_size: u32,
    ) -> io::Result<u32> {
        let mut bytes_returned = 0u32;
        let ok = unsafe {
            DeviceIoControl(
                self.handle,
                io_control,
                in_buffer as *mut _,
                in_size,
                out_buffer as *mut _,
                out_size,
                &mut bytes_returned,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(last_os_error("DeviceIoControl failed"));
        }
        Ok(bytes_returned)
    }

    fn cancel_io_ex(&self) -> io::Result<()> {
        let ok = unsafe { CancelIoEx(self.handle, std::ptr::null_mut()) };
        if ok == 0 {
            return Err(last_os_error("CancelIoEx failed"));
        }
        Ok(())
    }

    fn close(&self) -> io::Result<()> {
        let ok = unsafe { CloseHandle(self.handle) };
        if ok == 0 {
            return Err(last_os_error("CloseHandle failed"));
        }
        Ok(())
    }
}

pub struct SourceDriver {
    deadline: Option<Instant>,
    handle: Option<DriverHandle>,
    iocp: HANDLE,
    read_buffers: Vec<Box<ReadBuffer>>,
}

impl SourceDriver {
    pub fn new() -> io::Result<Self> {
        Ok(Self {
            deadline: None,
            handle: None,
            iocp: 0,
            read_buffers: Vec::new(),
        })
    }

    fn setup(&mut self) -> io::Result<()> {
        if let Some(handle) = &self.handle {
            handle.cancel_io_ex()?;
            unsafe {
                if self.iocp != 0 {
                    CloseHandle(self.iocp);
                }
            }
            handle.close()?;
            self.read_buffers.clear();
        }

        let handle = DriverHandle::new(FILE_FLAG_OVERLAPPED)?;
        let (iocp, buffers) = prepare_completion_buffers(handle.handle, READ_BUFFER_COUNT)?;
        self.iocp = iocp;
        self.read_buffers = buffers;
        self.handle = Some(handle);
        Ok(())
    }

    fn set_data_filters(&self, filters: &[FilterDefinition]) -> io::Result<()> {
        let handle = self
            .handle
            .as_ref()
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "driver handle not initialized"))?;
        for filter in filters {
            let mut id: i64 = 0;
            let in_ptr = filter as *const FilterDefinition as *const u8;
            let out_ptr = &mut id as *mut i64 as *mut u8;
            handle.device_io_control(
                SET_DATA_FILTER_IOCTL,
                in_ptr,
                mem::size_of::<FilterDefinition>() as u32,
                out_ptr,
                mem::size_of::<i64>() as u32,
            )?;
        }
        Ok(())
    }

    fn create_packet_filters(&self, spec: PacketFilterSpec) -> io::Result<Vec<FilterDefinition>> {
        let mut filters = Vec::new();
        filters.push(FilterDefinition {
            filter_version: SIGNATURE,
            size: FILTER_DEFINITION_SIZE,
            filter_layer: FILTER_LAYER_TRANSPORT,
            af: AF_INET as u64,
            direction: DIRECTION_INBOUND,
            protocol: IPPROTO_ICMP as u64,
            ..Default::default()
        });
        filters.push(FilterDefinition {
            filter_version: SIGNATURE,
            size: FILTER_DEFINITION_SIZE,
            filter_layer: FILTER_LAYER_TRANSPORT,
            af: AF_INET6 as u64,
            direction: DIRECTION_INBOUND,
            protocol: IPPROTO_ICMPV6 as u64,
            ..Default::default()
        });

        let mut extra = match spec.filter_type {
            PacketFilterType::Icmp | PacketFilterType::Udp => Vec::new(),
            PacketFilterType::Tcp => create_tcp_filters(spec),
            PacketFilterType::SynAck => create_synack_filters(spec),
            PacketFilterType::None => create_none_filters(),
        };

        filters.append(&mut extra);
        Ok(filters)
    }

    fn read_timeout_ms(&self) -> u32 {
        if let Some(deadline) = self.deadline {
            let now = Instant::now();
            if deadline <= now {
                return 0;
            }
            let dur = deadline.duration_since(now);
            return dur.as_millis().min(u32::MAX as u128) as u32;
        }
        0
    }
}

impl PacketSource for SourceDriver {
    fn set_read_deadline(&mut self, deadline: Instant) -> io::Result<()> {
        self.deadline = Some(deadline);
        Ok(())
    }

    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let handle = self
            .handle
            .as_ref()
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "driver handle not initialized"))?;

        let mut bytes_read: u32 = 0;
        let mut key: usize = 0;
        let mut overlapped: *mut OVERLAPPED = std::ptr::null_mut();
        let timeout_ms = self.read_timeout_ms();
        let ok = unsafe {
            GetQueuedCompletionStatus(
                self.iocp,
                &mut bytes_read,
                &mut key,
                &mut overlapped,
                timeout_ms,
            )
        };
        if ok == 0 {
            let err = unsafe { GetLastError() };
            if err == WAIT_TIMEOUT {
                return Err(io::Error::new(io::ErrorKind::TimedOut, "no packets ready"));
            }
            return Err(io::Error::from_raw_os_error(err as i32));
        }
        if overlapped.is_null() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "GetQueuedCompletionStatus returned null OVERLAPPED",
            ));
        }

        let buffer = unsafe { &mut *(overlapped as *mut ReadBuffer) };
        let header = FILTER_PACKET_HEADER_SIZE;
        let payload_len = bytes_read.saturating_sub(header as u32) as usize;
        let copy_len = payload_len.min(buf.len());
        if copy_len > 0 {
            buf[..copy_len].copy_from_slice(&buffer.data[header..header + copy_len]);
        }

        let ok = unsafe {
            ReadFile(
                handle.handle,
                buffer.data.as_mut_ptr(),
                buffer.data.len() as u32,
                std::ptr::null_mut(),
                &mut buffer.overlapped,
            )
        };
        if ok == 0 {
            let err = unsafe { GetLastError() };
            if err != ERROR_IO_PENDING {
                return Err(io::Error::from_raw_os_error(err as i32));
            }
        }
        Ok(copy_len)
    }

    fn close(&mut self) -> io::Result<()> {
        if let Some(handle) = &self.handle {
            let _ = handle.cancel_io_ex();
            if self.iocp != 0 {
                unsafe {
                    CloseHandle(self.iocp);
                }
                self.iocp = 0;
            }
            handle.close()?;
            self.handle = None;
            self.read_buffers.clear();
        }
        Ok(())
    }

    fn set_packet_filter(&mut self, spec: PacketFilterSpec) -> io::Result<()> {
        self.setup()?;
        let filters = self.create_packet_filters(spec)?;
        if filters.is_empty() {
            return Ok(());
        }
        self.set_data_filters(&filters)
    }
}

impl Drop for SourceDriver {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

pub struct SinkDriver {
    handle: DriverHandle,
}

impl SinkDriver {
    pub fn new() -> io::Result<Self> {
        Ok(Self {
            handle: DriverHandle::new(0)?,
        })
    }
}

impl PacketSink for SinkDriver {
    fn write_to(&mut self, buf: &[u8], _addr: SocketAddr) -> io::Result<()> {
        let ok = unsafe {
            WriteFile(
                self.handle.handle,
                buf.as_ptr(),
                buf.len() as u32,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            let err = unsafe { GetLastError() };
            return Err(io::Error::from_raw_os_error(err as i32));
        }
        Ok(())
    }

    fn close(&mut self) -> io::Result<()> {
        self.handle.close()
    }
}

impl Drop for SinkDriver {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

fn create_base_filter_definition(af: u64) -> FilterDefinition {
    FilterDefinition {
        filter_version: SIGNATURE,
        size: FILTER_DEFINITION_SIZE,
        filter_layer: FILTER_LAYER_TRANSPORT,
        af,
        interface_index: 0,
        direction: DIRECTION_INBOUND,
        ..Default::default()
    }
}

fn create_filter_address(addr: SocketAddr) -> FilterAddress {
    match addr {
        SocketAddr::V4(addr) => {
            let mut filter = FilterAddress::default();
            filter.af = AF_INET as u64;
            filter.v4_address = addr.ip().octets();
            filter.mask = 0xffff_ffff;
            filter
        }
        SocketAddr::V6(addr) => {
            let mut filter = FilterAddress::default();
            filter.af = AF_INET6 as u64;
            filter.v6_address = addr.ip().octets();
            filter.mask = 0xffff_ffff_ffff_ffff;
            filter
        }
    }
}

fn get_address_family(addr: SocketAddr) -> u64 {
    match addr {
        SocketAddr::V4(_) => AF_INET as u64,
        SocketAddr::V6(_) => AF_INET6 as u64,
    }
}

fn create_tcp_filters(spec: PacketFilterSpec) -> Vec<FilterDefinition> {
    let af = get_address_family(spec.filter_config.dst);
    let mut capture = create_base_filter_definition(af);
    capture.protocol = IPPROTO_TCP as u64;
    capture.local_address = create_filter_address(spec.filter_config.dst);
    capture.remote_address = create_filter_address(spec.filter_config.src);
    capture.local_port = spec.filter_config.dst.port() as u64;
    capture.remote_port = spec.filter_config.src.port() as u64;

    let mut discard = capture;
    discard.discard = 1;

    vec![capture, discard]
}

fn create_synack_filters(spec: PacketFilterSpec) -> Vec<FilterDefinition> {
    let af = get_address_family(spec.filter_config.src);
    let mut capture = create_base_filter_definition(af);
    capture.protocol = IPPROTO_TCP as u64;
    capture.remote_address = create_filter_address(spec.filter_config.src);
    capture.remote_port = spec.filter_config.src.port() as u64;

    let mut discard = capture;
    discard.discard = 1;

    vec![capture, discard]
}

fn create_none_filters() -> Vec<FilterDefinition> {
    let mut filters = Vec::new();
    let ipv4_capture = create_base_filter_definition(AF_INET as u64);
    let mut ipv4_discard = ipv4_capture;
    ipv4_discard.discard = 1;

    let ipv6_capture = create_base_filter_definition(AF_INET6 as u64);
    let mut ipv6_discard = ipv6_capture;
    ipv6_discard.discard = 1;

    filters.push(ipv4_capture);
    filters.push(ipv4_discard);
    filters.push(ipv6_capture);
    filters.push(ipv6_discard);
    filters
}

fn prepare_completion_buffers(
    handle: HANDLE,
    count: usize,
) -> io::Result<(HANDLE, Vec<Box<ReadBuffer>>)> {
    let iocp = unsafe { CreateIoCompletionPort(handle, 0, 0, 0) };
    if iocp == 0 {
        return Err(last_os_error("CreateIoCompletionPort failed"));
    }

    let mut buffers = Vec::with_capacity(count);
    for _ in 0..count {
        let mut buffer = Box::new(ReadBuffer {
            overlapped: unsafe { mem::zeroed() },
            data: [0; READ_BUFFER_SIZE],
        });

        let ok = unsafe {
            ReadFile(
                handle,
                buffer.data.as_mut_ptr(),
                buffer.data.len() as u32,
                std::ptr::null_mut(),
                &mut buffer.overlapped,
            )
        };
        if ok == 0 {
            let err = unsafe { GetLastError() };
            if err != ERROR_IO_PENDING {
                unsafe {
                    CloseHandle(iocp);
                }
                return Err(io::Error::from_raw_os_error(err as i32));
            }
        }
        buffers.push(buffer);
    }

    Ok((iocp, buffers))
}

fn to_wide_null(value: &str) -> Vec<u16> {
    let mut wide: Vec<u16> = value.encode_utf16().collect();
    wide.push(0);
    wide
}

fn last_os_error(message: &str) -> io::Error {
    let err = unsafe { GetLastError() };
    io::Error::new(io::ErrorKind::Other, format!("{}: {}", message, err))
}

fn start_driver_service(name: &str) -> io::Result<()> {
    let manager = unsafe { OpenSCManagerW(std::ptr::null(), std::ptr::null(), SC_MANAGER_CONNECT) };
    if manager == 0 {
        return Err(last_os_error("OpenSCManagerW failed"));
    }
    let service = unsafe {
        OpenServiceW(
            manager,
            to_wide_null(name).as_ptr(),
            SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG | SERVICE_CHANGE_CONFIG | SERVICE_START,
        )
    };
    if service == 0 {
        unsafe {
            CloseServiceHandle(manager);
        }
        return Err(last_os_error("OpenServiceW failed"));
    }

    let mut status: SERVICE_STATUS_PROCESS = unsafe { MaybeUninit::zeroed().assume_init() };
    let mut bytes_needed = 0u32;
    let ok = unsafe {
        QueryServiceStatusEx(
            service,
            SC_STATUS_PROCESS_INFO,
            &mut status as *mut _ as *mut u8,
            mem::size_of::<SERVICE_STATUS_PROCESS>() as u32,
            &mut bytes_needed,
        )
    };
    if ok == 0 {
        unsafe {
            CloseServiceHandle(service);
            CloseServiceHandle(manager);
        }
        return Err(last_os_error("QueryServiceStatusEx failed"));
    }
    if status.dwCurrentState == SERVICE_RUNNING || status.dwCurrentState == SERVICE_STOP_PENDING {
        unsafe {
            CloseServiceHandle(service);
            CloseServiceHandle(manager);
        }
        return Ok(());
    }

    if is_service_disabled(service)? {
        let ok = unsafe {
            ChangeServiceConfigW(
                service,
                u32::MAX,
                SERVICE_DEMAND_START,
                u32::MAX,
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null_mut(),
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
            )
        };
        if ok == 0 {
            unsafe {
                CloseServiceHandle(service);
                CloseServiceHandle(manager);
            }
            return Err(last_os_error("ChangeServiceConfigW failed"));
        }
    }

    let ok = unsafe { StartServiceW(service, 0, std::ptr::null()) };
    if ok == 0 {
        let err = unsafe { GetLastError() };
        if err != ERROR_SERVICE_ALREADY_RUNNING {
            unsafe {
                CloseServiceHandle(service);
                CloseServiceHandle(manager);
            }
            return Err(io::Error::from_raw_os_error(err as i32));
        }
    }

    unsafe {
        CloseServiceHandle(service);
        CloseServiceHandle(manager);
    }
    Ok(())
}

fn stop_driver_service(name: &str, disable: bool) -> io::Result<()> {
    let manager = unsafe { OpenSCManagerW(std::ptr::null(), std::ptr::null(), SC_MANAGER_CONNECT) };
    if manager == 0 {
        return Err(last_os_error("OpenSCManagerW failed"));
    }
    let service = unsafe {
        OpenServiceW(
            manager,
            to_wide_null(name).as_ptr(),
            SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG | SERVICE_CHANGE_CONFIG,
        )
    };
    if service == 0 {
        unsafe {
            CloseServiceHandle(manager);
        }
        return Err(last_os_error("OpenServiceW failed"));
    }

    let mut status: SERVICE_STATUS_PROCESS = unsafe { MaybeUninit::zeroed().assume_init() };
    let mut bytes_needed = 0u32;
    let ok = unsafe {
        QueryServiceStatusEx(
            service,
            SC_STATUS_PROCESS_INFO,
            &mut status as *mut _ as *mut u8,
            mem::size_of::<SERVICE_STATUS_PROCESS>() as u32,
            &mut bytes_needed,
        )
    };
    if ok == 0 {
        unsafe {
            CloseServiceHandle(service);
            CloseServiceHandle(manager);
        }
        return Err(last_os_error("QueryServiceStatusEx failed"));
    }

    if status.dwCurrentState == SERVICE_RUNNING {
        let mut service_status: SERVICE_STATUS = unsafe { MaybeUninit::zeroed().assume_init() };
        let ok = unsafe { ControlService(service, SERVICE_CONTROL_STOP, &mut service_status) };
        if ok == 0 {
            unsafe {
                CloseServiceHandle(service);
                CloseServiceHandle(manager);
            }
            return Err(last_os_error("ControlService failed"));
        }
    } else if status.dwCurrentState == SERVICE_STOPPED
        || status.dwCurrentState == SERVICE_STOP_PENDING
    {
        // Already stopping or stopped.
    }

    if disable {
        let ok = unsafe {
            ChangeServiceConfigW(
                service,
                u32::MAX,
                SERVICE_DISABLED,
                u32::MAX,
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null_mut(),
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
            )
        };
        if ok == 0 {
            unsafe {
                CloseServiceHandle(service);
                CloseServiceHandle(manager);
            }
            return Err(last_os_error("ChangeServiceConfigW failed"));
        }
    }

    unsafe {
        CloseServiceHandle(service);
        CloseServiceHandle(manager);
    }
    Ok(())
}

fn is_service_disabled(service: isize) -> io::Result<bool> {
    let mut bytes_needed = 0u32;
    let ok = unsafe { QueryServiceConfigW(service, std::ptr::null_mut(), 0, &mut bytes_needed) };
    if ok != 0 {
        return Ok(false);
    }
    let err = unsafe { GetLastError() };
    if err != ERROR_INSUFFICIENT_BUFFER {
        return Err(io::Error::from_raw_os_error(err as i32));
    }
    let mut buffer = vec![0u8; bytes_needed as usize];
    let ok = unsafe {
        QueryServiceConfigW(
            service,
            buffer.as_mut_ptr() as *mut _,
            bytes_needed,
            &mut bytes_needed,
        )
    };
    if ok == 0 {
        return Err(last_os_error("QueryServiceConfigW failed"));
    }
    let config = unsafe {
        &*(buffer.as_ptr() as *const windows_sys::Win32::System::Services::QUERY_SERVICE_CONFIGW)
    };
    Ok(config.dwStartType == SERVICE_DISABLED)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::FilterConfig;

    #[test]
    #[ignore]
    fn start_driver_smoke() {
        start_driver().expect("start driver");
    }

    #[test]
    fn filter_construction_smoke() {
        let spec = PacketFilterSpec {
            filter_type: PacketFilterType::Tcp,
            filter_config: FilterConfig {
                src: "192.0.2.1:1234".parse().unwrap(),
                dst: "192.0.2.2:80".parse().unwrap(),
            },
        };
        let driver = SourceDriver::new().expect("source driver");
        let filters = driver.create_packet_filters(spec).expect("filters");
        assert!(!filters.is_empty());
    }
}
