//! Platform-specific packet I/O implementations.

#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(target_os = "macos")]
pub mod darwin;

#[cfg(target_os = "windows")]
pub mod windows;

use crate::SourceSinkHandle;
use std::net::IpAddr;
use traceroute_core::TracerouteError;

/// Creates a Source and Sink appropriate for the current platform.
pub async fn new_source_sink(
    _target_addr: IpAddr,
    _use_driver: bool,
) -> Result<SourceSinkHandle, TracerouteError> {
    #[cfg(target_os = "linux")]
    return linux::new_source_sink(_target_addr).await;

    #[cfg(target_os = "macos")]
    return darwin::new_source_sink(_target_addr).await;

    #[cfg(target_os = "windows")]
    return windows::new_source_sink(_target_addr, _use_driver).await;

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    return Err(TracerouteError::Internal(
        "Unsupported platform".to_string(),
    ));
}

/// Starts the platform driver if applicable (Windows only, no-op elsewhere).
pub fn start_driver() -> Result<(), TracerouteError> {
    #[cfg(target_os = "windows")]
    return windows::start_driver();

    #[cfg(not(target_os = "windows"))]
    Ok(())
}
