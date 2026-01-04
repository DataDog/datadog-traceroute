//! Execution modes for traceroute.
//!
//! Provides both serial and parallel execution strategies.

pub mod parallel;
pub mod serial;

pub use parallel::traceroute_parallel;
pub use serial::traceroute_serial;
