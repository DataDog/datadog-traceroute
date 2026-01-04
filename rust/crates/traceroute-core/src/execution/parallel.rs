//! Parallel traceroute execution.
//!
//! Sends all probes in quick succession and collects responses asynchronously.

use crate::{ProbeResponse, TracerouteDriver, TracerouteError, TracerouteParams};
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{debug, trace};

/// Executes a traceroute using parallel probe sending.
///
/// This sends all probes in quick succession (with `send_delay` between them)
/// and collects responses asynchronously. More efficient for high-latency networks.
pub async fn traceroute_parallel<D: TracerouteDriver>(
    driver: &mut D,
    params: &TracerouteParams,
) -> Result<Vec<Option<ProbeResponse>>, TracerouteError> {
    params.validate()?;

    let driver_info = driver.get_driver_info();
    if !driver_info.supports_parallel {
        return Err(TracerouteError::ParallelNotSupported);
    }

    let results = Arc::new(Mutex::new(vec![
        None;
        params.max_ttl as usize + 1
    ]));
    let found_dest = Arc::new(std::sync::atomic::AtomicBool::new(false));

    let max_timeout = params.max_timeout();

    // We need to run sender and receiver concurrently
    // Since we only have one driver, we'll use a different approach:
    // Send all probes first, then receive

    // Phase 1: Send all probes
    debug!("Phase 1: Sending all probes");
    for ttl in params.min_ttl..=params.max_ttl {
        trace!(ttl = ttl, "Sending probe");
        driver.send_probe(ttl).await?;
        tokio::time::sleep(params.send_delay).await;
    }

    // Phase 2: Receive responses until timeout or destination found
    debug!("Phase 2: Receiving responses");
    let receive_deadline = tokio::time::Instant::now() + max_timeout;

    while tokio::time::Instant::now() < receive_deadline {
        if found_dest.load(std::sync::atomic::Ordering::Relaxed) {
            break;
        }

        match driver.receive_probe(params.poll_frequency).await {
            Ok(Some(probe)) => {
                debug!(
                    ttl = probe.ttl,
                    ip = %probe.ip,
                    rtt_ms = probe.rtt.as_secs_f64() * 1000.0,
                    is_dest = probe.is_dest,
                    "Received probe response"
                );

                let mut results_guard = results.lock().await;
                let existing = &results_guard[probe.ttl as usize];

                // Only update if we don't have a response yet, or if we're upgrading
                // from an ICMP response to a destination response
                if existing.is_none() || (probe.is_dest && !existing.as_ref().map(|p: &ProbeResponse| p.is_dest).unwrap_or(false)) {
                    if probe.is_dest {
                        found_dest.store(true, std::sync::atomic::Ordering::Relaxed);
                    }
                    results_guard[probe.ttl as usize] = Some(probe);
                }
            }
            Ok(None) => {
                // No packet available, continue polling
                continue;
            }
            Err(e) if e.is_retryable() => {
                trace!(error = %e, "Retryable error, continuing");
                continue;
            }
            Err(e) => {
                debug!(error = %e, "Fatal error during receive");
                return Err(e);
            }
        }
    }

    let final_results = Arc::try_unwrap(results)
        .map_err(|_| TracerouteError::Internal("Failed to unwrap results".into()))?
        .into_inner();

    Ok(clip_results(params.min_ttl, final_results))
}

/// Clips the results vector to remove leading None entries before min_ttl.
fn clip_results(min_ttl: u8, results: Vec<Option<ProbeResponse>>) -> Vec<Option<ProbeResponse>> {
    results.into_iter().skip(min_ttl as usize).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_clip_results() {
        let results = vec![
            None,
            Some(ProbeResponse {
                ttl: 1,
                ip: "10.0.0.1".parse().unwrap(),
                rtt: std::time::Duration::from_millis(10),
                is_dest: false,
            }),
            None,
            None,
        ];

        let clipped = clip_results(1, results);
        assert_eq!(clipped.len(), 3);
        assert!(clipped[0].is_some());
    }
}
