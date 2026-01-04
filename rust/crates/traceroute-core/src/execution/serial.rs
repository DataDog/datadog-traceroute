//! Serial traceroute execution.
//!
//! Sends one probe at a time and waits for a response before sending the next.

use crate::{ProbeResponse, TracerouteDriver, TracerouteError, TracerouteParams};
use tokio::time::timeout;
use tracing::{debug, trace};

/// Executes a traceroute using serial probe sending.
///
/// This sends one probe at a time and waits for a response (or timeout)
/// before sending the next probe. This is simpler but slower than parallel mode.
pub async fn traceroute_serial<D: TracerouteDriver + ?Sized>(
    driver: &mut D,
    params: &TracerouteParams,
) -> Result<Vec<Option<ProbeResponse>>, TracerouteError> {
    params.validate()?;

    let mut results = vec![None; params.max_ttl as usize + 1];

    for ttl in params.min_ttl..=params.max_ttl {
        let send_time = tokio::time::Instant::now();

        debug!(ttl = ttl, "Sending probe");
        driver.send_probe(ttl).await?;

        // Wait for response with timeout
        let probe_result = timeout(params.timeout, async {
            loop {
                match driver.receive_probe(params.poll_frequency).await {
                    Ok(Some(p)) => return Ok(p),
                    Ok(None) => continue,
                    Err(e) if e.is_retryable() => {
                        trace!(error = %e, "Retryable error, continuing");
                        continue;
                    }
                    Err(e) => return Err(e),
                }
            }
        })
        .await;

        match probe_result {
            Ok(Ok(probe)) => {
                let is_dest = probe.is_dest;
                let ttl_idx = probe.ttl as usize;
                debug!(
                    ttl = probe.ttl,
                    ip = %probe.ip,
                    rtt_ms = probe.rtt.as_secs_f64() * 1000.0,
                    is_dest = is_dest,
                    "Received probe response"
                );
                results[ttl_idx] = Some(probe);
                if is_dest {
                    debug!("Reached destination, stopping");
                    break;
                }
            }
            Ok(Err(e)) => {
                debug!(ttl = ttl, error = %e, "Fatal error during receive");
                return Err(e);
            }
            Err(_) => {
                debug!(ttl = ttl, "Timeout waiting for response");
                // Timeout, leave as None
            }
        }

        // Ensure minimum delay between probes
        let elapsed = send_time.elapsed();
        if elapsed < params.send_delay {
            tokio::time::sleep(params.send_delay - elapsed).await;
        }
    }

    // Clip results to only include valid TTL range
    Ok(clip_results(params.min_ttl, results))
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
