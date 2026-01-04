# Rust Core Traceroute Design

This document captures the core traceroute engine behavior that must be preserved in Rust.
It covers parameter handling, orchestration, serial/parallel drivers, and normalization semantics.

## Core Data Flow

High-level pipeline:

1. Validate inputs and resolve destination (host + port).
2. Run N traceroute runs (parallel goroutines).
3. Run M e2e probes (parallel goroutines, with delay).
4. Optionally collect source public IP.
5. Populate protocol/destination metadata.
6. Optionally enrich reverse DNS.
7. Normalize results (run IDs, reachable flags, hop stats, e2e stats).
8. Optionally remove private hops.

## TracerouteParams (Go -> Rust)

Go fields to preserve:

- `Hostname` (string)
- `Port` (int)
- `Protocol` (string: `udp|tcp|icmp`)
- `MinTTL` (int)
- `MaxTTL` (int)
- `Delay` (int, ms)
- `Timeout` (time.Duration)
- `TCPMethod` (string: `syn|sack|prefer_sack|syn_socket`)
- `WantV6` (bool)
- `TCPSynParisTracerouteMode` (bool)
- `ReverseDns` (bool)
- `CollectSourcePublicIP` (bool)
- `TracerouteQueries` (int)
- `E2eQueries` (int)
- `UseWindowsDriver` (bool)
- `SkipPrivateHops` (bool)

Rust should mirror this struct and map CLI/server params to the same defaults.

## Orchestration: RunTraceroute

Behavior (from `traceroute/traceroute.go`):

- If `Port == 0`, use `common.DefaultPort`.
- Call `runTracerouteMulti()`.
- Set `results.Protocol` and `results.Destination`.
- If `ReverseDns`, call `results.EnrichWithReverseDns()`.
- Call `results.Normalize()`.
- If `SkipPrivateHops`, call `results.RemovePrivateHops()`.

### runTracerouteMulti

- Launch `TracerouteQueries` runs concurrently:
  - Each run calls `runTracerouteOnce()`.
  - Successful runs append to `results.Traceroute.Runs` (order is nondeterministic).
  - Errors are aggregated; if any error exists, return an error and no results.
- For e2e probes:
  - If `E2eQueries > 0`, compute delay:
    - `delay = (MaxTTL * Timeout) / E2eQueries`
    - Clamp to 1s max.
  - Spawn one goroutine per e2e probe, sleeping `delay` between launches.
  - On error, append `0.0` to `E2eProbe.RTTs`.
  - On success, append RTT in ms to `E2eProbe.RTTs`.
- If `CollectSourcePublicIP`:
  - Call public IP fetcher concurrently.
  - On error, ignore and leave `source.public_ip` empty.

Errors are combined using `errors.Join` in Go. Rust should aggregate errors so
tests can assert multiple error substrings.

## runTracerouteOnce (per protocol)

Dispatch by `Protocol`:

- UDP:
  - Resolve target with `parseTarget(hostname, destinationPort, wantV6)`.
  - Use `udp.NewUDPv4(...)` and call `Traceroute()`.
- TCP:
  - Resolve target.
  - `doSyn`: `tcp.NewTCPv4(...).Traceroute()`.
  - `doSack`: `sack.RunSackTraceroute(...)`.
  - `doSynSocket`: `tcp.NewTCPv4(...).TracerouteSequentialSocket()`.
  - Use `performTCPFallback()` based on `TCPMethod`.
- ICMP:
  - Resolve target with port 80.
  - Build `icmp.Params` with `common.TracerouteParallelParams`:
    - `MinTTL`, `MaxTTL`, `TracerouteTimeout`, `PollFrequency=100ms`,
      `SendDelay=Delay`.
  - `icmp.RunICMPTraceroute(ctx, cfg)`.

Errors are wrapped with context strings (e.g., `invalid target`, `could not generate udp traceroute results`).

## E2E Probe Semantics

From `runE2eProbeOnce`:

- Set `MinTTL = MaxTTL` to probe only the destination.
- If protocol is TCP and method is `sack` or `prefer_sack`, force method to `syn`.
- Call `runTracerouteOnce`.
- If destination hop not found, return `0`.
- Otherwise return destination hop RTT in ms.

## Target Resolution (`parseTarget`)

- If no port is provided, append `defaultPort`.
- If host is not an IP, do DNS lookup:
  - If `wantIPv6`, pick first IPv6.
  - Else pick first IPv4.
  - If no suitable address found, return error.
- Validate port in `1..65535`.

## Serial vs Parallel Drivers

### Serial (`common.TracerouteSerial`)

- Loop TTL from `MinTTL` to `MaxTTL`.
- For each TTL:
  - `SendProbe(ttl)`, then poll `ReceiveProbe(PollFrequency)` until timeout.
  - Retry on `ReceiveProbeNoPktError` and `BadPacketError`.
  - Stop early when destination is found.
- Respect `SendDelay` between probes.
- On context cancellation, return `ctx.Err()`.

### Parallel (`common.TracerouteParallel`)

- Requires `driver.SupportsParallel = true`.
- Use `MaxTimeout = TracerouteTimeout + SendDelay * ProbeCount`.
- Launch sender goroutine (SendProbe in loop with SendDelay).
- Launch receiver goroutine:
  - Wait until first probe is sent (Windows raw socket constraint).
  - Read probes until timeout or context cancel.
  - Track first probe per TTL; do not overwrite with later probes unless
    the newer probe is a destination response.
  - When destination is found, cancel sender but keep reading.
- Return trimmed results `clipResults(MinTTL, results)`.

## Result Normalization

From `result.Normalize()`:

- Assign a UUID `run_id` to each run.
- Set hop `reachable=true` when `ip_address` is non-empty.
- Compute hop_count stats based on trailing empty hops.
- E2E stats:
  - `packets_sent = len(rtts)`
  - `packets_received = count(rtt > 0)`
  - `packet_loss_percentage = (sent - received) / sent`
  - `rtt.avg/min/max` based on non-zero RTTs
  - `jitter = mean(abs(diff consecutive RTTs))`

These normalization semantics must be preserved in Rust.
