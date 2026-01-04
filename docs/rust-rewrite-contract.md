# Rust Rewrite Contract

This document freezes the external behavior and compatibility contract that the Rust rewrite must preserve.
It is a checklist for parity across CLI, server API, output schema, and platform-specific behavior.

## Compatibility Objectives

- Preserve CLI interface, flags, defaults, and output semantics.
- Preserve HTTP server REST API endpoints, query parameters, defaults, and errors.
- Preserve JSON output schema and field semantics for traceroute results.
- Preserve platform-specific behavior and Windows driver integration.
- Ensure unit + e2e tests pass locally and on GitHub CI (GitHub-hosted runners).

## CLI Contract (datadog-traceroute)

Binary name: `datadog-traceroute`

Usage:

```
datadog-traceroute [target]
```

Flags and defaults:

- `-P, --proto`: default `udp`. Values: `udp`, `tcp`, `icmp`.
- `-p, --port`: default `33434`.
- `-q, --traceroute-queries`: default `3`.
- `-m, --max-ttl`: default `30`.
- `-v, --verbose`: default `false`.
- `--tcp-method`: default `syn`. Values: `syn`, `sack`, `prefer_sack`.
- `--ipv6`: default `false`.
- `--timeout`: default `0` (interpreted as `common.DefaultNetworkPathTimeout` ms).
- `--reverse-dns`: default `false`.
- `--source-public-ip`: default `false`.
- `-Q, --e2e-queries`: default `50`.
- `--windows-driver`: default `false`.
- `--skip-private-hops`: default `false`.

Behavior:

- Requires exactly one positional argument `target`.
- JSON output is printed to stdout, formatted with 2-space indentation.
- On error, exits with non-zero status and writes error to stderr.
- `--verbose` sets log level to trace.
- If `--windows-driver` is set, driver is started before traceroute execution.

## HTTP Server Contract (datadog-traceroute-server)

Binary name: `datadog-traceroute-server`

Usage:

```
datadog-traceroute-server
```

Flags and defaults:

- `-a, --addr`: default `:3765`.
- `-l, --log-level`: default `info`. Values: `error`, `warn`, `info`, `debug`, `trace`.

Endpoints:

- `GET /traceroute`

Query parameters and defaults:

- `target` (required).
- `protocol`: default `udp`.
- `port`: default `33434`.
- `traceroute-queries`: default `3`.
- `max-ttl`: default `30`.
- `timeout`: default `common.DefaultNetworkPathTimeout` ms.
- `tcp-method`: default `syn`.
- `e2e-queries`: default `50`.
- `ipv6`: default `false`.
- `reverse-dns`: default `false`.
- `source-public-ip`: default `false`.
- `windows-driver`: default `false`.
- `skip-private-hops`: default `false`.

Error handling:

- Non-GET methods: HTTP 405.
- Missing target: HTTP 400 with `Invalid parameters: missing required parameter: target`.
- Traceroute failure: HTTP 500 with `Traceroute failed: <error>`.
- JSON encoding failure: HTTP 500 with `Failed to encode response: <error>`.

## Output Schema (JSON)

The Rust implementation must preserve the output JSON structure, field names, and serialization formats.
The schema is defined by:

- `common/traceroute_types.go`
- `result/result.go`

### Field-Level Schema

Top-level:

- `protocol` (string): `udp`, `tcp`, `icmp`.
- `source` (object):
  - `public_ip` (string): may be empty if not collected.
- `destination` (object):
  - `hostname` (string): input target hostname or IP.
  - `port` (number): integer; for ICMP typically `0` or default port.
- `traceroute` (object):
  - `runs` (array): list of traceroute runs.
  - `hop_count` (object):
    - `avg` (number, float)
    - `min` (number, int)
    - `max` (number, int)
- `e2e_probe` (object):
  - `rtts` (array of number): RTTs in milliseconds; `0` indicates no response.
  - `packets_sent` (number, int)
  - `packets_received` (number, int)
  - `packet_loss_percentage` (number, float): fraction in [0,1], not 0-100.
  - `jitter` (number, float): mean absolute difference of consecutive RTTs (ms).
  - `rtt` (object):
    - `avg` (number, float, ms)
    - `min` (number, float, ms)
    - `max` (number, float, ms)

Traceroute run:

- `run_id` (string, UUID)
- `source` (object):
  - `ip_address` (string): IPv4/IPv6 textual form.
  - `port` (number, int)
- `destination` (object):
  - `ip_address` (string)
  - `port` (number, int)
  - `reverse_dns` (array of string, optional)
- `hops` (array):
  - `ttl` (number, int)
  - `ip_address` (string): empty string when unreachable.
  - `rtt` (number, float, ms): zero when unreachable.
  - `reachable` (boolean)
  - `reverse_dns` (array of string, optional)

Serialization rules:

- `net.IP` fields marshal as strings (text form, not base64).
- `reverse_dns` uses `omitempty` (absent if empty).
- Internal fields are not serialized: `is_dest`, `port`, `icmp_type`, `icmp_code`.

### Golden JSON Example

```json
{
  "protocol": "udp",
  "source": {
    "public_ip": "203.0.113.10"
  },
  "destination": {
    "hostname": "example.com",
    "port": 33434
  },
  "traceroute": {
    "runs": [
      {
        "run_id": "7f3fcb63-6e54-4a8a-9f8c-3b8edb3e91ac",
        "source": {
          "ip_address": "192.0.2.10",
          "port": 54321
        },
        "destination": {
          "ip_address": "93.184.216.34",
          "port": 33434,
          "reverse_dns": [
            "example.com"
          ]
        },
        "hops": [
          {
            "ttl": 1,
            "ip_address": "192.0.2.1",
            "rtt": 1.2,
            "reachable": true
          },
          {
            "ttl": 2,
            "ip_address": "",
            "rtt": 0,
            "reachable": false
          },
          {
            "ttl": 3,
            "ip_address": "93.184.216.34",
            "rtt": 12.7,
            "reachable": true,
            "reverse_dns": [
              "example.com"
            ]
          }
        ]
      }
    ],
    "hop_count": {
      "avg": 3,
      "min": 3,
      "max": 3
    }
  },
  "e2e_probe": {
    "rtts": [
      12.7,
      12.5,
      0,
      12.9
    ],
    "packets_sent": 4,
    "packets_received": 3,
    "packet_loss_percentage": 0.25,
    "jitter": 0.3,
    "rtt": {
      "avg": 12.7,
      "min": 12.5,
      "max": 12.9
    }
  }
}
```

Contract must be updated with any schema updates during the rewrite. Use the golden JSON example in tests to ensure field parity.

## Default Constants

Defined in `common/common.go`:

- `DefaultNetworkPathTimeout`: `3000` ms
- `DefaultPort`: `33434`
- `DefaultTracerouteQueries`: `3`
- `DefaultNumE2eProbes`: `50`
- `DefaultMinTTL`: `1`
- `DefaultMaxTTL`: `30`
- `DefaultDelay`: `50` ms
- `DefaultProtocol`: `udp`
- `DefaultTcpMethod`: `syn`
- `DefaultWantV6`: `false`
- `DefaultReverseDns`: `false`
- `DefaultCollectSourcePublicIP`: `false`
- `DefaultUseWindowsDriver`: `false`
- `DefaultSkipPrivateHops`: `false`

## Platform Support Matrix (IPv4)

Linux:
- ICMP: supported
- UDP: supported
- TCP SYN: supported
- TCP SACK: supported

Windows Server:
- ICMP: supported
- UDP: supported
- TCP SYN: supported
- TCP SACK: supported (requires Windows driver)

Windows Client:
- ICMP: supported (requires Windows driver)
- UDP: supported (requires Windows driver)
- TCP SYN: supported (requires Windows driver)
- TCP SACK: supported (requires Windows driver)
- TCP SYN socket: supported

macOS:
- ICMP: supported
- UDP: supported
- TCP SYN: supported
- TCP SACK: supported

## Support vs CI Coverage

- The Rust rewrite must implement full protocol support across all platforms listed above.
- GitHub-hosted runner limitations may prevent full e2e coverage; CI expectations must encode those limits.
- A protocol/OS combination that is not testable on hosted runners is still required to be supported.

## Test Contract

- Unit tests must cover all protocol drivers, packet parsers, and output aggregation behavior.
- E2E tests must validate:
  - CLI output JSON fields and types.
  - HTTP server response JSON fields and types.
  - All protocols across Linux, Windows, and macOS.
  - Localhost, public target, and fake network targets (fake network on Linux).
  - Key fields: destination, protocol, traceroute runs, hop stats, e2e probe stats, source public IP.

### GitHub-Hosted Runner Expectation Matrix

Due to known GitHub-hosted runner network restrictions and platform limitations, the e2e tests must encode
explicit expectations per protocol/target/OS. These constraints are treated as pass conditions.

Limitations summary (hosted runners):

- ICMP public targets: blocked on Linux and Windows; macOS works.
- UDP: public targets fail on Linux; localhost + public fail on Windows and macOS.
- TCP SACK: unsupported or flaky on multiple OS/targets; must validate expected error strings.
- Intermediate hops: often missing on Linux/Windows public targets; macOS TCP public targets can show hops.

Expectation matrix (high-level):

- Linux:
  - ICMP: localhost pass, public fail, fake network pass.
  - UDP: localhost pass, public fail, fake network pass.
  - TCP SYN: localhost pass, public pass, fake network pass.
  - TCP SACK: localhost fail (expected), public pass, fake network fail (expected).
- Windows:
  - ICMP: localhost pass, public fail.
  - UDP: localhost fail (expected), public fail (expected).
  - TCP SYN: localhost pass, public pass.
  - TCP SACK: localhost fail (expected), public fail (expected).
- macOS:
  - ICMP: localhost pass, public pass.
  - UDP: localhost fail (expected), public fail (expected).
  - TCP SYN: localhost pass, public pass.
  - TCP SACK: localhost fail (expected), public pass but allow retries/flakiness.

The Rust e2e suite must mirror the above expectations to avoid false failures on GitHub-hosted runners.

## CI Gate

- All unit tests and e2e tests must pass locally.
- All CI checks must pass on GitHub Actions (GitHub-hosted runner matrix).
- GitHub MCP must be used to confirm green checks before declaring completion.
