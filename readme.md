# Datadog Traceroute

Datadog Traceroute produce traceroute results reflecting real traffic paths.

## Support Matrix for IPv4

### Linux

| Protocol-Variant | Supported |  Traceroute CLI |
|------------------|:---------:|----------------:|
| ICMP             |    Yes    | `traceroute -I` |
| UDP              |    Yes    |    `traceroute` |
| TCP SYN          |    Yes    | `tcptraceroute` |
| TCP SACK         |    Yes    |                 |

### Windows

*Windows Server:*

| Protocol-Variant |       Supported       | Traceroute CLI |
|------------------|:---------------------:|---------------:|
| ICMP             |          Yes          |      `tracert` |
| UDP              |          Yes          |                |
| TCP SYN          |          Yes          |                |
| TCP SACK         | Yes (req. win driver) |                |

*Windows Client:*

| Protocol-Variant |         Supported          | Traceroute CLI |
|------------------|:--------------------------:|---------------:|
| ICMP             |   Yes (req. win driver)    |      `tracert` |
| UDP              |   Yes (req. win driver)    |                |
| TCP SYN          |   Yes (req. win driver)    |                |
| TCP SACK         |   Yes (req. win driver)    |                |
| TCP SYN SOCKET   |            Yes             |                |

Note: Default firewall on windows can block the ICMP responses when not using Windows Driver.
Note2: TCP syn_socket is only useful for Windows Client without Windows Driver.

### macOS

| Protocol-Variant | Supported |  Traceroute CLI |
|------------------|:---------:|----------------:|
| ICMP             |    Yes    | `traceroute -I` |
| UDP              |    Yes    |    `traceroute` |
| TCP SYN          |    Yes    | `tcptraceroute` |
| TCP SACK         |    Yes    |                 |


## IPv6 Support

IPv6 is only partially supported.

Note: Windows driver is needed for all protocol-variant for IPv6s on server versions.

# Getting Started

## Prerequisites

- Go 1.25.6+
- Root/administrator privileges (required for raw sockets)

## Building

```bash
# Build the CLI
make build
# or: go build .

# Build the HTTP server
make build-server
```

## CLI Usage

```bash
sudo ./datadog-traceroute [flags] <target>
```

### Examples

```bash
# UDP traceroute (default)
sudo ./datadog-traceroute google.com

# TCP SYN traceroute on port 443
sudo ./datadog-traceroute -P tcp -p 443 google.com

# ICMP traceroute with reverse DNS
sudo ./datadog-traceroute -P icmp --reverse-dns google.com

# TCP SACK traceroute with verbose output
sudo ./datadog-traceroute -P tcp --tcp-method sack -p 443 -v google.com

# IPv6 traceroute
sudo ./datadog-traceroute --ipv6 google.com
```

Output is JSON.

An expired total timeout returns `context.DeadlineExceeded` and no results. Each call emits one stable
`traceroute_run_completed` terminal log with the hostname, protocol, outcome,
completed/requested run counts, deadline indication, destination port, and—when
results exist—the test run ID. Success is logged at debug, timeout at warning, and
other failures at error.

### Flags

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--proto` | `-P` | `udp` | Protocol (`udp`, `tcp`, `icmp`) |
| `--port` | `-p` | `33434` | Destination port |
| `--traceroute-queries` | `-q` | `3` | Number of traceroute queries; must not be negative |
| `--e2e-queries` | `-Q` | `50` | Number of end-to-end probe queries; must not be negative |
| `--max-ttl` | `-m` | `30` | Maximum TTL (1-255) |
| `--timeout` | | `3000` | Per-probe timeout in milliseconds. With a total timeout, an omitted or zero value is derived as `0.9 * total timeout / (TTLs probed)`, where TTLs probed is `max TTL - min TTL + 1`; without one, it uses the 3000 ms default. Must be non-negative |
| `--total-timeout-ms` | | `0` | Total timeout for the entire traceroute call, in milliseconds. `0` disables the overall deadline. Independent from `--timeout`: when both are set, each probe is capped by `--timeout` and the complete call is capped by `--total-timeout-ms`. Must be non-negative |
| `--tcp-method` | | `syn` | TCP method (`syn`, `sack`, `prefer_sack`) |
| `--ipv6` | | `false` | Use IPv6 |
| `--reverse-dns` | | `false` | Enrich IPs with reverse DNS names |
| `--source-public-ip` | | `false` | Enrich with source public IP |
| `--skip-private-hops` | | `false` | Skip private hops |
| `--windows-driver` | | `false` | Use Windows driver (Windows only) |
| `--verbose` | `-v` | `false` | Verbose logging |

### Timeouts

`--timeout` and `--total-timeout-ms` are independent knobs. `--max-ttl` only comes
into play when deriving a per-probe timeout from the total timeout (the CLI always
starts at TTL 1, so TTLs probed here is `--max-ttl`; library callers that set a
higher `MinTTL` derive from the narrower `MaxTTL - MinTTL + 1` range instead).

| `--total-timeout-ms` | `--timeout` | Effective per-probe timeout | Overall call deadline |
|---|---|---|---|
| `0` (unset) | `0` (unset) | `3000ms` (legacy default) | none |
| `0` (unset) | `N > 0` | `N` | none |
| `T > 0` | `0` (unset) | `max(0.9 * T / (TTLs probed), 50ms)` | `T` |
| `T > 0` | `N > 0` | `N` (not affected by `T`, `--max-ttl`, or TTLs probed) | `T` |

When both are set, `--timeout` bounds how long each individual probe's own window
waits for a response; for UDP, ICMP, and SACK traceroutes, which probe every TTL in
parallel, a response that arrives after that window but before the composed run
deadline is still retained rather than discarded, for backward compatibility with
prior serial-only behavior. `--total-timeout-ms` independently bounds the complete
call (DNS resolution, all traceroute queries, all end-to-end queries, and
enrichment) and can end it early even if an in-flight probe hasn't hit `--timeout`
yet. Because polling drivers check for cancellation between blocking reads, the
actual deadline may be observed up to ~100ms late. Negative values for either flag
are rejected.

The derived per-probe timeout never derives below `50ms` (`MinProbeTimeout`), so a
large TTL range can't silently squeeze every probe into an unusably short window.
There is no upfront rejection of an infeasible `--total-timeout-ms`: a value too
small for the requested work simply expires the deadline during the run and discards
results with `context.DeadlineExceeded`.

### Subcommands

| Command | Description |
|---------|-------------|
| `version` | Print version, commit, build date, and Go version |

## HTTP Server

An HTTP server mode is also available. See [server/README.md](server/README.md) for details.

```bash
# Run the server (default port 3765)
sudo ./datadog-traceroute-server

# Query it
curl 'http://localhost:3765/traceroute?target=google.com&protocol=tcp&port=443'
```

## Testing

```bash
# Unit tests
make test

# E2E tests (require root)
sudo go test -tags=e2etest -v ./e2etests/...
```

See [e2etests/README.md](e2etests/README.md) for the full e2e test matrix and instructions.

# Publishing Changes

After merging changes to `main` create a release by:

1. Navigate to the [Releases](https://github.com/DataDog/datadog-traceroute/releases) page
2. Click "Draft a new release"
3. You can "Select a tag" using the dropdown or "Create a new tag"
   
   When creating a new tag, make sure to include the `v` prefix.
   For example, if the last release was v0.1.29, your release should be v0.1.30.

5. The release title should be the same as the version tag
6. Use "Generate release notes" to fill in the release description
7. Click "Publish release"
   
   This will create a git tag that can now be referenced in other repos.
   This will trigger go-releaser that will add installable artifacts to the release.

# Downstream Consumers

`datadog-traceroute` is used by:

  - [Network Path](https://docs.datadoghq.com/network_monitoring/network_path)
    - Used Scheduled Tests and Dynamic Tests in [datadog-agent](https://github.com/DataDog/datadog-agent)
  - [Datadog Synthetic Monitoring](https://www.datadoghq.com/product/synthetic-monitoring/)
    - Used for Network Tests in Managed Locations and [datadog-agent](https://github.com/DataDog/datadog-agent)
    - Used for API Tests traceroute in Private Locations
