# Traceroute HTTP Server

This package provides an HTTP server with a REST API for running traceroutes.

## API Endpoint

### GET /traceroute

Runs a traceroute to the specified target.

#### Query Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `target` | string | *required* | Target hostname or IP address |
| `protocol` | string | `udp` | Protocol to use (`udp`, `tcp`, `icmp`) |
| `port` | int | `33434` | Destination port |
| `traceroute-queries` | int | `3` | Number of traceroute queries |
| `max-ttl` | int | `30` | Maximum TTL |
| `timeout` | int | `3000` | Timeout in milliseconds |
| `tcp-method` | string | `syn` | TCP method (`syn`, `sack`, `prefer_sack`) |
| `ipv6` | bool | `false` | Use IPv6 |
| `reverse-dns` | bool | `false` | Enrich IPs with reverse DNS names |
| `source-public-ip` | bool | `false` | Enrich with source public IP |
| `e2e-queries` | int | `50` | Number of end-to-end probe queries |
| `windows-driver` | bool | `false` | Use Windows driver (Windows only) |
| `skip-private-hops` | bool | `false` | Skip private hops |
| `verbose` | bool | `false` | Enable verbose logging |

#### Example Requests

```bash
# Basic traceroute to google.com
curl 'http://localhost:8080/traceroute?target=google.com'

# TCP traceroute to specific port with reverse DNS
curl 'http://localhost:8080/traceroute?target=example.com&protocol=tcp&port=443&reverse-dns=true'

# UDP traceroute with custom settings
curl 'http://localhost:8080/traceroute?target=8.8.8.8&protocol=udp&max-ttl=20&traceroute-queries=5'
```

#### Response

Returns JSON with the traceroute results. Example:

```json
{
  "destination": {
    "hostname": "google.com",
    "port": 33434
  },
  "protocol": "udp",
  "traceroute": {
    "runs": [...]
  },
  "e2e_probe": {
    "rtts": [...]
  },
  "source": {
    "public_ip": ""
  }
}
```

## Usage

### Running the Server

```go
package main

import (
    "log"
    "github.com/DataDog/datadog-traceroute/server"
)

func main() {
    srv := server.NewServer()
    
    if err := srv.Start(":8080"); err != nil {
        log.Fatalf("Server failed: %v", err)
    }
}
```

### Integration

```go
import "github.com/DataDog/datadog-traceroute/server"

// Create a new server instance
srv := server.NewServer()

// Start the server
err := srv.Start(":8080")
```

The server creates a single `Traceroute` instance on initialization that is reused for all subsequent requests.

