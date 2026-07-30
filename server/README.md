# Traceroute HTTP Server

This package provides an HTTP server with a REST API for running traceroutes.

## API Endpoint

### GET /traceroute

Runs a traceroute to the specified target.

#### Query Parameters

See `parseTracerouteParams()` function

#### Example Requests

```bash
# Basic traceroute to google.com
curl 'http://localhost:8080/traceroute?target=google.com'

# TCP traceroute to specific port with reverse DNS
curl 'http://localhost:8080/traceroute?target=example.com&protocol=tcp&port=443&reverse-dns=true'

# UDP traceroute with custom settings
curl 'http://localhost:8080/traceroute?target=8.8.8.8&protocol=udp&max-ttl=20&traceroute-queries=5'

# Bound the complete call to 10 seconds; with the default max TTL of 30,
# the omitted per-probe timeout is derived as 0.9 * (10s / 30) = 300ms
curl 'http://localhost:8080/traceroute?target=8.8.8.8&total_timeout_ms=10000'

# Opt in to completed traceroute runs when the total timeout expires
curl 'http://localhost:8080/traceroute?target=8.8.8.8&total_timeout_ms=10000&return-partial-results=true'
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
  "timed_out": false,
  "source": {
    "public_ip": ""
  }
}
```

By default, an expired total timeout returns HTTP `504` with a `TIMEOUT` error. When
`return-partial-results=true` and at least one traceroute query completes, the response
contains only those completed runs and sets `timed_out` to `true`.
