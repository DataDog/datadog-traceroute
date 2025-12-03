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
