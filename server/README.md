# Traceroute HTTP Server

This package provides an HTTP server with a REST API for running traceroutes.

## Access control

The server has no access control by default. Two options restrict it:

- `DATADOG_TRACEROUTE_AUTH_TOKEN` (environment variable): when set, `/traceroute` requires
  `Authorization: Bearer <token>` and answers `401` otherwise. `/health` stays open. The token is
  read from the environment, not from a flag, because command lines are readable by every local user.
- `--blocked-cidrs`: comma-separated target ranges the server refuses to trace, for example
  `--blocked-cidrs 0.0.0.0/8,127.0.0.0/8,169.254.0.0/16,::/128,::1/128,fd00:ec2::254/128`. The target is
  checked after each DNS resolution. A blocked target gets `403` with code `DENIED`. Block `0.0.0.0/8` and
  `::/128` along with loopback, because traffic to those addresses reaches the local host. Write IPv4 ranges
  in their IPv4 form: IPv4-mapped IPv6 ranges such as `::ffff:169.254.0.0/112` are rejected.
- A token variable that is set but empty stops the server at startup.

Bind to loopback (`--addr 127.0.0.1:3765`) unless other hosts must reach the server.

```bash
export DATADOG_TRACEROUTE_AUTH_TOKEN="$(openssl rand -hex 32)"
datadog-traceroute-server --addr 127.0.0.1:3765 \
  --blocked-cidrs 0.0.0.0/8,127.0.0.0/8,169.254.0.0/16,::/128,::1/128,fd00:ec2::254/128 &
curl -H "Authorization: Bearer $DATADOG_TRACEROUTE_AUTH_TOKEN" 'http://127.0.0.1:3765/traceroute?target=example.com'
```

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
