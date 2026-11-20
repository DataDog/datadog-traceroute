# Traceroute HTTP Server

This package provides an HTTP server with a REST API for running traceroutes.

## Access control

- **Listen address:** `--addr` defaults to `127.0.0.1:3765`, so only local processes can reach the
  server. Pass `--addr :3765` to listen on every interface.
- **Token:** when the `DATADOG_TRACEROUTE_AUTH_TOKEN` environment variable is set, `/traceroute`
  requires `Authorization: Bearer <token>` and answers `401` otherwise. `/health` stays open. The token
  is read from the environment, not from a flag, because command lines are readable by every local user.
  A variable that is set but empty stops the server at startup.
- **Token file:** `--auth-token-file <path>` reads the token from a file instead, for launchers that cannot
  set a secret in the environment without a shell. A shell in between drops the capabilities the binary
  needs when privilege escalation is disabled. An empty file stops the server, and setting both the
  variable and the flag is an error.

```bash
export DATADOG_TRACEROUTE_AUTH_TOKEN="$(openssl rand -hex 32)"
datadog-traceroute-server &
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
curl 'http://127.0.0.1:3765/traceroute?target=google.com'

# TCP traceroute to specific port with reverse DNS
curl 'http://127.0.0.1:3765/traceroute?target=example.com&protocol=tcp&port=443&reverse-dns=true'

# UDP traceroute with custom settings
curl 'http://127.0.0.1:3765/traceroute?target=8.8.8.8&protocol=udp&max-ttl=20&traceroute-queries=5'
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
