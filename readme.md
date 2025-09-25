# Datadog Traceroute

Datadog Traceroute produce traceroute results reflecting real traffic paths.

## Support Matrix

### Linux

| Protocol-Variant | Supported |  Traceroute CLI | Comment |
|------------------|:---------:|----------------:|---------|
| ICMP             |    Yes    | `traceroute -I` |         |
| UDP              |    Yes    |    `traceroute` |         |
| TCP SYN          |    Yes    | `tcptraceroute` |         |
| TCP SACK         |    Yes    |                 |         |

### Windows

| Protocol-Variant | Supported | Traceroute CLI | Comment                                         |
|------------------|:---------:|---------------:|-------------------------------------------------|
| ICMP             |    Yes    |      `tracert` |                                                 |
| UDP              |    Yes    |                |                                                 |
| TCP SYN          |    Yes    |                |                                                 |
| TCP SACK         |   Yes?    |                |                                                 |
| TCP SYN SOCKET   |    Yes    |                | default firewall on windows will block the ICMP |

### macOS

| Protocol-Variant | Supported |  Traceroute CLI | Comment |
|------------------|:---------:|----------------:|---------|
| ICMP             |    Yes    | `traceroute -I` |         |
| UDP              |    Yes    |    `traceroute` |         |
| TCP SYN          |    Yes    | `tcptraceroute` |         |
| TCP SACK         |    Yes    |                 |         |


## IPv6 Support

IPv6 is only partially supported.
