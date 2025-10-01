# Datadog Traceroute

Datadog Traceroute produce traceroute results reflecting real traffic paths.

## Support Matrix for IPv4

### Linux

| Protocol-Variant | Supported |  Traceroute CLI | Comment |
|------------------|:---------:|----------------:|---------|
| ICMP             |    Yes    | `traceroute -I` |         |
| UDP              |    Yes    |    `traceroute` |         |
| TCP SYN          |    Yes    | `tcptraceroute` |         |
| TCP SACK         |    Yes    |                 |         |

### Windows

*Windows Server:*

| Protocol-Variant | Supported (with Win Driver) | Traceroute CLI | Comment                                |
|------------------|:---------------------------:|---------------:|----------------------------------------|
| ICMP             |             Yes             |      `tracert` |                                        |
| UDP              |             Yes             |                |                                        |
| TCP SYN          |             Yes             |                |                                        |
| TCP SACK         |            Yes*             |                |                                        |
| TCP SYN SOCKET   |             Yes             |                | no reason to use it for windows server |

*Windows Client:*

| Protocol-Variant | Supported (with Win Driver) | Traceroute CLI | Comment |
|------------------|:---------------------------:|---------------:|---------|
| ICMP             |            Yes*             |      `tracert` |         |
| UDP              |            Yes*             |                |         |
| TCP SYN          |            Yes*             |                |         |
| TCP SACK         |            Yes*             |                |         |
| TCP SYN SOCKET   |             Yes             |                |         |

* requires Windows Driver (default firewall on windows will block the ICMP responses when not using Windows Driver)

### macOS

| Protocol-Variant | Supported |  Traceroute CLI | Comment |
|------------------|:---------:|----------------:|---------|
| ICMP             |    Yes    | `traceroute -I` |         |
| UDP              |    Yes    |    `traceroute` |         |
| TCP SYN          |    Yes    | `tcptraceroute` |         |
| TCP SACK         |    Yes    |                 |         |


## IPv6 Support

IPv6 is only partially supported.

Note: Windows driver is needed for all protocol-variant for IPv6s on server versions.
