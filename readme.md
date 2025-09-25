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

### Windows Server

| Protocol-Variant | Supported | Windows Driver required | Traceroute CLI | Comment                                |
|------------------|:---------:|-------------------------|---------------:|----------------------------------------|
| ICMP             |    Yes    | No                      |      `tracert` |                                        |
| UDP              |    Yes    | No                      |                |                                        |
| TCP SYN          |    Yes    | No                      |                |                                        |
| TCP SACK         |    Yes    | Yes                     |                |                                        |
| TCP SYN SOCKET   |    Yes    | No                      |                | no reason to use it for windows server |

Note:
- Default firewall on windows will block the ICMP responses when not using Windows Driver.

### Windows Client

| Protocol-Variant | Supported | Windows Driver required | Traceroute CLI | Comment |
|------------------|:---------:|-------------------------|---------------:|---------|
| ICMP             |    Yes    | Yes                     |      `tracert` |         |
| UDP              |    Yes    | Yes                     |                |         |
| TCP SYN          |    Yes    | Yes                     |                |         |
| TCP SACK         |    Yes    | Yes                     |                |         |
| TCP SYN SOCKET   |    Yes    | No                      |                |         |

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
