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

| Protocol-Variant | Supported (with Win Driver) | Traceroute CLI |
|------------------|:---------------------------:|---------------:|
| ICMP             |    Yes (req. win driver)    |      `tracert` |
| UDP              |    Yes (req. win driver)    |                |
| TCP SYN          |    Yes (req. win driver)    |                |
| TCP SACK         |    Yes (req. win driver)    |                |
| TCP SYN SOCKET   |             Yes             |                |

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
