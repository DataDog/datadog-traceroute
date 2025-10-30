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

# Publishing Changes

After merging changes to `main` create a release by:

1. Navigate to the [Releases](https://github.com/DataDog/datadog-traceroute/releases) page
2. Click "Draft a new release"
3. In the "Choose a tag" drop down, type in the next version number
   
   Generally you can add one to the last version number.  Make sure to include the `v` prefix. For example, if the last release was v0.1.29, your release should be v0.1.30.
   
5. The release title should be the same as the version tag
6. Use "Generate release notes" to fill in the release description
7. Click "Publish release"
   
   This will create a git tag that can now be referenced in other repos.
   This will trigger go-releaser that will add installable artifacts to the release.
