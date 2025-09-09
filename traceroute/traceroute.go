package traceroute

// Protocol defines supported network protocols
// Please define new protocols based on the Keyword from:
// https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
type Protocol string

const (
	// ProtocolTCP is the TCP protocol.
	ProtocolTCP Protocol = "TCP"
	// ProtocolUDP is the UDP protocol.
	ProtocolUDP Protocol = "UDP"
	// ProtocolICMP is the ICMP protocol.
	ProtocolICMP Protocol = "ICMP"
)

// TCPMethod is the method used to run a TCP traceroute.
type TCPMethod string

const (
	// TCPConfigSYN means to only perform SYN traceroutes
	TCPConfigSYN TCPMethod = "syn"
	// TCPConfigSACK means to only perform SACK traceroutes
	TCPConfigSACK TCPMethod = "sack"
	// TCPConfigPreferSACK means to try SACK, and fall back to SYN if the remote doesn't support SACK
	TCPConfigPreferSACK TCPMethod = "prefer_sack"
	// TCPConfigSYNSocket means to use a SYN with TCP socket options to perform the traceroute (windows only)
	TCPConfigSYNSocket TCPMethod = "syn_socket"
)

// DNSResolutionStrategy is the DNS Resolution Strategy.
type DNSResolutionStrategy string

const (
	// DNSResStrategyFirst means choosing first IP from DNS Resolution
	DNSResStrategyFirst DNSResolutionStrategy = "first"
	// DNSResStrategyRandom means choosing random IP from DNS Resolution
	DNSResStrategyRandom DNSResolutionStrategy = "random"
)
