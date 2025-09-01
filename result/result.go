package result

import "net"

type (
	// Results all the results from a single test run
	Results struct {
		Params         Params         `json:"params"`
		TracerouteTest TracerouteTest `json:"traceroute"`
		E2eProbe       E2eProbe       `json:"e2e_probe"`
		Tags           []string       `json:"tags"`
	}

	// E2eProbe TODO
	E2eProbe struct {
		Rtts                 []float64   `json:"rtts"`
		PacketsSent          int         `json:"packets_sent"`
		PacketsReceived      int         `json:"packets_received"`
		PacketLossPercentage float32     `json:"packet_loss_percentage"`
		Jitter               int         `json:"jitter"`
		Rtt                  E2eProbeRtt `json:"latency"`
	}

	E2eProbeRtt struct {
		Avg float64 `json:"avg"`
		Min float64 `json:"min"`
		Max float64 `json:"max"`
	}

	HopsStats struct {
		Avg float64 `json:"avg"`
		Min float64 `json:"min"`
		Max float64 `json:"max"`
	}

	// TracerouteTest TODO
	TracerouteTest struct {
		Runs []TracerouteRun `json:"runs"`
		Hops HopsStats       `json:"hops"`
	}

	// TracerouteRun TODO
	TracerouteRun struct {
		Source      ResultSource      `json:"source"`
		Destination ResultDestination `json:"destination"`
		Hops        []*ResultHop      `json:"hops"`
	}

	// ResultHop encapsulates information about a single
	// hop in a traceroute
	ResultHop struct {
		IP  string  `json:"ip"`
		RTT float64 `json:"rtt"`

		// DEPRECATED: In separate PR, remove fields below and its usage
		IsDest   bool   `json:"-"`
		Port     uint16 `json:"-"`
		ICMPType uint8  `json:"-"`
		ICMPCode uint8  `json:"-"`
	}
	// ResultSource contains result source info
	ResultSource struct {
		IP   net.IP `json:"ip"`
		Port uint16 `json:"port"`
	}

	// ResultDestination contains result destination info
	ResultDestination struct {
		IP   string `json:"ip"`
		Port uint16 `json:"port"`
	}
	// Params contains destination param info
	Params struct {
		Protocol string `json:"protocol"`
		Hostname string `json:"hostname"`
		Port     int    `json:"port"`
	}
)
