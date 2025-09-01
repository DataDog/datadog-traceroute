package common

import "net"

type (
	// Results all the results from a single test run
	Results struct {
		Params         Params         `json:"params"`
		TracerouteTest TracerouteTest `json:"traceroute"`
		Tags           []string       `json:"tags"`
	}

	// TracerouteTest TODO
	TracerouteTest struct {
		Runs []TracerouteRun `json:"runs"`
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
		IP    string  `json:"ip"`
		RTTMs float64 `json:"rtt_ms"`

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
