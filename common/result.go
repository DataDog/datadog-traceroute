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
		TracerouteRuns []TracerouteRun `json:"traceroute_runs"`
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

		IsDest   bool   `json:"-"` // DEPRECATED: TO REMOVE since now used at the moment
		Port     uint16 `json:"-"` // DEPRECATED: TO REMOVE since now used at the moment
		ICMPType uint8  `json:"-"` // DEPRECATED: TO REMOVE since now used at the moment
		ICMPCode uint8  `json:"-"` // DEPRECATED: TO REMOVE since now used at the moment
	}
	// ResultSource contains result source info
	ResultSource struct {
		IP   net.IP `json:"ip"`
		Port uint16 `json:"port"`
	}

	// ResultDestination contains result destination info
	ResultDestination struct {
		IP   net.IP `json:"ip"`
		Port uint16 `json:"port"`
	}
	// Params contains destination param info
	Params struct {
		Protocol string `json:"protocol"`
		Hostname string `json:"hostname"`
		Port     int    `json:"port"`
	}
)
